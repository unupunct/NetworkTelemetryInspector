using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Processes;

/// <summary>
/// Resolves a PID to its executable, publisher, signature, start time and hosted services.
/// Everything uses native calls with PROCESS_QUERY_LIMITED_INFORMATION, which a standard user
/// may open for most processes; protected/system processes gracefully return
/// "Information unavailable" instead of failing. Results are cached per (PID, start time) so a
/// reused PID never inherits another program's identity.
/// </summary>
public sealed class ProcessInspector
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr h, int flags, char[] name, ref int size);

    private readonly ConcurrentDictionary<(int Pid, long Start), ProcessDetails> _cache = new();
    private readonly ConcurrentDictionary<string, SignatureVerifier.Result> _signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _signaturePending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ImageSource?> _icons = new(StringComparer.OrdinalIgnoreCase);
    private readonly ServiceMap _services = new();
    private volatile Dictionary<int, SystemProcessTable.Entry> _table = new();
    private long _tableTick;

    /// <summary>Returns (cached) details for a PID. Never throws.</summary>
    public ProcessDetails Get(int pid)
    {
        try
        {
            if (pid == 0) return new ProcessDetails { Pid = 0, Name = "System Idle Process", Publisher = "Microsoft Windows" };
            if (pid == 4) return new ProcessDetails { Pid = 4, Name = "System", Publisher = "Microsoft Windows", Description = "Windows kernel (drivers and kernel-mode networking such as SMB)" };

            var entry = TableEntry(pid);
            var key = (pid, entry?.StartTime?.ToFileTimeUtc() ?? 0L);
            if (_cache.TryGetValue(key, out var cached))
            {
                // Services can start/stop inside a shared svchost, and signatures finish in the background.
                var svc = _services.For(pid);
                var sigReady = cached.Signature == SignatureStatus.Unknown && cached.Path is not null && _signatures.ContainsKey(cached.Path);
                if (!sigReady && svc.SequenceEqual(cached.Services)) return cached;
                var refreshed = Build(pid, cached.Path, cached.StartTime, entry?.Name);
                _cache[key] = refreshed;
                return refreshed;
            }

            var path = QueryPath(pid);
            var details = Build(pid, path, entry?.StartTime, entry?.Name);
            _cache[key] = details;
            if (_cache.Count > 4000) _cache.Clear();
            return details;
        }
        catch (Exception ex)
        {
            Log.Debug("Process", $"PID {pid}: {ex.Message}");
            return new ProcessDetails { Pid = pid, Name = TableEntry(pid)?.Name ?? "Unknown Process" };
        }
    }

    private ProcessDetails Build(int pid, string? path, DateTime? start, string? tableName)
    {
        string name;
        string? publisher = null, version = null, description = null, signer = null;
        var signature = SignatureStatus.Unavailable;

        if (path is not null)
        {
            name = System.IO.Path.GetFileName(path);
            try
            {
                var fvi = FileVersionInfo.GetVersionInfo(path);
                publisher = Blank(fvi.CompanyName);
                version = Blank(fvi.FileVersion);
                description = Blank(fvi.FileDescription);
            }
            catch { /* file not readable */ }

            if (_signatures.TryGetValue(path, out var sig))
            {
                signature = sig.Status;
                signer = sig.Signer;
            }
            else
            {
                signature = SignatureStatus.Unknown;
                QueueSignature(path);
            }
        }
        else
        {
            name = tableName ?? "Unknown Process";
        }

        return new ProcessDetails
        {
            Pid = pid,
            Name = name,
            Path = path,
            Publisher = signer ?? publisher,
            FileVersion = version,
            Description = description,
            Signature = signature,
            Signer = signer,
            StartTime = start,
            Services = _services.For(pid)
        };
    }

    /// <summary>Authenticode checks take tens of milliseconds each; run them off the monitor thread.</summary>
    private void QueueSignature(string path)
    {
        if (!_signaturePending.TryAdd(path, 0)) return;
        ThreadPool.UnsafeQueueUserWorkItem(state =>
        {
            try { _signatures[path] = SignatureVerifier.Verify(path); }
            catch { _signatures[path] = new SignatureVerifier.Result(SignatureStatus.Unavailable, null, false); }
            finally { _signaturePending.TryRemove(path, out _); }
        }, null);
    }

    /// <summary>Waits until queued signature checks finish (headless tests).</summary>
    public void WaitForSignatures(int timeoutMs)
    {
        var until = Environment.TickCount64 + timeoutMs;
        while (!_signaturePending.IsEmpty && Environment.TickCount64 < until) Thread.Sleep(50);
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string? QueryPath(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                var buf = new char[1024];
                var size = buf.Length;
                if (QueryFullProcessImageName(h, 0, buf, ref size)) return new string(buf, 0, size);
            }
            finally { CloseHandle(h); }
        }
        // Not openable (SYSTEM service / protected process): ask the kernel for the image name instead.
        return SystemProcessTable.ImagePath(pid);
    }

    private SystemProcessTable.Entry? TableEntry(int pid)
    {
        if (Environment.TickCount64 - Interlocked.Read(ref _tableTick) > 1500 || !_table.ContainsKey(pid))
        {
            // Refresh at most every 1.5 s, or when an unseen PID appears (at most every 250 ms).
            if (Environment.TickCount64 - Interlocked.Read(ref _tableTick) > 250)
            {
                _table = SystemProcessTable.Snapshot();
                Interlocked.Exchange(ref _tableTick, Environment.TickCount64);
            }
        }
        return _table.TryGetValue(pid, out var e) ? e : null;
    }

    public void RefreshServices() => _services.Refresh();

    /// <summary>Small shell icon for an executable, frozen so any thread may use it.</summary>
    public ImageSource? Icon(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        return _icons.GetOrAdd(path, p => ShellIcon.Load(p));
    }
}

/// <summary>PID → hosted service names (so "svchost.exe" can say which service is talking).</summary>
internal sealed unsafe class ServiceMap
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? db, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusEx(IntPtr scm, int infoLevel, uint type, uint state, IntPtr buffer, int bufSize,
        out int needed, out int returned, ref int resume, string? group);

    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr h);

    private volatile Dictionary<int, List<string>> _map = new();
    private long _lastRefresh;

    public IReadOnlyList<string> For(int pid)
    {
        if (Environment.TickCount64 - Interlocked.Read(ref _lastRefresh) > 30000) Refresh();
        return _map.TryGetValue(pid, out var l) ? l : [];
    }

    public void Refresh()
    {
        Interlocked.Exchange(ref _lastRefresh, Environment.TickCount64);
        var scm = OpenSCManager(null, null, 0x0004 /* SC_MANAGER_ENUMERATE_SERVICE */);
        if (scm == IntPtr.Zero) return;
        var buffer = IntPtr.Zero;
        try
        {
            var resume = 0;
            EnumServicesStatusEx(scm, 0, 0x30 /* SERVICE_WIN32 */, 1 /* ACTIVE */, IntPtr.Zero, 0, out var needed, out _, ref resume, null);
            if (needed <= 0) return;
            needed += 4096;
            buffer = Marshal.AllocHGlobal(needed);
            resume = 0;
            if (!EnumServicesStatusEx(scm, 0, 0x30, 1, buffer, needed, out _, out var count, ref resume, null)) return;

            var map = new Dictionary<int, List<string>>();
            // ENUM_SERVICE_STATUS_PROCESSW (x64): lpServiceName@0, lpDisplayName@8, SERVICE_STATUS_PROCESS@16 (dwProcessId@+28)
            const int stride = 56;
            var p = (byte*)buffer;
            for (var i = 0; i < count; i++, p += stride)
            {
                var name = Marshal.PtrToStringUni(*(IntPtr*)p);
                var pid = *(int*)(p + 16 + 28);
                if (pid == 0 || name is null) continue;
                if (!map.TryGetValue(pid, out var list)) map[pid] = list = new List<string>();
                list.Add(name);
            }
            foreach (var l in map.Values) l.Sort(StringComparer.OrdinalIgnoreCase);
            _map = map;
        }
        catch (Exception ex) { Log.Debug("Services", ex.Message); }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseServiceHandle(scm);
        }
    }
}

internal static class ShellIcon
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfo(string path, uint attrs, ref SHFILEINFO info, uint size, uint flags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr h);

    public static ImageSource? Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var info = new SHFILEINFO();
            // SHGFI_ICON | SHGFI_LARGEICON (32 px, rendered smaller for crisp HiDPI output)
            if (SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFO>(), 0x100) == IntPtr.Zero || info.hIcon == IntPtr.Zero)
                return null;
            try
            {
                var src = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, System.Windows.Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                return src;
            }
            finally { DestroyIcon(info.hIcon); }
        }
        catch { return null; }
    }
}
