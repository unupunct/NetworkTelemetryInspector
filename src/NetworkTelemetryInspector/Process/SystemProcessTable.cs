using System.Runtime.InteropServices;

namespace NetworkTelemetryInspector.Processes;

/// <summary>
/// Process facts that Windows reveals without opening the process, so they also work for
/// SYSTEM services and protected processes that a standard user cannot open:
///  * NtQuerySystemInformation(SystemProcessInformation) → PID, image name, creation time for all processes;
///  * NtQuerySystemInformation(SystemProcessIdInformation) → full image path of one PID.
/// Both are what Task Manager and Process Explorer use. Failures degrade to "unavailable".
/// </summary>
internal static unsafe class SystemProcessTable
{
    private const int SystemProcessInformation = 5;
    private const int SystemProcessIdInformation = 88;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int cls, void* info, int length, out int returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string deviceName, char[] target, int max);

    public readonly record struct Entry(string Name, DateTime? StartTime);

    private static Dictionary<string, string>? _devices;
    private static long _devicesTick;

    public static Dictionary<int, Entry> Snapshot()
    {
        var map = new Dictionary<int, Entry>();
        var size = 512 * 1024;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQuerySystemInformation(SystemProcessInformation, (void*)buffer, size, out var needed);
                if (status == STATUS_INFO_LENGTH_MISMATCH) { size = Math.Max(size * 2, needed + 64 * 1024); continue; }
                if (status != 0) return map;

                // SYSTEM_PROCESS_INFORMATION (x64): NextEntryOffset@0, CreateTime@32, ImageName@56, UniqueProcessId@80
                var p = (byte*)buffer;
                while (true)
                {
                    var next = *(uint*)p;
                    var create = *(long*)(p + 32);
                    var nameLen = *(ushort*)(p + 56);
                    var namePtr = *(char**)(p + 64);
                    var pid = (int)*(long*)(p + 80);
                    var name = namePtr != null && nameLen > 0 ? new string(namePtr, 0, nameLen / 2) : pid == 0 ? "System Idle Process" : "System";
                    map[pid] = new Entry(name, create > 0 ? DateTime.FromFileTime(create) : null);
                    if (next == 0) break;
                    p += next;
                }
                return map;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return map;
    }

    /// <summary>Full Win32 path of the image of <paramref name="pid"/>, or null.</summary>
    public static string? ImagePath(int pid)
    {
        const int max = 32768 * 2;
        var buffer = Marshal.AllocHGlobal(max);
        try
        {
            // SYSTEM_PROCESS_ID_INFORMATION (x64): ProcessId@0, UNICODE_STRING{Length@8, MaximumLength@10, Buffer@16}
            var info = stackalloc byte[24];
            *(long*)info = pid;
            *(ushort*)(info + 8) = 0;
            *(ushort*)(info + 10) = (ushort)Math.Min(max, ushort.MaxValue - 1);
            *(IntPtr*)(info + 16) = buffer;
            if (NtQuerySystemInformation(SystemProcessIdInformation, info, 24, out _) != 0) return null;
            var len = *(ushort*)(info + 8);
            if (len == 0) return null;
            var nt = new string((char*)buffer, 0, len / 2);
            return NtToDosPath(nt);
        }
        catch { return null; }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>"\Device\HarddiskVolume3\Windows\x.exe" → "C:\Windows\x.exe".</summary>
    internal static string? NtToDosPath(string nt)
    {
        if (nt.Length > 2 && nt[1] == ':') return nt;
        if (_devices is null || Environment.TickCount64 - _devicesTick > 60000)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var buf = new char[1024];
            foreach (var drive in Environment.GetLogicalDrives())
            {
                var letter = drive.TrimEnd('\\');
                var n = QueryDosDevice(letter, buf, buf.Length);
                if (n == 0) continue;
                var target = new string(buf, 0, Array.IndexOf(buf, '\0') is var z and >= 0 ? z : (int)n);
                d[target] = letter;
            }
            _devices = d;
            _devicesTick = Environment.TickCount64;
        }
        foreach (var (device, letter) in _devices)
        {
            if (nt.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return letter + nt[device.Length..];
        }
        return null;
    }
}
