using System.Runtime.InteropServices;

namespace NetworkTelemetryInspector.Processes;

/// <summary>
/// Tracks which processes the user is interacting with: the foreground window's PID and the set
/// of PIDs owning a visible top-level window. Used only for the heuristic "Background" label.
/// </summary>
public sealed class WindowActivity
{
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr hWnd, uint cmd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int pid);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    private readonly Dictionary<int, DateTime> _lastForeground = new();
    private HashSet<int> _windowed = new();

    public IReadOnlySet<int> WindowedPids => _windowed;

    /// <summary>PID owning the foreground window at the last sample (0 = none).</summary>
    public int ForegroundPid { get; private set; }

    public void Sample()
    {
        try
        {
            var fg = GetForegroundWindow();
            if (fg != IntPtr.Zero)
            {
                GetWindowThreadProcessId(fg, out var fgPid);
                ForegroundPid = fgPid;
                if (fgPid > 0) _lastForeground[fgPid] = DateTime.Now;
            }

            var set = new HashSet<int>();
            EnumWindows((h, _) =>
            {
                // Visible, unowned, titled top-level windows = something the user can see.
                if (IsWindowVisible(h) && GetWindow(h, 4 /* GW_OWNER */) == IntPtr.Zero && GetWindowTextLength(h) > 0)
                {
                    GetWindowThreadProcessId(h, out var pid);
                    if (pid > 0) set.Add(pid);
                }
                return true;
            }, IntPtr.Zero);
            _windowed = set;

            if (_lastForeground.Count > 2000)
            {
                foreach (var k in _lastForeground.Where(kv => kv.Value < DateTime.Now.AddHours(-2)).Select(kv => kv.Key).ToList())
                    _lastForeground.Remove(k);
            }
        }
        catch { /* desktop switch (lock screen / UAC): keep the previous sample */ }
    }

    public DateTime? LastForeground(IEnumerable<int> pids)
    {
        DateTime? best = null;
        foreach (var p in pids)
            if (_lastForeground.TryGetValue(p, out var t) && (best is null || t > best)) best = t;
        return best;
    }

    public bool HasWindow(IEnumerable<int> pids) => pids.Any(_windowed.Contains);
}
