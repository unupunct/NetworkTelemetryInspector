using System.Runtime.InteropServices;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Network;

/// <summary>
/// Per-connection byte counters from Windows TCP Extended Statistics (GetPerTcpConnectionEStats).
///
/// Limitation, stated plainly in the UI: enabling collection on a connection
/// (SetPerTcpConnectionEStats) requires administrator rights, and Windows offers no per-process
/// counter for UDP. Without elevation this class reports <see cref="Available"/> = false and the
/// UI shows adapter totals only — it never estimates per-app traffic.
/// </summary>
public sealed unsafe class TcpTrafficCounter
{
    private const int TcpConnectionEstatsData = 1;
    private const int RodSize = 96;   // TCP_ESTATS_DATA_ROD_v0
    private const uint ERROR_ACCESS_DENIED = 5;

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcpConnectionEStats(byte* row, int type, byte* rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcpConnectionEStats(byte* row, int type, byte* rw, uint rwVersion, uint rwSize,
        byte* ros, uint rosVersion, uint rosSize, byte* rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcp6ConnectionEStats(byte* row, int type, byte* rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcp6ConnectionEStats(byte* row, int type, byte* rw, uint rwVersion, uint rwSize,
        byte* ros, uint rosVersion, uint rosSize, byte* rod, uint rodVersion, uint rodSize);

    private readonly HashSet<ConnectionKey> _enabled = new();
    private bool _denied;

    public TcpTrafficCounter() => Available = Elevation.IsElevated;

    public bool Available { get; private set; }

    public string UnavailableReason => _denied || !Elevation.IsElevated
        ? "Per-application traffic needs administrator rights (Windows TCP extended statistics). Adapter totals are shown instead."
        : "Per-application traffic is not available on this system.";

    /// <summary>Returns cumulative (bytesIn, bytesOut) since collection was enabled, or null.</summary>
    public (ulong In, ulong Out)? Read(ConnectionSample c)
    {
        if (!Available || c.RawRow is null || c.State != TcpState.Established) return null;
        var v6 = c.Protocol == Protocol.Tcp6;
        fixed (byte* row = c.RawRow)
        {
            if (!_enabled.Contains(c.Key))
            {
                byte enable = 1;
                var r = v6
                    ? SetPerTcp6ConnectionEStats(row, TcpConnectionEstatsData, &enable, 0, 1, 0)
                    : SetPerTcpConnectionEStats(row, TcpConnectionEstatsData, &enable, 0, 1, 0);
                if (r == ERROR_ACCESS_DENIED)
                {
                    _denied = true;
                    Available = false;
                    Log.Info("Traffic", "TCP extended statistics denied; per-app traffic disabled.");
                    return null;
                }
                if (r != 0) return null;
                _enabled.Add(c.Key);
            }

            var rod = stackalloc byte[RodSize];
            var ret = v6
                ? GetPerTcp6ConnectionEStats(row, TcpConnectionEstatsData, null, 0, 0, null, 0, 0, rod, 0, RodSize)
                : GetPerTcpConnectionEStats(row, TcpConnectionEstatsData, null, 0, 0, null, 0, 0, rod, 0, RodSize);
            if (ret != 0) return null;
            return (*(ulong*)(rod + 16), *(ulong*)rod);
        }
    }

    /// <summary>Drops bookkeeping for connections that no longer exist.</summary>
    public void Retain(HashSet<ConnectionKey> live) => _enabled.IntersectWith(live);
}
