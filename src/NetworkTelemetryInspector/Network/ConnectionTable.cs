using System.Net;
using System.Runtime.InteropServices;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Network;

/// <summary>
/// Reads the TCP/UDP endpoint tables with their owning PID straight from iphlpapi
/// (GetExtendedTcpTable / GetExtendedUdpTable) — the same source TCPView uses. No external
/// process is spawned. The buffer is reused between polls, so steady-state polling allocates
/// little beyond the result list.
/// </summary>
public sealed unsafe class ConnectionTable : IDisposable
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    private IntPtr _buffer;
    private int _bufferSize;
    private readonly Dictionary<uint, string> _v4Cache = new();
    private readonly object _gate = new();

    public List<ConnectionSample> Read(bool includeUdp)
    {
        lock (_gate)
        {
            var list = new List<ConnectionSample>(512);
            Safe(() => ReadTcp4(list), "TCP");
            Safe(() => ReadTcp6(list), "TCPv6");
            if (includeUdp)
            {
                Safe(() => ReadUdp4(list), "UDP");
                Safe(() => ReadUdp6(list), "UDPv6");
            }
            if (_v4Cache.Count > 20000) _v4Cache.Clear();
            return list;
        }
    }

    private static void Safe(Action a, string what)
    {
        try { a(); }
        catch (Exception ex) { Log.Debug("ConnectionTable", what + " table unavailable: " + ex.Message); }
    }

    private int Fill(bool tcp, int af)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var size = _bufferSize;
            var ret = tcp
                ? GetExtendedTcpTable(_buffer, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
                : GetExtendedUdpTable(_buffer, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
            if (ret == 0) return _buffer == IntPtr.Zero ? 0 : *(int*)_buffer;
            if (ret != ERROR_INSUFFICIENT_BUFFER) throw new System.ComponentModel.Win32Exception((int)ret);
            // The table grows between the size query and the read; leave head-room.
            Grow(size + 16 * 1024);
        }
        return 0;
    }

    private void Grow(int size)
    {
        if (_buffer != IntPtr.Zero) Marshal.FreeHGlobal(_buffer);
        _buffer = Marshal.AllocHGlobal(size);
        _bufferSize = size;
    }

    public static int Port(uint networkOrder) => (int)(((networkOrder & 0xFF) << 8) | ((networkOrder >> 8) & 0xFF));

    private string V4(uint addr)
    {
        if (!_v4Cache.TryGetValue(addr, out var s))
        {
            s = new IPAddress(addr).ToString();
            _v4Cache[addr] = s;
        }
        return s;
    }

    private static string V6(byte* p)
    {
        var ip = new IPAddress(new ReadOnlySpan<byte>(p, 16));
        // IPv4-mapped (dual-stack sockets): show the IPv4 form so DNS names and filters match.
        return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();
    }

    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, owningPid (6 x uint)
    private void ReadTcp4(List<ConnectionSample> list)
    {
        var n = Fill(true, AF_INET);
        var row = (uint*)(_buffer + 4);
        for (var i = 0; i < n; i++, row += 6)
        {
            // ESTATS wants MIB_TCPROW: the first five fields in the same layout.
            var raw = new byte[20];
            fixed (byte* r = raw) Buffer.MemoryCopy(row, r, 20, 20);
            list.Add(new ConnectionSample
            {
                Key = new ConnectionKey(Protocol.Tcp, V4(row[1]), Port(row[2]), V4(row[3]), Port(row[4]), (int)row[5]),
                State = (TcpState)row[0],
                RawRow = raw
            });
        }
    }

    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid (56 bytes)
    private void ReadTcp6(List<ConnectionSample> list)
    {
        var n = Fill(true, AF_INET6);
        var p = (byte*)(_buffer + 4);
        for (var i = 0; i < n; i++, p += 56)
        {
            var localPort = *(uint*)(p + 20);
            var remotePort = *(uint*)(p + 44);
            var state = *(uint*)(p + 48);
            var pid = *(uint*)(p + 52);

            // MIB_TCP6ROW for ESTATS: State, LocalAddr[16], LocalScope, LocalPort, RemoteAddr[16], RemoteScope, RemotePort (52 bytes)
            var raw = new byte[52];
            fixed (byte* r = raw)
            {
                *(uint*)r = state;
                Buffer.MemoryCopy(p, r + 4, 48, 24);        // local addr + scope + port
                Buffer.MemoryCopy(p + 24, r + 28, 24, 24);  // remote addr + scope + port
            }
            list.Add(new ConnectionSample
            {
                Key = new ConnectionKey(Protocol.Tcp6, V6(p), Port(localPort), V6(p + 24), Port(remotePort), (int)pid),
                State = (TcpState)state,
                RawRow = raw
            });
        }
    }

    // MIB_UDPROW_OWNER_PID: localAddr, localPort, owningPid
    private void ReadUdp4(List<ConnectionSample> list)
    {
        var n = Fill(false, AF_INET);
        var row = (uint*)(_buffer + 4);
        for (var i = 0; i < n; i++, row += 3)
        {
            list.Add(new ConnectionSample
            {
                Key = new ConnectionKey(Protocol.Udp, V4(row[0]), Port(row[1]), "*", 0, (int)row[2]),
                State = TcpState.UdpBound
            });
        }
    }

    // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, owningPid (28 bytes)
    private void ReadUdp6(List<ConnectionSample> list)
    {
        var n = Fill(false, AF_INET6);
        var p = (byte*)(_buffer + 4);
        for (var i = 0; i < n; i++, p += 28)
        {
            list.Add(new ConnectionSample
            {
                Key = new ConnectionKey(Protocol.Udp6, V6(p), Port(*(uint*)(p + 20)), "*", 0, (int)*(uint*)(p + 24)),
                State = TcpState.UdpBound
            });
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_buffer != IntPtr.Zero) Marshal.FreeHGlobal(_buffer);
            _buffer = IntPtr.Zero;
            _bufferSize = 0;
        }
    }
}
