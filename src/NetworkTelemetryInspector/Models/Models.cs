using System.Text.Json.Serialization;

namespace NetworkTelemetryInspector.Models;

public enum Protocol { Tcp, Tcp6, Udp, Udp6 }

public static class ProtocolText
{
    public static string Of(Protocol p) => p switch
    {
        Protocol.Tcp => "TCP",
        Protocol.Tcp6 => "TCPv6",
        Protocol.Udp => "UDP",
        Protocol.Udp6 => "UDPv6",
        _ => "?"
    };

    public static bool IsTcp(Protocol p) => p is Protocol.Tcp or Protocol.Tcp6;
}

/// <summary>MIB_TCP_STATE values as returned by iphlpapi (numeric, so language independent).</summary>
public enum TcpState
{
    Unknown = 0, Closed = 1, Listen = 2, SynSent = 3, SynReceived = 4, Established = 5,
    FinWait1 = 6, FinWait2 = 7, CloseWait = 8, Closing = 9, LastAck = 10, TimeWait = 11, DeleteTcb = 12,
    /// <summary>Not a TCP state: a bound UDP endpoint.</summary>
    UdpBound = 100
}

public static class TcpStateText
{
    public static string Of(TcpState s) => s switch
    {
        TcpState.Established => "ESTABLISHED",
        TcpState.Listen => "LISTENING",
        TcpState.SynSent => "SYN_SENT",
        TcpState.SynReceived => "SYN_RECEIVED",
        TcpState.FinWait1 => "FIN_WAIT_1",
        TcpState.FinWait2 => "FIN_WAIT_2",
        TcpState.CloseWait => "CLOSE_WAIT",
        TcpState.Closing => "CLOSING",
        TcpState.LastAck => "LAST_ACK",
        TcpState.TimeWait => "TIME_WAIT",
        TcpState.Closed => "CLOSED",
        TcpState.DeleteTcb => "DELETE_TCB",
        TcpState.UdpBound => "BOUND",
        _ => "UNKNOWN"
    };
}

/// <summary>Identity of one socket as reported by the OS table. Equal keys = same connection across polls.</summary>
public readonly record struct ConnectionKey(Protocol Protocol, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, int Pid);

/// <summary>One row of the OS connection table at a single point in time.</summary>
public sealed class ConnectionSample
{
    public required ConnectionKey Key { get; init; }
    public TcpState State { get; init; }

    /// <summary>Raw row bytes needed to query TCP extended statistics (null for UDP).</summary>
    [JsonIgnore] public byte[]? RawRow { get; init; }

    public Protocol Protocol => Key.Protocol;
    public int Pid => Key.Pid;
    public string RemoteAddress => Key.RemoteAddress;
    public int RemotePort => Key.RemotePort;
    public bool HasRemote => Key.RemotePort != 0 && !NetworkAddress.IsUnspecified(Key.RemoteAddress);
    public bool IsLoopback => NetworkAddress.IsLoopback(Key.RemoteAddress) || (!HasRemote && NetworkAddress.IsLoopback(Key.LocalAddress));
}

public static class NetworkAddress
{
    public static bool IsUnspecified(string address) =>
        address is "0.0.0.0" or "::" or "" || address.StartsWith("0.0.0.0", StringComparison.Ordinal);

    public static bool IsLoopback(string address) =>
        address.StartsWith("127.", StringComparison.Ordinal) || address == "::1" || address.StartsWith("::ffff:127.", StringComparison.OrdinalIgnoreCase);

    /// <summary>RFC1918 / link-local / ULA: traffic that does not leave the local network.</summary>
    public static bool IsPrivate(string address)
    {
        if (!System.Net.IPAddress.TryParse(address, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254) || b[0] == 127 || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal || System.Net.IPAddress.IPv6Loopback.Equals(ip);
    }
}

public enum SignatureStatus { Unknown, Valid, Unsigned, Invalid, Unavailable }

/// <summary>Static facts about one running process, gathered once per (PID, start time) and cached.</summary>
public sealed class ProcessDetails
{
    public int Pid { get; init; }
    public string Name { get; init; } = "Unknown Process";
    public string? Path { get; init; }
    public string? Publisher { get; init; }
    public string? FileVersion { get; init; }
    public string? Description { get; init; }
    public SignatureStatus Signature { get; init; } = SignatureStatus.Unknown;
    public string? Signer { get; init; }
    public DateTime? StartTime { get; init; }
    public IReadOnlyList<string> Services { get; init; } = [];
    public bool IsSystemIdle => Pid is 0;
    public bool IsSystem => Pid is 4;
    public bool PathKnown => !string.IsNullOrEmpty(Path);

    /// <summary>Grouping key: same executable = same application, whatever the PID.</summary>
    public string GroupKey => PathKnown ? Path!.ToLowerInvariant() : Pid switch
    {
        0 => "#idle",
        4 => "#system",
        _ => "#pid:" + Pid + ":" + Name.ToLowerInvariant()
    };
}

public enum ActivityClass { Normal, Background, PossibleTelemetry, UpdateService, Unknown }

public static class ActivityClassText
{
    public static string Of(ActivityClass c) => c switch
    {
        ActivityClass.Normal => "Normal",
        ActivityClass.Background => "Background",
        ActivityClass.PossibleTelemetry => "Possible Telemetry",
        ActivityClass.UpdateService => "Update Service",
        _ => "Unknown"
    };
}

public sealed record Classification(ActivityClass Class, IReadOnlyList<string> Reasons);

public enum TimelineKind { Opened, Closed, BlockedAttempt, Dns, Blocked, Unblocked }

public sealed record TimelineEvent(DateTime Time, TimelineKind Kind, string Text);

public sealed class HistoryEntry
{
    public DateTime Time { get; set; }
    public string Application { get; set; } = "";
    public string? Path { get; set; }
    public int Pid { get; set; }
    public string RemoteAddress { get; set; } = "";
    public string? Hostname { get; set; }
    public int Port { get; set; }
    public string Protocol { get; set; } = "";
    /// <summary>Opened, Closed, BlockedAttempt, Blocked, Unblocked, RuleDeleted, RuleEnabled, RuleDisabled.</summary>
    public string Action { get; set; } = "";
    /// <summary>Allowed or Blocked.</summary>
    public string Status { get; set; } = "Allowed";
}

public sealed class FirewallRuleInfo
{
    public string Name { get; init; } = "";
    public string? ApplicationPath { get; init; }
    public string Direction { get; init; } = "Outbound";
    public string Action { get; init; } = "Block";
    public bool Enabled { get; init; }
    public string? Description { get; init; }
    public string ApplicationName => string.IsNullOrEmpty(ApplicationPath) ? "(any)" : System.IO.Path.GetFileName(ApplicationPath);
}

public sealed class AdapterInfo
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string Type { get; init; } = "";
    public string Status { get; init; } = "";
    public long Speed { get; init; }
    public bool IsPrimary { get; init; }
    public bool IsVpn { get; init; }
    public IReadOnlyList<string> IPv4 { get; init; } = [];
    public IReadOnlyList<string> IPv6 { get; init; } = [];
    public IReadOnlyList<string> Gateways { get; init; } = [];
    public IReadOnlyList<string> DnsServers { get; init; } = [];
    public string Mac { get; init; } = "";
}
