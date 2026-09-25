using NetworkTelemetryInspector.Models;

namespace NetworkTelemetryInspector.Network;

/// <summary>Immutable view of one connection, handed from the monitor thread to the UI.</summary>
public sealed record ConnectionView(
    ConnectionKey Key,
    TcpState State,
    string? Hostname,
    HostnameSource HostnameSource,
    double RateIn,
    double RateOut,
    ulong? BytesIn,
    ulong? BytesOut,
    DateTime FirstSeen,
    DateTime LastSeen,
    bool BlockedAttempt)
{
    public string ProtocolText => Models.ProtocolText.Of(Key.Protocol);
}

/// <summary>Immutable view of one application (all PIDs of the same executable).</summary>
public sealed record AppView(
    string GroupKey,
    ProcessDetails Details,
    IReadOnlyList<int> Pids,
    IReadOnlyList<ConnectionView> Connections,
    int TotalConnections,
    double RateIn,
    double RateOut,
    ulong TotalIn,
    ulong TotalOut,
    DateTime FirstSeen,
    DateTime LastSeen,
    Classification Classification,
    bool Blocked,
    IReadOnlyList<TimelineEvent> Timeline,
    int TimelineVersion,
    IReadOnlyList<string> RemoteAddresses,
    IReadOnlyList<string> Hostnames,
    IReadOnlyList<int> RemotePorts,
    IReadOnlyList<string> Protocols);

public sealed record MonitorSnapshot(
    DateTime Time,
    IReadOnlyList<AppView> Apps,
    int ActiveConnections,
    int AppsOnline,
    int Blocked,
    int NewConnections,
    bool TrafficPerApp,
    string TrafficUnavailableReason,
    TimeSpan TickCost);

public enum MonitorNoticeKind { NewApplication, UnusualBackground }

public sealed record MonitorNotice(MonitorNoticeKind Kind, string Application, string Message);
