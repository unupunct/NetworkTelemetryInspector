using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Network;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

/// <summary>One connection row. Updated in place from each snapshot (no row rebuilding).</summary>
public sealed partial class ConnectionItemViewModel : ObservableObject
{
    public ConnectionItemViewModel(ConnectionKey key, AppItemViewModel owner)
    {
        Key = key;
        Owner = owner;
        Protocol = ProtocolText.Of(key.Protocol);
        LocalEndpoint = Format.Endpoint(key.LocalAddress, key.LocalPort);
        RemoteAddress = key.RemoteAddress;
        RemoteEndpoint = key.RemotePort == 0 ? "*" : Format.Endpoint(key.RemoteAddress, key.RemotePort);
        Port = key.RemotePort;
        Pid = key.Pid;
    }

    public ConnectionKey Key { get; }
    public AppItemViewModel Owner { get; }
    public string Protocol { get; }
    public string LocalEndpoint { get; }
    public string RemoteAddress { get; }
    public string RemoteEndpoint { get; }
    public int Port { get; }
    public int Pid { get; }

    [ObservableProperty] private string _state = "";
    [ObservableProperty] private string _hostname = "";
    [ObservableProperty] private string _hostnameSource = "";
    [ObservableProperty] private string _download = "—";
    [ObservableProperty] private string _upload = "—";
    [ObservableProperty] private double _rateTotal;
    [ObservableProperty] private string _firstSeen = "";
    [ObservableProperty] private DateTime _lastSeenTime;
    [ObservableProperty] private bool _isBlockedAttempt;
    [ObservableProperty] private bool _isEstablished;

    public string AppName => Owner.Name;
    public ImageSource? Icon => Owner.Icon;
    public string LastSeen => Format.Ago(LastSeenTime);
    public string Status => Owner.IsBlocked ? "BLOCKED" : "Allowed";

    public void Update(ConnectionView v, bool trafficAvailable)
    {
        State = TcpStateText.Of(v.State);
        IsEstablished = v.State == TcpState.Established;
        Hostname = v.Hostname ?? "";
        HostnameSource = v.HostnameSource switch
        {
            Network.HostnameSource.DnsCache => "From the local DNS cache (the name this PC looked up)",
            Network.HostnameSource.ReverseDns => "From reverse DNS (PTR); may name the hosting provider rather than the service",
            Network.HostnameSource.Local => "Local machine",
            _ => "No hostname known"
        };
        var tcp = ProtocolText.IsTcp(v.Key.Protocol);
        Download = trafficAvailable && tcp ? Format.Rate(v.RateIn) : "—";
        Upload = trafficAvailable && tcp ? Format.Rate(v.RateOut) : "—";
        RateTotal = v.RateIn + v.RateOut;
        FirstSeen = v.FirstSeen.ToString("HH:mm:ss");
        LastSeenTime = v.LastSeen;
        IsBlockedAttempt = v.BlockedAttempt;
        OnPropertyChanged(nameof(LastSeen));
        OnPropertyChanged(nameof(Status));
    }

    public void RefreshStatus() => OnPropertyChanged(nameof(Status));

    /// <summary>Search text match used by the global filter.</summary>
    public bool Matches(string q) =>
        RemoteAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        Hostname.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        Port.ToString() == q ||
        LocalEndpoint.Contains(q, StringComparison.OrdinalIgnoreCase) ||
        Protocol.Equals(q, StringComparison.OrdinalIgnoreCase);
}

public sealed record TimelineItem(string Time, string Text, TimelineKind Kind, string Glyph);

/// <summary>One application (executable) with all its connections.</summary>
public sealed partial class AppItemViewModel : ObservableObject
{
    private readonly Dictionary<ConnectionKey, ConnectionItemViewModel> _byKey = new();
    private int _timelineVersion = -1;

    public AppItemViewModel(string groupKey) => GroupKey = groupKey;

    public string GroupKey { get; }
    public ObservableCollection<ConnectionItemViewModel> Connections { get; } = new();
    public ObservableCollection<TimelineItem> Timeline { get; } = new();

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _subtitle = "";
    [ObservableProperty] private string? _path;
    [ObservableProperty] private string _pathText = "";
    [ObservableProperty] private string _publisher = "";
    [ObservableProperty] private string _signature = "";
    [ObservableProperty] private string _signatureTone = "Neutral";
    [ObservableProperty] private string _fileVersion = "";
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private string _pidText = "";
    [ObservableProperty] private int _mainPid;
    [ObservableProperty] private string _startTime = "";
    [ObservableProperty] private string _services = "";
    [ObservableProperty] private ImageSource? _icon;
    [ObservableProperty] private bool _isUnknownProcess;
    [ObservableProperty] private int _connectionCount;
    [ObservableProperty] private int _establishedCount;
    [ObservableProperty] private int _totalConnections;
    [ObservableProperty] private string _download = "—";
    [ObservableProperty] private string _upload = "—";
    [ObservableProperty] private double _rateTotal;
    [ObservableProperty] private string _totalDownloaded = "—";
    [ObservableProperty] private string _totalUploaded = "—";
    [ObservableProperty] private DateTime _lastSeenTime;
    [ObservableProperty] private string _firstSeen = "";
    [ObservableProperty] private ActivityClass _class = ActivityClass.Unknown;
    [ObservableProperty] private string _classReasons = "";
    [ObservableProperty] private bool _isBlocked;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private bool _isExpanded;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string? _blockRefusal;
    [ObservableProperty] private string _remoteAddresses = "";
    [ObservableProperty] private string _hostnames = "";
    [ObservableProperty] private string _remotePorts = "";
    [ObservableProperty] private string _protocols = "";

    public string LastSeen => IsActive ? "now" : Format.Ago(LastSeenTime);
    public string StatusText => IsBlocked ? "BLOCKED" : IsActive ? "Online" : "Idle";
    public bool CanBlock => Path is not null && BlockRefusal is null;

    public void Update(AppView v, bool trafficAvailable, Func<string?, ImageSource?> iconLoader)
    {
        var d = v.Details;
        if (Name != d.Name) Name = d.Name;
        IsUnknownProcess = !d.PathKnown && !d.IsSystem;
        if (Path != d.Path)
        {
            Path = d.Path;
            Icon = iconLoader(d.Path);
            BlockRefusal = d.Path is null
                ? (d.IsSystem ? "The Windows kernel (System) cannot be blocked per application." : "The executable path is unavailable, so no firewall rule can target it.")
                : PathValidator.RefusalReason(d.Path);
            OnPropertyChanged(nameof(CanBlock));
        }
        PathText = d.Path ?? Format.Unavailable;
        Publisher = d.Publisher ?? (d.PathKnown ? "Unknown publisher" : Format.Unavailable);
        (Signature, SignatureTone) = d.Signature switch
        {
            SignatureStatus.Valid => ("✓ Valid" + (d.Signer is null ? "" : " — " + d.Signer), "Success"),
            SignatureStatus.Unsigned => ("Not signed", "Warning"),
            SignatureStatus.Invalid => ("✗ Invalid or untrusted signature", "Danger"),
            _ => (Format.Unavailable, "Neutral")
        };
        FileVersion = d.FileVersion ?? (d.PathKnown ? "—" : Format.Unavailable);
        Description = d.Description ?? "";
        Services = d.Services.Count == 0 ? "" : string.Join(", ", d.Services);
        Subtitle = Services.Length > 0 ? "Services: " + Services
            : d.Description ?? d.Publisher ?? (d.PathKnown ? System.IO.Path.GetDirectoryName(d.Path) ?? "" : "Executable path unavailable");

        var pids = v.Pids.Count > 0 ? v.Pids : new[] { d.Pid };
        MainPid = pids[0];
        PidText = pids.Count switch { 1 => pids[0].ToString(), _ => $"{pids[0]} +{pids.Count - 1}" };
        StartTime = d.StartTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? Format.Unavailable;

        ConnectionCount = v.Connections.Count;
        EstablishedCount = v.Connections.Count(c => c.State == TcpState.Established);
        TotalConnections = v.TotalConnections;
        IsActive = v.Connections.Count > 0;
        Download = trafficAvailable ? Format.Rate(v.RateIn) : "—";
        Upload = trafficAvailable ? Format.Rate(v.RateOut) : "—";
        RateTotal = v.RateIn + v.RateOut;
        TotalDownloaded = trafficAvailable ? Format.Bytes(v.TotalIn) : "Requires administrator";
        TotalUploaded = trafficAvailable ? Format.Bytes(v.TotalOut) : "Requires administrator";
        LastSeenTime = v.LastSeen;
        FirstSeen = v.FirstSeen.ToString("HH:mm:ss");
        Class = v.Classification.Class;
        ClassReasons = string.Join(Environment.NewLine, v.Classification.Reasons.Select(r => "• " + r));
        IsBlocked = v.Blocked;
        RemoteAddresses = v.RemoteAddresses.Count == 0 ? "—" : string.Join(", ", v.RemoteAddresses.Take(60));
        Hostnames = v.Hostnames.Count == 0 ? "None resolved yet" : string.Join(", ", v.Hostnames.Take(60));
        RemotePorts = v.RemotePorts.Count == 0 ? "—" : string.Join(", ", v.RemotePorts);
        Protocols = v.Protocols.Count == 0 ? "—" : string.Join(", ", v.Protocols);
        OnPropertyChanged(nameof(LastSeen));
        OnPropertyChanged(nameof(StatusText));

        SyncConnections(v.Connections, trafficAvailable);

        if (v.TimelineVersion != _timelineVersion)
        {
            _timelineVersion = v.TimelineVersion;
            SyncTimeline(v.Timeline);
        }
    }

    private void SyncConnections(IReadOnlyList<ConnectionView> views, bool trafficAvailable)
    {
        var live = new HashSet<ConnectionKey>();
        foreach (var cv in views)
        {
            live.Add(cv.Key);
            if (!_byKey.TryGetValue(cv.Key, out var item))
            {
                item = new ConnectionItemViewModel(cv.Key, this);
                _byKey[cv.Key] = item;
                Connections.Add(item);
            }
            item.Update(cv, trafficAvailable);
        }
        for (var i = Connections.Count - 1; i >= 0; i--)
        {
            if (!live.Contains(Connections[i].Key))
            {
                _byKey.Remove(Connections[i].Key);
                Connections.RemoveAt(i);
            }
        }
    }

    private void SyncTimeline(IReadOnlyList<TimelineEvent> events)
    {
        // Newest first; only the tail changes, so rebuilding at most 120 small records is cheap.
        Timeline.Clear();
        for (var i = events.Count - 1; i >= 0 && Timeline.Count < 60; i--)
        {
            var e = events[i];
            Timeline.Add(new TimelineItem(e.Time.ToString("HH:mm:ss"), e.Text, e.Kind, e.Kind switch
            {
                TimelineKind.Opened => "→",
                TimelineKind.Closed => "×",
                TimelineKind.BlockedAttempt => "⊘",
                TimelineKind.Dns => "?",
                TimelineKind.Blocked => "⊘",
                TimelineKind.Unblocked => "✓",
                _ => "•"
            }));
        }
    }

    public bool Matches(string q)
    {
        if (Name.Contains(q, StringComparison.OrdinalIgnoreCase)) return true;
        if (Path?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) return true;
        if (Publisher.Contains(q, StringComparison.OrdinalIgnoreCase)) return true;
        if (Services.Contains(q, StringComparison.OrdinalIgnoreCase)) return true;
        if (PidText.StartsWith(q, StringComparison.Ordinal)) return true;
        foreach (var c in Connections) if (c.Matches(q)) return true;
        return Hostnames.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    partial void OnIsBlockedChanged(bool value)
    {
        OnPropertyChanged(nameof(StatusText));
        foreach (var c in Connections) c.RefreshStatus();
    }
}
