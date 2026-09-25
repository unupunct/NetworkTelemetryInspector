using System.Diagnostics;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Processes;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Network;

/// <summary>
/// The monitoring engine. One dedicated background thread polls the OS connection table at the
/// configured interval, diffs it against the previous poll (new / closed), aggregates by
/// executable, samples traffic counters, classifies and publishes an immutable
/// <see cref="MonitorSnapshot"/>. A second light timer samples adapter throughput once per second
/// for the live graph. Nothing here touches the UI thread.
/// </summary>
public sealed class NetworkMonitor : IDisposable
{
    private sealed class ConnTrack
    {
        public required ConnectionKey Key;
        public TcpState State;
        public DateTime FirstSeen, LastSeen;
        public ulong? LastIn, LastOut;
        public ulong? BytesIn, BytesOut;
        public double RateIn, RateOut;
        public bool BlockedAttemptLogged;
    }

    private sealed class AppTrack
    {
        public required string GroupKey;
        public ProcessDetails Details = null!;
        public DateTime FirstSeen, LastSeen;
        public int TotalConnections;
        public ulong TotalIn, TotalOut;
        public readonly List<TimelineEvent> Timeline = new();
        public int TimelineVersion;
        public readonly HashSet<string> RemoteAddresses = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> Hostnames = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<int> Ports = new();
        public readonly HashSet<string> Protocols = new();
        public readonly Queue<DateTime> RecentOpens = new();
        public Classification Classification = new(ActivityClass.Unknown, []);
        public int ClassifiedHostCount = -1;
        public DateTime ClassifiedAt;
        public DateTime LastUnusualNotice;
        public bool WasBlocked;

        public void AddTimeline(TimelineEvent e)
        {
            Timeline.Add(e);
            if (Timeline.Count > 120) Timeline.RemoveRange(0, Timeline.Count - 120);
            TimelineVersion++;
        }
    }

    private readonly ConnectionTable _table = new();
    private readonly TcpTrafficCounter _traffic = new();
    private readonly AdapterService _adapters;
    private readonly ProcessInspector _processes;
    private readonly HostnameResolver _resolver;
    private readonly TelemetryClassifier _classifier;
    private readonly FirewallService _firewall;
    private readonly HistoryStore _history;
    private readonly WindowActivity _windows = new();
    private readonly Func<AppSettings> _settings;

    private readonly Dictionary<ConnectionKey, ConnTrack> _conns = new();
    private readonly Dictionary<string, AppTrack> _apps = new();
    private readonly Dictionary<string, (string Name, DateTime Time)> _recentLookups = new();
    private readonly object _lookupLock = new();
    private readonly Queue<DateTime> _recentOpens = new();
    private readonly HashSet<string> _seenApps = new();
    // Window/focus state per executable: a browser's network process has no window, its UI process does.
    private readonly Dictionary<string, DateTime> _groupForeground = new();
    private HashSet<string> _windowedGroups = new();

    private readonly AutoResetEvent _wake = new(false);
    private Thread? _thread;
    private Timer? _throughputTimer;
    private volatile bool _disposed;
    private volatile bool _paused;
    private bool _firstTick = true;
    private long _lastTick;
    private readonly DateTime _started = DateTime.Now;

    public NetworkMonitor(AdapterService adapters, ProcessInspector processes, HostnameResolver resolver,
        TelemetryClassifier classifier, FirewallService firewall, HistoryStore history, Func<AppSettings> settings)
    {
        _adapters = adapters;
        _processes = processes;
        _resolver = resolver;
        _classifier = classifier;
        _firewall = firewall;
        _history = history;
        _settings = settings;
        _resolver.DnsLookupObserved += OnDnsLookup;
    }

    public event Action<MonitorSnapshot>? SnapshotReady;
    public event Action<double, double>? ThroughputSampled;
    public event Action<MonitorNotice>? Notice;
    public event Action<bool>? PausedChanged;

    public bool IsPaused => _paused;
    public MonitorSnapshot? Latest { get; private set; }
    public int TickCount { get; private set; }

    public void Start()
    {
        if (_thread is not null) return;
        _thread = new Thread(Loop) { IsBackground = true, Name = "NTI monitor", Priority = ThreadPriority.BelowNormal };
        _thread.Start();
        _throughputTimer = new Timer(_ => SampleThroughput(), null, 0, 1000);
    }

    public void Pause()
    {
        _paused = true;
        PausedChanged?.Invoke(true);
    }

    public void Resume()
    {
        _paused = false;
        PausedChanged?.Invoke(false);
        _wake.Set();
    }

    public void RefreshNow() => _wake.Set();

    private void SampleThroughput()
    {
        if (_paused || _disposed) return;
        try
        {
            var (up, down) = _adapters.SampleThroughput();
            ThroughputSampled?.Invoke(up, down);
        }
        catch (Exception ex) { Log.Debug("Monitor", "Throughput: " + ex.Message); }
    }

    private void Loop()
    {
        while (!_disposed)
        {
            if (!_paused)
            {
                try { Tick(); }
                catch (Exception ex) { Log.Error("Monitor", "Monitoring cycle failed; continuing", ex); }
            }
            _wake.WaitOne(_settings().RefreshIntervalMs);
        }
    }

    private void OnDnsLookup(string name, IReadOnlyList<string> addresses)
    {
        lock (_lookupLock)
        {
            foreach (var a in addresses) _recentLookups[a] = (name.TrimEnd('.').ToLowerInvariant(), DateTime.Now);
        }
    }

    /// <summary>One monitoring cycle. Public for the headless self-test.</summary>
    public MonitorSnapshot Tick()
    {
        var sw = Stopwatch.StartNew();
        var s = _settings();
        var now = DateTime.Now;
        var nowTick = Environment.TickCount64;
        var seconds = _lastTick == 0 ? 0 : (nowTick - _lastTick) / 1000.0;
        _lastTick = nowTick;

        _resolver.Enabled = s.ResolveHostnames;
        _resolver.ReverseLookupEnabled = s.ResolveHostnames && s.ReverseDnsLookup;
        _history.Enabled = s.RecordHistory;
        _resolver.RefreshCache(TimeSpan.FromSeconds(8));
        _windows.Sample();

        var samples = _table.Read(includeUdp: s.ShowListeningAndUdp);
        var live = new HashSet<ConnectionKey>();
        var opened = new List<ConnTrack>();

        foreach (var c in samples)
        {
            if (!Include(c, s)) continue;
            live.Add(c.Key);
            if (!_conns.TryGetValue(c.Key, out var t))
            {
                t = new ConnTrack { Key = c.Key, FirstSeen = now };
                _conns[c.Key] = t;
                opened.Add(t);
            }
            t.State = c.State;
            t.LastSeen = now;

            var counters = _traffic.Read(c);
            if (counters is { } v)
            {
                if (t.LastIn is { } li && t.LastOut is { } lo && seconds > 0)
                {
                    t.RateIn = v.In >= li ? (v.In - li) / seconds : 0;
                    t.RateOut = v.Out >= lo ? (v.Out - lo) / seconds : 0;
                }
                t.LastIn = v.In;
                t.LastOut = v.Out;
                t.BytesIn = v.In;
                t.BytesOut = v.Out;
            }
            else
            {
                t.RateIn = t.RateOut = 0;
            }
        }
        _traffic.Retain(live);

        // Closed connections.
        var closed = _conns.Values.Where(t => !live.Contains(t.Key)).ToList();
        foreach (var t in closed) _conns.Remove(t.Key);

        // Details once per PID this tick.
        var detailsByPid = new Dictionary<int, ProcessDetails>();
        ProcessDetails DetailsOf(int pid)
        {
            if (!detailsByPid.TryGetValue(pid, out var d)) detailsByPid[pid] = d = _processes.Get(pid);
            return d;
        }

        // Which executables have a visible window / the foreground (any of their processes).
        _windowedGroups = _windows.WindowedPids.Select(p => DetailsOf(p).GroupKey).ToHashSet();
        if (_windows.ForegroundPid > 0) _groupForeground[DetailsOf(_windows.ForegroundPid).GroupKey] = now;

        // Aggregate live connections per application.
        var liveByApp = new Dictionary<string, List<ConnTrack>>();
        var pidsByApp = new Dictionary<string, SortedSet<int>>();
        foreach (var t in _conns.Values)
        {
            var d = DetailsOf(t.Key.Pid);
            var key = d.GroupKey;
            if (!_apps.TryGetValue(key, out var app))
            {
                app = new AppTrack { GroupKey = key, FirstSeen = now, Details = d };
                _apps[key] = app;
                if (_seenApps.Add(key) && !_firstTick)
                    Notice?.Invoke(new MonitorNotice(MonitorNoticeKind.NewApplication, d.Name, $"{d.Name} connected to the network."));
            }
            app.Details = d;
            app.LastSeen = now;
            if (!liveByApp.TryGetValue(key, out var list)) { liveByApp[key] = list = new(); pidsByApp[key] = new(); }
            list.Add(t);
            pidsByApp[key].Add(t.Key.Pid);
        }
        if (_firstTick) foreach (var k in _apps.Keys) _seenApps.Add(k);

        var blockedPaths = _firewall.BlockedPaths;

        // Timeline + history for opened connections.
        foreach (var t in opened)
        {
            var d = DetailsOf(t.Key.Pid);
            var app = _apps[d.GroupKey];
            app.TotalConnections++;
            var host = _resolver.Get(t.Key.RemoteAddress);
            if (host.Name is null && t.Key.RemotePort != 0) _resolver.Request(t.Key.RemoteAddress);
            var blocked = d.Path is not null && blockedPaths.Contains(d.Path);

            if (!_firstTick)
            {
                (string Name, DateTime Time) lookup = default;
                bool hasLookup;
                lock (_lookupLock) hasLookup = _recentLookups.TryGetValue(t.Key.RemoteAddress, out lookup);
                if (hasLookup && now - lookup.Time < TimeSpan.FromSeconds(15))
                    app.AddTimeline(new TimelineEvent(lookup.Time, TimelineKind.Dns, "DNS lookup " + lookup.Name));

                app.AddTimeline(new TimelineEvent(now, TimelineKind.Opened, Format.Endpoint(t.Key.RemoteAddress, t.Key.RemotePort) + Suffix(host.Name)));
                app.RecentOpens.Enqueue(now);
                _recentOpens.Enqueue(now);
                Record(d, t, host.Name, "Opened", blocked);
            }
        }

        // Closed connections.
        foreach (var t in closed)
        {
            var d = DetailsOf(t.Key.Pid);
            if (!_apps.TryGetValue(d.GroupKey, out var app)) continue;
            app.AddTimeline(new TimelineEvent(now, TimelineKind.Closed, Format.Endpoint(t.Key.RemoteAddress, t.Key.RemotePort) + Suffix(_resolver.Get(t.Key.RemoteAddress).Name)));
            Record(d, t, _resolver.Get(t.Key.RemoteAddress).Name, "Closed", d.Path is not null && blockedPaths.Contains(d.Path));
        }

        // Prune rolling windows.
        var minute = now.AddSeconds(-60);
        while (_recentOpens.Count > 0 && _recentOpens.Peek() < minute) _recentOpens.Dequeue();
        lock (_lookupLock)
        {
            if (_recentLookups.Count > 0)
                foreach (var k in _recentLookups.Where(kv => now - kv.Value.Time > TimeSpan.FromSeconds(30)).Select(kv => kv.Key).ToList())
                    _recentLookups.Remove(k);
        }

        // Build application views.
        var views = new List<AppView>(_apps.Count);
        var activeConnections = 0;
        var appsOnline = 0;
        foreach (var app in _apps.Values.ToList())
        {
            liveByApp.TryGetValue(app.GroupKey, out var conns);
            conns ??= new List<ConnTrack>();
            while (app.RecentOpens.Count > 0 && app.RecentOpens.Peek() < minute) app.RecentOpens.Dequeue();

            var blocked = app.Details.Path is not null && blockedPaths.Contains(app.Details.Path);
            if (blocked != app.WasBlocked)
            {
                app.AddTimeline(new TimelineEvent(now, blocked ? TimelineKind.Blocked : TimelineKind.Unblocked,
                    blocked ? "Internet access blocked by firewall rule" : "Internet access restored"));
                app.WasBlocked = blocked;
            }

            // Keep an app listed for two minutes after its last connection (and blocked apps for the session).
            if (conns.Count == 0 && !blocked && now - app.LastSeen > TimeSpan.FromMinutes(2))
            {
                _apps.Remove(app.GroupKey);
                continue;
            }

            var connViews = new List<ConnectionView>(conns.Count);
            double rin = 0, rout = 0;
            foreach (var t in conns)
            {
                var host = _resolver.Get(t.Key.RemoteAddress);
                if (host.Name is null && t.Key.RemotePort != 0) _resolver.Request(t.Key.RemoteAddress);
                if (host.Name is not null) app.Hostnames.Add(host.Name);
                if (t.Key.RemotePort != 0)
                {
                    app.RemoteAddresses.Add(t.Key.RemoteAddress);
                    app.Ports.Add(t.Key.RemotePort);
                }
                app.Protocols.Add(ProtocolText.Of(t.Key.Protocol));

                // A blocked app's connection stuck in SYN_SENT is an attempt the firewall is dropping.
                var attempt = blocked && t.State == TcpState.SynSent;
                if (attempt && !t.BlockedAttemptLogged)
                {
                    t.BlockedAttemptLogged = true;
                    app.AddTimeline(new TimelineEvent(now, TimelineKind.BlockedAttempt,
                        "Blocked attempt " + Format.Endpoint(t.Key.RemoteAddress, t.Key.RemotePort) + Suffix(host.Name)));
                    Record(app.Details, t, host.Name, "BlockedAttempt", true);
                }

                rin += t.RateIn;
                rout += t.RateOut;
                connViews.Add(new ConnectionView(t.Key, t.State, host.Name, host.Source, t.RateIn, t.RateOut,
                    t.BytesIn, t.BytesOut, t.FirstSeen, t.LastSeen, attempt));
            }
            if (seconds > 0)
            {
                app.TotalIn += (ulong)(rin * seconds);
                app.TotalOut += (ulong)(rout * seconds);
            }
            if (app.Hostnames.Count > 500) app.Hostnames.Clear();
            if (app.RemoteAddresses.Count > 500) app.RemoteAddresses.Clear();

            // Reclassify when new hostnames arrived, or every 10 s (foreground state changes).
            if (app.ClassifiedHostCount != app.Hostnames.Count || now - app.ClassifiedAt > TimeSpan.FromSeconds(10))
            {
                app.Classification = _classifier.Classify(new ClassificationInput
                {
                    Process = app.Details,
                    Hostnames = app.Hostnames,
                    HasVisibleWindow = _windowedGroups.Contains(app.GroupKey),
                    LastForeground = _groupForeground.TryGetValue(app.GroupKey, out var fgAt) ? fgAt : null,
                    Now = now,
                    MonitoringStarted = _started,
                    MonitorBackground = s.MonitorBackgroundActivity
                });
                app.ClassifiedHostCount = app.Hostnames.Count;
                app.ClassifiedAt = now;
            }

            if (s.MonitorBackgroundActivity && app.Classification.Class == ActivityClass.Background &&
                app.RecentOpens.Count >= 40 && now - app.LastUnusualNotice > TimeSpan.FromMinutes(15))
            {
                app.LastUnusualNotice = now;
                Notice?.Invoke(new MonitorNotice(MonitorNoticeKind.UnusualBackground, app.Details.Name,
                    $"{app.Details.Name} opened {app.RecentOpens.Count} connections in the last minute while in the background."));
            }

            activeConnections += conns.Count;
            if (conns.Count > 0) appsOnline++;

            views.Add(new AppView(
                app.GroupKey, app.Details,
                pidsByApp.TryGetValue(app.GroupKey, out var pidSet) ? pidSet.ToList() : new List<int>(),
                connViews
                    .OrderBy(c => c.State == TcpState.Established ? 0 : 1)
                    .ThenByDescending(c => c.RateIn + c.RateOut)
                    .ThenByDescending(c => c.FirstSeen)
                    .ToList(),
                app.TotalConnections, rin, rout, app.TotalIn, app.TotalOut, app.FirstSeen, app.LastSeen,
                app.Classification, blocked, app.Timeline.ToArray(), app.TimelineVersion,
                app.RemoteAddresses.Take(200).ToList(), app.Hostnames.Take(200).ToList(),
                app.Ports.OrderBy(p => p).Take(100).ToList(), app.Protocols.OrderBy(p => p).ToList()));
        }

        if (opened.Count > 0 || closed.Count > 0) _history.NotifyChanged();

        var snapshot = new MonitorSnapshot(now, views, activeConnections, appsOnline, blockedPaths.Count,
            _recentOpens.Count, _traffic.Available, _traffic.UnavailableReason, sw.Elapsed);
        Latest = snapshot;
        TickCount++;
        _firstTick = false;
        try { SnapshotReady?.Invoke(snapshot); } catch (Exception ex) { Log.Error("Monitor", "Snapshot listener failed", ex); }
        return snapshot;
    }

    private static string Suffix(string? host) => host is null ? "" : "  " + host;

    private static bool Include(ConnectionSample c, AppSettings s)
    {
        // PID 0 rows are sockets whose process already exited (TIME_WAIT): not an application.
        if (c.Pid == 0) return false;
        if (ProtocolText.IsTcp(c.Protocol))
        {
            if (c.State == TcpState.Listen) return s.ShowListeningAndUdp;
            if (!c.HasRemote) return false;
        }
        else if (!s.ShowListeningAndUdp) return false;
        if (!s.ShowLocalTraffic && c.IsLoopback) return false;
        return true;
    }

    private void Record(ProcessDetails d, ConnTrack t, string? host, string action, bool blocked)
    {
        if (!_history.Enabled || t.Key.RemotePort == 0) return;
        _history.Add(new HistoryEntry
        {
            Time = DateTime.Now,
            Application = d.Name,
            Path = d.Path,
            Pid = t.Key.Pid,
            RemoteAddress = t.Key.RemoteAddress,
            Hostname = host,
            Port = t.Key.RemotePort,
            Protocol = ProtocolText.Of(t.Key.Protocol),
            Action = action,
            Status = blocked ? "Blocked" : "Allowed"
        });
    }

    /// <summary>Adds a user action (block/unblock) to the app timeline and history.</summary>
    public void RecordUserAction(string? path, string appName, string action, bool blocked)
    {
        _history.Add(new HistoryEntry
        {
            Time = DateTime.Now, Application = appName, Path = path, Action = action,
            Status = blocked ? "Blocked" : "Allowed", Protocol = "—"
        });
        _history.NotifyChanged();
    }

    public void Dispose()
    {
        _disposed = true;
        _wake.Set();
        _throughputTimer?.Dispose();
        _thread?.Join(2000);
        _table.Dispose();
    }
}
