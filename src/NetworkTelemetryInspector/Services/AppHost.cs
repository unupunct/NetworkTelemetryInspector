using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Network;
using NetworkTelemetryInspector.Processes;

namespace NetworkTelemetryInspector.Services;

/// <summary>Composition root: every long-lived service, created once at startup.</summary>
public sealed class AppHost : IDisposable
{
    public SettingsService Settings { get; } = new();
    public ClassificationRules Rules { get; private set; }
    public TelemetryClassifier Classifier { get; }
    public ProcessInspector Processes { get; } = new();
    public HostnameResolver Resolver { get; } = new();
    public AdapterService Adapters { get; } = new();
    public PublicIpService PublicIp { get; } = new();
    public HistoryStore History { get; } = new();
    public FirewallService Firewall { get; }
    public NetworkMonitor Monitor { get; }

    public AppHost()
    {
        Settings.Load();
        Rules = ClassificationRules.LoadOrCreate();
        Classifier = new TelemetryClassifier(Rules);
        Firewall = new FirewallService(() => Settings.Current);
        History.Enabled = Settings.Current.RecordHistory;
        History.Load(Settings.Current.HistoryRetentionDays);
        Monitor = new NetworkMonitor(Adapters, Processes, Resolver, Classifier, Firewall, History, () => Settings.Current);
    }

    public void ReloadRules()
    {
        Rules = ClassificationRules.LoadOrCreate();
        Classifier.Apply(Rules);
    }

    public void Dispose()
    {
        Monitor.Dispose();
        History.Dispose();
    }
}
