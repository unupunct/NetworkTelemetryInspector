namespace NetworkTelemetryInspector.Models;

public enum ThemeMode { Dark, Light, System }

public sealed class AppSettings
{
    // Monitoring
    public int RefreshIntervalMs { get; set; } = 2000;
    public bool StartWithWindows { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public bool MonitorBackgroundActivity { get; set; } = true;
    public bool ResolveHostnames { get; set; } = true;
    public bool RecordHistory { get; set; } = true;
    public bool ShowLocalTraffic { get; set; }
    public bool ShowListeningAndUdp { get; set; }

    // Privacy
    public bool PublicIpLookup { get; set; } = true;
    /// <summary>Reverse DNS (PTR) queries to the configured DNS server. The local DNS cache is always read.</summary>
    public bool ReverseDnsLookup { get; set; } = true;
    public int HistoryRetentionDays { get; set; } = 14;

    // Firewall
    public bool RequireBlockConfirmation { get; set; } = true;
    public string RulePrefix { get; set; } = "NTI_BLOCK";
    public bool RemoveRulesOnUninstall { get; set; } = true;
    public bool ReadOnlyMode { get; set; }

    // Notifications (minimal by default)
    public bool NotifyNewApplication { get; set; }
    public bool NotifyBlocked { get; set; } = true;
    public bool NotifyUnusualBackground { get; set; }

    // Appearance
    public ThemeMode Theme { get; set; } = ThemeMode.Dark;

    public bool FirstRunCompleted { get; set; }

    public AppSettings Clone() => (AppSettings)MemberwiseClone();

    /// <summary>Clamps every value into its supported range; settings files are user editable.</summary>
    public void Normalize()
    {
        RefreshIntervalMs = Math.Clamp(RefreshIntervalMs, 1000, 10000);
        HistoryRetentionDays = Math.Clamp(HistoryRetentionDays, 1, 365);
        if (!Firewall.RuleNaming.IsValidPrefix(RulePrefix)) RulePrefix = "NTI_BLOCK";
        if (!Enum.IsDefined(Theme)) Theme = ThemeMode.Dark;
    }
}
