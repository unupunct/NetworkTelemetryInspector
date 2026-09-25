using System.Diagnostics;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

/// <summary>Every setting is applied and saved as soon as it changes — there is no Save button to forget.</summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly AppHost _host;
    private readonly MainViewModel _main;

    public SettingsViewModel(AppHost host, MainViewModel main)
    {
        _host = host;
        _main = main;
        _prefixDraft = host.Settings.Current.RulePrefix;
    }

    private AppSettings S => _host.Settings.Current;

    private void Set<T>(T value, Func<AppSettings, T> get, Action<AppSettings, T> set, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(get(S), value)) return;
        _host.Settings.Update(s => set(s, value));
        OnPropertyChanged(name);
    }

    public void Reload() => OnPropertyChanged(string.Empty);

    public IReadOnlyList<int> IntervalOptions { get; } = [1000, 2000, 3000, 5000, 10000];
    public IReadOnlyList<int> RetentionOptions { get; } = [1, 3, 7, 14, 30, 90, 365];

    // Monitoring
    public int RefreshIntervalMs { get => S.RefreshIntervalMs; set => Set(value, s => s.RefreshIntervalMs, (s, v) => s.RefreshIntervalMs = v); }
    public bool StartWithWindows { get => S.StartWithWindows; set => Set(value, s => s.StartWithWindows, (s, v) => s.StartWithWindows = v); }
    public bool MinimizeToTray { get => S.MinimizeToTray; set => Set(value, s => s.MinimizeToTray, (s, v) => s.MinimizeToTray = v); }
    public bool MonitorBackgroundActivity { get => S.MonitorBackgroundActivity; set => Set(value, s => s.MonitorBackgroundActivity, (s, v) => s.MonitorBackgroundActivity = v); }
    public bool ResolveHostnames { get => S.ResolveHostnames; set => Set(value, s => s.ResolveHostnames, (s, v) => s.ResolveHostnames = v); }
    public bool RecordHistory { get => S.RecordHistory; set => Set(value, s => s.RecordHistory, (s, v) => s.RecordHistory = v); }
    public bool ShowLocalTraffic { get => S.ShowLocalTraffic; set => Set(value, s => s.ShowLocalTraffic, (s, v) => s.ShowLocalTraffic = v); }
    public bool ShowListeningAndUdp { get => S.ShowListeningAndUdp; set => Set(value, s => s.ShowListeningAndUdp, (s, v) => s.ShowListeningAndUdp = v); }

    // Privacy
    public bool PublicIpLookup
    {
        get => S.PublicIpLookup;
        set { Set(value, s => s.PublicIpLookup, (s, v) => s.PublicIpLookup = v); _ = _main.RefreshNetworkAsync(publicIp: true); }
    }
    public bool ReverseDnsLookup { get => S.ReverseDnsLookup; set => Set(value, s => s.ReverseDnsLookup, (s, v) => s.ReverseDnsLookup = v); }
    public int HistoryRetentionDays
    {
        get => S.HistoryRetentionDays;
        set { Set(value, s => s.HistoryRetentionDays, (s, v) => s.HistoryRetentionDays = v); _host.History.Prune(value); }
    }

    // Firewall
    public bool RequireBlockConfirmation { get => S.RequireBlockConfirmation; set => Set(value, s => s.RequireBlockConfirmation, (s, v) => s.RequireBlockConfirmation = v); }
    public bool RemoveRulesOnUninstall { get => S.RemoveRulesOnUninstall; set => Set(value, s => s.RemoveRulesOnUninstall, (s, v) => s.RemoveRulesOnUninstall = v); }
    public bool ReadOnlyMode { get => S.ReadOnlyMode; set => Set(value, s => s.ReadOnlyMode, (s, v) => s.ReadOnlyMode = v); }

    [ObservableProperty] private string _prefixDraft = "";
    [ObservableProperty] private string? _prefixError;
    public string RulePrefix => S.RulePrefix;
    public string RuleExample => RuleNaming.BuildName(S.RulePrefix, @"C:\Program Files\Example\Example.exe");

    // Notifications
    public bool NotifyNewApplication { get => S.NotifyNewApplication; set => Set(value, s => s.NotifyNewApplication, (s, v) => s.NotifyNewApplication = v); }
    public bool NotifyBlocked { get => S.NotifyBlocked; set => Set(value, s => s.NotifyBlocked, (s, v) => s.NotifyBlocked = v); }
    public bool NotifyUnusualBackground { get => S.NotifyUnusualBackground; set => Set(value, s => s.NotifyUnusualBackground, (s, v) => s.NotifyUnusualBackground = v); }

    // Appearance
    public ThemeMode Theme
    {
        get => S.Theme;
        set { Set(value, s => s.Theme, (s, v) => s.Theme = v); App.ApplyTheme(value); }
    }

    public string DataFolder => AppPaths.Root;
    public string RulesFile => AppPaths.Rules;
    public string LogFile => Log.CurrentFile;

    [RelayCommand]
    private void ApplyPrefix()
    {
        var p = (PrefixDraft ?? "").Trim();
        if (!RuleNaming.IsValidPrefix(p))
        {
            PrefixError = "Use 2–24 letters, digits or underscores, starting with a letter.";
            return;
        }
        PrefixError = null;
        _host.Settings.Update(s => s.RulePrefix = p);
        OnPropertyChanged(nameof(RulePrefix));
        OnPropertyChanged(nameof(RuleExample));
        _main.Toast("New rules will be named " + RuleExample + ". Existing rules keep their names and remain managed.", "Success");
    }

    [RelayCommand]
    private void OpenDataFolder() => OpenPath(AppPaths.Root);

    [RelayCommand]
    private void OpenRulesFile() => OpenPath(AppPaths.Rules);

    [RelayCommand]
    private void OpenLogFolder() => OpenPath(AppPaths.Logs);

    [RelayCommand]
    private void ReloadRules()
    {
        _host.ReloadRules();
        _main.Toast("Classification rules reloaded.", "Success");
    }

    private void OpenPath(string path)
    {
        try
        {
            AppPaths.EnsureCreated();
            if (!File.Exists(path) && !Directory.Exists(path)) { _main.Toast("Not found: " + path, "Warning"); return; }
            var psi = new ProcessStartInfo("explorer.exe") { UseShellExecute = false };
            psi.ArgumentList.Add(path);
            Process.Start(psi);
        }
        catch (Exception ex) { _main.Toast(FriendlyError.Describe(ex), "Danger"); }
    }

    [RelayCommand]
    private async Task Uninstall()
    {
        var removeRules = S.RemoveRulesOnUninstall;
        var ok = await _main.ConfirmAsync("Uninstall Network & Telemetry Inspector?",
            "This portable app has no installer. Uninstalling cleans up everything it created, then exits:\n\n" +
            (removeRules ? "• all firewall rules created by this application (administrator permission required)\n" : "• firewall rules are KEPT (\"Remove rules on uninstall\" is off)\n") +
            "• the Start with Windows entry\n• settings, history and logs in " + AppPaths.Root +
            "\n\nAfterwards you can simply delete NetworkTelemetryInspector.exe.",
            "Uninstall", true);
        if (!ok) return;

        if (removeRules)
        {
            var r = await _host.Firewall.RemoveAllAsync();
            if (!r.Ok)
            {
                _main.Toast("Uninstall stopped: " + r.Message, "Danger");
                return;
            }
        }
        App.UninstallAndExit();
    }
}
