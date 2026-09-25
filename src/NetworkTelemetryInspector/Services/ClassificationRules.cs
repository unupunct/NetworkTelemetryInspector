using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Services;

/// <summary>
/// User-editable pattern lists for the heuristic classifier, stored as
/// classification-rules.json. Patterns use * as a wildcard and match case-insensitively.
/// </summary>
public sealed class ClassificationRules
{
    public List<string> TelemetryHostPatterns { get; set; } =
    [
        "*.events.data.microsoft.com", "*.telemetry.microsoft.com", "vortex*.data.microsoft.com",
        "settings-win.data.microsoft.com", "watson.*.microsoft.com", "*.data.microsoft.com",
        "*telemetry*", "*google-analytics.com", "*googletagmanager.com", "app-measurement.com",
        "*.app-measurement.com", "*analytics*", "*metrics*", "*.crashlytics.com", "*.sentry.io",
        "*.bugsnag.com", "*.mixpanel.com", "*.segment.io", "*.segment.com", "*.amplitude.com",
        "*.appcenter.ms", "*.hotjar.com", "*.newrelic.com", "*.nr-data.net", "*.datadoghq.com",
        "incoming.telemetry.mozilla.org", "*.doubleclick.net", "*.scorecardresearch.com"
    ];

    public List<string> TelemetryProcesses { get; set; } =
    [
        "CompatTelRunner.exe", "DeviceCensus.exe", "*telemetry*.exe", "*crashreport*.exe", "*crashhandler*.exe",
        "*CrashPad*.exe", "WerFault.exe", "wermgr.exe"
    ];

    public List<string> TelemetryServices { get; set; } = ["DiagTrack", "dmwappushservice", "diagsvc", "WerSvc"];

    public List<string> UpdateProcesses { get; set; } =
    [
        "*update*.exe", "*updater*.exe", "MoUsoCoreWorker.exe", "usoclient.exe", "TiWorker.exe",
        "TrustedInstaller.exe", "*maintenanceservice*.exe", "*autoupdate*.exe", "OneDriveStandaloneUpdater.exe"
    ];

    public List<string> UpdateServices { get; set; } =
        ["wuauserv", "UsoSvc", "BITS", "DoSvc", "WaaSMedicSvc", "edgeupdate", "edgeupdatem", "gupdate", "gupdatem", "MozillaMaintenance", "InstallService"];

    public List<string> UpdateHostPatterns { get; set; } =
    [
        "*.windowsupdate.com", "*.update.microsoft.com", "*.delivery.mp.microsoft.com", "*.dl.delivery.mp.microsoft.com",
        "update.googleapis.com", "dl.google.com", "*.gvt1.com", "edgedl.me.gvt1.com", "msedge.api.cdp.microsoft.com",
        "aus5.mozilla.org", "*.download.windowsupdate.com", "*update*"
    ];

    public static ClassificationRules LoadOrCreate()
    {
        try
        {
            if (File.Exists(AppPaths.Rules))
            {
                var rules = JsonSerializer.Deserialize<ClassificationRules>(File.ReadAllText(AppPaths.Rules));
                if (rules is not null) return rules;
            }
            var defaults = new ClassificationRules();
            AppPaths.EnsureCreated();
            File.WriteAllText(AppPaths.Rules, JsonSerializer.Serialize(defaults, new JsonSerializerOptions { WriteIndented = true }));
            return defaults;
        }
        catch (Exception ex)
        {
            Log.Warn("Rules", "Classification rules unreadable, built-in defaults used: " + ex.Message);
            return new ClassificationRules();
        }
    }
}

public sealed class WildcardSet
{
    private readonly List<(string Pattern, Regex Regex)> _items;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> _memo = new(StringComparer.OrdinalIgnoreCase);

    public WildcardSet(IEnumerable<string> patterns) =>
        _items = patterns.Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => (p, new Regex("^" + Regex.Escape(p.Trim()).Replace("\\*", ".*") + "$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled)))
            .ToList();

    /// <summary>The first pattern that matches, or null.</summary>
    public string? Match(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        if (_memo.TryGetValue(value, out var cached)) return cached;
        string? hit = null;
        foreach (var (pattern, regex) in _items)
            if (regex.IsMatch(value)) { hit = pattern; break; }
        if (_memo.Count > 20000) _memo.Clear();
        _memo[value] = hit;
        return hit;
    }
}
