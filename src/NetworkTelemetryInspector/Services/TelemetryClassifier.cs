using NetworkTelemetryInspector.Models;

namespace NetworkTelemetryInspector.Services;

/// <summary>What the classifier knows about one application at one moment.</summary>
public sealed class ClassificationInput
{
    public required ProcessDetails Process { get; init; }
    public IReadOnlyCollection<string> Hostnames { get; init; } = [];
    public bool HasVisibleWindow { get; init; }
    public DateTime? LastForeground { get; init; }
    public DateTime Now { get; init; } = DateTime.Now;
    /// <summary>When observation began: an app not yet seen in the foreground is judged from this point.</summary>
    public DateTime MonitoringStarted { get; init; } = DateTime.Now;
    public bool MonitorBackground { get; init; } = true;
}

/// <summary>
/// Heuristic, informational labelling. Every label comes with the evidence that produced it,
/// and nothing here claims to know what an encrypted connection carries: a pattern match on a
/// hostname or process name is reported as "Possible Telemetry", never as telemetry.
/// </summary>
public sealed class TelemetryClassifier
{
    public const string Disclaimer = "Classification is heuristic and does not prove that traffic is telemetry.";

    /// <summary>How long without foreground focus before an app with a window counts as "in the background".</summary>
    public static readonly TimeSpan IdleThreshold = TimeSpan.FromMinutes(2);

    private WildcardSet _telemetryHosts, _telemetryProcs, _telemetryServices, _updateProcs, _updateServices, _updateHosts;

    public TelemetryClassifier(ClassificationRules rules)
    {
        _telemetryHosts = _telemetryProcs = _telemetryServices = _updateProcs = _updateServices = _updateHosts = null!;
        Apply(rules);
    }

    public void Apply(ClassificationRules rules)
    {
        _telemetryHosts = new WildcardSet(rules.TelemetryHostPatterns);
        _telemetryProcs = new WildcardSet(rules.TelemetryProcesses);
        _telemetryServices = new WildcardSet(rules.TelemetryServices);
        _updateProcs = new WildcardSet(rules.UpdateProcesses);
        _updateServices = new WildcardSet(rules.UpdateServices);
        _updateHosts = new WildcardSet(rules.UpdateHostPatterns);
    }

    public Classification Classify(ClassificationInput input)
    {
        var p = input.Process;
        var reasons = new List<string>();

        if (p.IsSystem || p.IsSystemIdle)
        {
            return new Classification(ActivityClass.Normal, [p.IsSystem
                ? "Windows kernel networking (file sharing, network discovery and similar system traffic)."
                : "Connections left over by processes that have already exited (normally TIME_WAIT)."]);
        }

        if (!p.PathKnown)
        {
            return new Classification(ActivityClass.Unknown,
                ["The executable path could not be read (the process may be protected or has exited). Insufficient information to classify."]);
        }

        // Possible telemetry: process name, hosted service, or destination hostname matches a rule.
        if (_telemetryProcs.Match(p.Name) is { } tp) reasons.Add($"Process name matches telemetry rule \"{tp}\".");
        foreach (var s in p.Services)
            if (_telemetryServices.Match(s) is { } ts) reasons.Add($"Hosts the \"{s}\" service (rule \"{ts}\").");
        foreach (var h in input.Hostnames.Take(200))
        {
            if (_telemetryHosts.Match(h) is { } th)
            {
                reasons.Add($"Contacted {h} (matches telemetry rule \"{th}\").");
                if (reasons.Count >= 6) break;
            }
        }
        if (reasons.Count > 0) return new Classification(ActivityClass.PossibleTelemetry, reasons);

        // Update service.
        if (_updateProcs.Match(p.Name) is { } up) reasons.Add($"Process name matches updater rule \"{up}\".");
        foreach (var s in p.Services)
            if (_updateServices.Match(s) is { } us) reasons.Add($"Hosts the \"{s}\" update service (rule \"{us}\").");
        if (reasons.Count == 0)
        {
            var updateHosts = input.Hostnames.Where(h => _updateHosts.Match(h) is not null).Take(3).ToList();
            // Only when *all* resolved destinations look like update endpoints — a browser visiting
            // one update site is not an updater.
            if (updateHosts.Count > 0 && input.Hostnames.All(h => _updateHosts.Match(h) is not null))
                reasons.AddRange(updateHosts.Select(h => $"Only contacts update endpoints such as {h}."));
        }
        if (reasons.Count > 0) return new Classification(ActivityClass.UpdateService, reasons);

        // Background: talking to the network while the user is not interacting with it.
        if (input.MonitorBackground)
        {
            if (!input.HasVisibleWindow && (input.LastForeground is null || input.Now - input.LastForeground > IdleThreshold))
            {
                reasons.Add(p.Services.Count > 0
                    ? $"Windows service host ({string.Join(", ", p.Services.Take(4))}) with no visible window."
                    : "Has no visible window and has not been in the foreground recently.");
                return new Classification(ActivityClass.Background, reasons);
            }
            // Never-focused-yet counts from monitoring start, so an app is not called
            // "background" just because the inspector was launched a moment ago.
            var lastFocus = input.LastForeground ?? input.MonitoringStarted;
            if (input.HasVisibleWindow && input.Now - lastFocus > IdleThreshold)
            {
                reasons.Add($"Not in the foreground for {(int)(input.Now - lastFocus).TotalMinutes} min while communicating.");
                return new Classification(ActivityClass.Background, reasons);
            }
        }

        reasons.Add(input.HasVisibleWindow ? "Application in active use." : "Known application traffic.");
        if (p.Signature == SignatureStatus.Valid && p.Signer is not null) reasons.Add($"Signed by {p.Signer}.");
        return new Classification(ActivityClass.Normal, reasons);
    }
}
