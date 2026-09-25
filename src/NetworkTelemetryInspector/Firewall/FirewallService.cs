using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Firewall;

/// <summary>
/// The UI's single entry point for firewall work. Enforces read-only mode, routes mutations
/// either in-process (already elevated) or through the one-shot elevated helper, keeps a cached
/// list of our rules and raises <see cref="RulesChanged"/> after every change.
/// </summary>
public sealed class FirewallService
{
    private readonly Func<AppSettings> _settings;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private List<FirewallRuleInfo> _rules = new();

    public FirewallService(Func<AppSettings> settings) => _settings = settings;

    public event Action? RulesChanged;

    public IReadOnlyList<FirewallRuleInfo> Rules => _rules;
    public string? LastReadError { get; private set; }
    public bool? FirewallEnabled { get; private set; }

    /// <summary>Paths currently blocked by an enabled rule of ours.</summary>
    public HashSet<string> BlockedPaths { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    public bool IsBlocked(string? path) => path is not null && BlockedPaths.Contains(path);

    public async Task RefreshAsync()
    {
        var (rules, error, enabled) = await Task.Run(() =>
        {
            var r = FirewallOperations.ReadOwnedRules(out var e);
            return (r, e, FirewallOperations.IsFirewallEnabled());
        }).ConfigureAwait(false);

        LastReadError = error;
        FirewallEnabled = enabled;
        if (rules is not null)
        {
            _rules = rules.OrderBy(r => r.ApplicationName, StringComparer.OrdinalIgnoreCase).ToList();
            BlockedPaths = new HashSet<string>(
                rules.Where(r => r.Enabled && r.Action == "Block" && r.Direction == "Outbound" && r.ApplicationPath is not null)
                     .Select(r => r.ApplicationPath!), StringComparer.OrdinalIgnoreCase);
        }
        RulesChanged?.Invoke();
    }

    public Task<FirewallResult> BlockAsync(string path) =>
        MutateAsync(new FirewallRequest { Op = FirewallOp.Block, Path = path, Prefix = _settings().RulePrefix });

    public Task<FirewallResult> UnblockAsync(string path) =>
        MutateAsync(new FirewallRequest { Op = FirewallOp.Unblock, Path = path });

    public Task<FirewallResult> DeleteAsync(string name) =>
        MutateAsync(new FirewallRequest { Op = FirewallOp.Delete, Name = name });

    public Task<FirewallResult> SetEnabledAsync(string name, bool enabled) =>
        MutateAsync(new FirewallRequest { Op = enabled ? FirewallOp.Enable : FirewallOp.Disable, Name = name });

    public Task<FirewallResult> RemoveAllAsync() =>
        MutateAsync(new FirewallRequest { Op = FirewallOp.RemoveAll });

    private async Task<FirewallResult> MutateAsync(FirewallRequest request)
    {
        if (_settings().ReadOnlyMode)
            return FirewallResult.Fail("Read-only mode is on. Turn it off in the header or Settings to change firewall rules.");

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            FirewallResult result;
            try
            {
                result = Elevation.IsElevated
                    ? await Task.Run(() => ElevatedFirewallHelper.Perform(request)).ConfigureAwait(false)
                    : await ElevatedFirewallHelper.RunAsync(request).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Error("Firewall", $"{request.Op} failed", ex);
                result = FirewallResult.Fail(FriendlyError.Describe(ex));
            }

            Log.Write(result.Ok ? LogLevel.Info : LogLevel.Warning, "Firewall",
                $"{request.Op} {(request.Path ?? request.Name ?? "")}: {result.Message}");
            await RefreshAsync().ConfigureAwait(false);
            return result;
        }
        finally { _gate.Release(); }
    }
}
