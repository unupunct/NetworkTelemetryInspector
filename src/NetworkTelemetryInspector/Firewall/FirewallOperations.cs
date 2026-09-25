using System.Runtime.InteropServices;
using NetworkTelemetryInspector.Models;

namespace NetworkTelemetryInspector.Firewall;

public sealed record FirewallResult(bool Ok, string Message, string? RuleName = null, int Count = 0)
{
    public static FirewallResult Fail(string message) => new(false, message);
}

/// <summary>
/// Direct Windows Defender Firewall access through its COM API (HNetCfg.FwPolicy2 / HNetCfg.FWRule).
/// Reading works for standard users; every mutation requires an elevated process and is
/// performed either here (when the app already runs elevated) or in the one-shot elevated helper.
///
/// Every mutation re-checks ownership (<see cref="RuleNaming.IsOwned"/>) immediately before it acts.
/// </summary>
public static class FirewallOperations
{
    private const int NET_FW_ACTION_BLOCK = 0;
    private const int NET_FW_RULE_DIR_OUT = 2;
    private const int NET_FW_PROFILE2_ALL = 0x7FFFFFFF;

    private static dynamic Policy()
    {
        var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return Activator.CreateInstance(t)!;
    }

    /// <summary>All rules owned by this application. Never throws; returns null when the firewall API is unavailable.</summary>
    public static List<FirewallRuleInfo>? ReadOwnedRules(out string? error)
    {
        error = null;
        var list = new List<FirewallRuleInfo>();
        try
        {
            var policy = Policy();
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    string? grouping = rule.Grouping;
                    if (!string.Equals(grouping, RuleNaming.Group, StringComparison.Ordinal)) continue;
                    string? description = rule.Description;
                    if (!RuleNaming.IsOwned(grouping, description)) continue;
                    list.Add(new FirewallRuleInfo
                    {
                        Name = rule.Name,
                        ApplicationPath = rule.ApplicationName,
                        Direction = (int)rule.Direction == NET_FW_RULE_DIR_OUT ? "Outbound" : "Inbound",
                        Action = (int)rule.Action == NET_FW_ACTION_BLOCK ? "Block" : "Allow",
                        Enabled = rule.Enabled,
                        Description = description
                    });
                }
                finally { ReleaseCom(rule); }
            }
            return list;
        }
        catch (Exception ex)
        {
            error = "Windows Firewall rules could not be read: " + ex.Message;
            return null;
        }
    }

    /// <summary>Whether Windows Firewall is enabled for the currently active profile(s).</summary>
    public static bool? IsFirewallEnabled()
    {
        try
        {
            var policy = Policy();
            int current = policy.CurrentProfileTypes;
            foreach (var profile in new[] { 1, 2, 4 })
                if ((current & profile) != 0 && !(bool)policy.FirewallEnabled[profile]) return false;
            return true;
        }
        catch { return null; }
    }

    public static FirewallResult Block(string exePath, string prefix)
    {
        if (!PathValidator.TryValidate(exePath, out var path, out var error)) return FirewallResult.Fail(error);
        var name = RuleNaming.BuildName(prefix, path);
        var policy = Policy();

        // Idempotent: if our rule already exists, just make sure it is enabled.
        var existing = FindByName((object)policy, name);
        if (existing.Count > 0)
        {
            if (existing.Any(r => !r.Owned))
                return FirewallResult.Fail($"A rule named {name} exists that was not created by this application. Nothing was changed.");
            foreach (var r in existing) { r.Rule.Enabled = true; ReleaseCom(r.Rule); }
            return new FirewallResult(true, $"Internet access for {Path.GetFileName(path)} is blocked (existing rule enabled).", name, 1);
        }

        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        dynamic rule = Activator.CreateInstance(ruleType)!;
        try
        {
            rule.Name = name;
            rule.Description = RuleNaming.BuildDescription(path);
            rule.ApplicationName = path;
            rule.Direction = NET_FW_RULE_DIR_OUT;
            rule.Action = NET_FW_ACTION_BLOCK;
            rule.Profiles = NET_FW_PROFILE2_ALL;
            rule.Grouping = RuleNaming.Group;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
        finally { ReleaseCom(rule); }

        // Verify it really landed rather than assuming success.
        var check = FindByName((object)policy, name);
        var ok = check.Any(r => r.Owned && (bool)r.Rule.Enabled);
        foreach (var r in check) ReleaseCom(r.Rule);
        return ok
            ? new FirewallResult(true, $"Internet access for {Path.GetFileName(path)} is now blocked.", name, 1)
            : FirewallResult.Fail("Windows Firewall did not report the new rule. The block may not be active.");
    }

    /// <summary>Removes every rule we own that targets this executable. Other rules are untouched.</summary>
    public static FirewallResult Unblock(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return FirewallResult.Fail("No executable path was given.");
        var policy = Policy();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (dynamic rule in policy.Rules)
        {
            try
            {
                if (!RuleNaming.IsOwned(rule.Grouping, rule.Description)) continue;
                string? app = rule.ApplicationName;
                if (app is not null && string.Equals(app, exePath, StringComparison.OrdinalIgnoreCase)) names.Add((string)rule.Name);
            }
            finally { ReleaseCom(rule); }
        }
        if (names.Count == 0) return new FirewallResult(true, $"{Path.GetFileName(exePath)} had no rules from this application.", null, 0);

        var removed = 0;
        foreach (var n in names)
        {
            var r = RemoveOwned((object)policy, n);
            if (!r.Ok) return r;
            removed += r.Count;
        }
        return new FirewallResult(true, $"Internet access for {Path.GetFileName(exePath)} is restored.", null, removed);
    }

    public static FirewallResult Delete(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 200) return FirewallResult.Fail("Invalid rule name.");
        return RemoveOwned((object)Policy(), name);
    }

    public static FirewallResult SetEnabled(string name, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 200) return FirewallResult.Fail("Invalid rule name.");
        var policy = Policy();
        var matches = FindByName((object)policy, name);
        try
        {
            if (matches.Count == 0) return FirewallResult.Fail($"Rule {name} was not found.");
            if (matches.Any(m => !m.Owned)) return FirewallResult.Fail($"Rule {name} was not created by this application and was not changed.");
            foreach (var m in matches) m.Rule.Enabled = enabled;
            return new FirewallResult(true, $"Rule {name} {(enabled ? "enabled" : "disabled")}.", name, matches.Count);
        }
        finally { foreach (var m in matches) ReleaseCom(m.Rule); }
    }

    public static FirewallResult RemoveAll()
    {
        var policy = Policy();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (dynamic rule in policy.Rules)
        {
            try { if (RuleNaming.IsOwned(rule.Grouping, rule.Description)) names.Add((string)rule.Name); }
            finally { ReleaseCom(rule); }
        }
        var removed = 0;
        foreach (var n in names)
        {
            var r = RemoveOwned((object)policy, n);
            if (!r.Ok) return r with { Count = removed };
            removed += r.Count;
        }
        return new FirewallResult(true, removed == 0 ? "There were no rules to remove." : $"Removed {removed} rule(s) created by this application.", null, removed);
    }

    /// <summary>
    /// INetFwRules.Remove deletes every rule with the given name, so we refuse unless every
    /// rule carrying that name is ours.
    /// </summary>
    private static FirewallResult RemoveOwned(object policyObject, string name)
    {
        dynamic policy = policyObject;
        var matches = FindByName((object)policy, name);
        try
        {
            if (matches.Count == 0) return new FirewallResult(true, $"Rule {name} was already gone.", name, 0);
            if (matches.Any(m => !m.Owned))
                return FirewallResult.Fail($"Rule name {name} is shared with a rule not created by this application. Nothing was removed.");
        }
        finally { foreach (var m in matches) ReleaseCom(m.Rule); }

        policy.Rules.Remove(name);
        var after = FindByName((object)policy, name);
        foreach (var m in after) ReleaseCom(m.Rule);
        return after.Count == 0
            ? new FirewallResult(true, $"Rule {name} removed.", name, matches.Count)
            : FirewallResult.Fail($"Windows Firewall still reports rule {name} after removal.");
    }

    private static List<(dynamic Rule, bool Owned)> FindByName(object policyObject, string name)
    {
        dynamic policy = policyObject;
        var list = new List<(dynamic, bool)>();
        foreach (dynamic rule in policy.Rules)
        {
            string? n = rule.Name;
            if (string.Equals(n, name, StringComparison.Ordinal))
                list.Add((rule, RuleNaming.IsOwned(rule.Grouping, rule.Description)));
            else
                ReleaseCom(rule);
        }
        return list;
    }

    private static void ReleaseCom(object? o)
    {
        try { if (o is not null && Marshal.IsComObject(o)) Marshal.ReleaseComObject(o); } catch { }
    }
}
