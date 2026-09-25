using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkTelemetryInspector.Firewall;

/// <summary>
/// Naming and ownership rules for firewall entries this application creates.
///
/// A rule counts as ours only when BOTH hold:
///   * its Grouping is exactly <see cref="Group"/>, and
///   * its Description starts with <see cref="Marker"/>.
/// The name prefix (default NTI_BLOCK) is for humans and uniqueness; it is never enough on its
/// own to delete something. Rules that fail the ownership test are never modified or removed.
/// </summary>
public static partial class RuleNaming
{
    public const string Group = "Network & Telemetry Inspector";
    public const string Marker = "[NTI-managed]";
    public const string DefaultPrefix = "NTI_BLOCK";

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_]{1,23}$")]
    private static partial Regex PrefixPattern();

    [GeneratedRegex("[^A-Za-z0-9._-]")]
    private static partial Regex UnsafeChars();

    public static bool IsValidPrefix(string? prefix) => prefix is not null && PrefixPattern().IsMatch(prefix);

    /// <summary>Stable 8-hex hash of the lower-cased full path: one rule name per executable.</summary>
    public static string PathHash(string path)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(path.Trim().ToLowerInvariant()));
        return Convert.ToHexString(bytes, 0, 4);
    }

    public static string BuildName(string prefix, string exePath)
    {
        if (!IsValidPrefix(prefix)) prefix = DefaultPrefix;
        var app = Path.GetFileNameWithoutExtension(exePath);
        app = UnsafeChars().Replace(app, "_");
        if (app.Length > 40) app = app[..40];
        if (app.Length == 0) app = "App";
        return $"{prefix}_{app}_{PathHash(exePath)}";
    }

    public static string BuildDescription(string exePath) =>
        $"{Marker} Outbound block created by Network & Telemetry Inspector for {exePath}. Remove it from the app's Firewall page.";

    public static bool IsOwned(string? grouping, string? description) =>
        string.Equals(grouping, Group, StringComparison.Ordinal) &&
        description is not null && description.StartsWith(Marker, StringComparison.Ordinal);
}

/// <summary>Validation applied to every executable path before a rule is created for it.</summary>
public static class PathValidator
{
    /// <summary>
    /// Processes whose blocking would cut networking for the whole PC (or that are not
    /// meaningful to block). Refused outright with an explanation.
    /// </summary>
    private static readonly Dictionary<string, string> Refused = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = "svchost.exe hosts many Windows services at once (DNS client, DHCP, time sync, Windows Update). Blocking it would break networking for the whole PC.",
        ["lsass.exe"] = "lsass.exe handles Windows sign-in and domain authentication. Blocking it can lock you out of network resources.",
        ["services.exe"] = "services.exe is the Windows service controller and must not be blocked.",
        ["wininit.exe"] = "wininit.exe is a core Windows process and must not be blocked.",
        ["csrss.exe"] = "csrss.exe is a core Windows process and must not be blocked.",
        ["smss.exe"] = "smss.exe is a core Windows process and must not be blocked.",
        ["winlogon.exe"] = "winlogon.exe is a core Windows process and must not be blocked.",
    };

    public static bool TryValidate(string? path, out string normalized, out string error)
    {
        normalized = "";
        error = "";
        if (string.IsNullOrWhiteSpace(path)) { error = "The executable path is not known, so no rule can target it."; return false; }
        if (path.Length > 1024) { error = "The executable path is too long."; return false; }
        if (path.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || path.Contains('"') || path.Contains('\0'))
        {
            error = "The executable path contains characters that are not allowed.";
            return false;
        }
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) { error = "Network (UNC) paths are not supported."; return false; }
        string full;
        try { full = Path.GetFullPath(path); }
        catch { error = "The executable path is not valid."; return false; }
        if (!Path.IsPathFullyQualified(full) || !string.Equals(full, path, StringComparison.OrdinalIgnoreCase))
        {
            error = "Only fully qualified local paths are accepted.";
            return false;
        }
        if (!full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { error = "Only .exe files can be blocked."; return false; }
        if (Refused.TryGetValue(Path.GetFileName(full), out var why)) { error = why; return false; }
        if (!File.Exists(full)) { error = "The executable no longer exists at this path."; return false; }
        normalized = full;
        return true;
    }

    /// <summary>Whether blocking is refused for this file name (used to disable the button up front).</summary>
    public static string? RefusalReason(string? path) =>
        path is not null && Refused.TryGetValue(Path.GetFileName(path), out var why) ? why : null;
}
