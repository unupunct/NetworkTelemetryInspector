using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Firewall;

public enum FirewallOp { Block, Unblock, Delete, Enable, Disable, RemoveAll }

public sealed class FirewallRequest
{
    public FirewallOp Op { get; set; }
    public string? Path { get; set; }
    public string? Name { get; set; }
    public string? Prefix { get; set; }
}

/// <summary>
/// Runs one firewall operation in an elevated copy of this exe.
///
/// The standard-user UI writes a small request file into its own %LOCALAPPDATA% folder and
/// relaunches itself with "runas" and a single argument: <c>--firewall-op &lt;guid&gt;</c>. No path or
/// rule name is ever placed on a command line or passed to a shell. The elevated child reads the
/// request, re-validates everything (op is an enum, the path goes through PathValidator, ownership is
/// checked again by FirewallOperations), performs exactly one operation, writes the result and exits.
/// </summary>
public static partial class ElevatedFirewallHelper
{
    public const string Argument = "--firewall-op";

    [GeneratedRegex("^[0-9a-f]{32}$")]
    private static partial Regex IdPattern();

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    /// <summary>Called from the UI side. Shows a UAC prompt; returns the child's result.</summary>
    public static async Task<FirewallResult> RunAsync(FirewallRequest request, CancellationToken ct = default)
    {
        AppPaths.EnsureCreated();
        var id = Guid.NewGuid().ToString("N");
        var reqFile = System.IO.Path.Combine(AppPaths.Ipc, id + ".req.json");
        var resFile = System.IO.Path.Combine(AppPaths.Ipc, id + ".res.json");
        await File.WriteAllTextAsync(reqFile, JsonSerializer.Serialize(request, Json), ct).ConfigureAwait(false);
        try
        {
            var psi = new ProcessStartInfo(AppPaths.ExecutablePath)
            {
                UseShellExecute = true,
                Verb = "runas",
                // id is our own 32-hex GUID: nothing to escape. A non-default data root (headless tests)
                // is passed along so both sides agree where the request lives; it never contains quotes.
                Arguments = Argument + " " + id + (AppPaths.IsOverridden && !AppPaths.Root.Contains('"') ? " --data \"" + AppPaths.Root + "\"" : ""),
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process? child;
            try { child = Process.Start(psi); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return FirewallResult.Fail("Administrator permission was not granted, so the firewall was not changed.");
            }
            if (child is null) return FirewallResult.Fail("The elevated firewall helper could not be started.");

            using (child)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(60));
                try { await child.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return FirewallResult.Fail("The firewall helper did not finish in time."); }
            }

            if (!File.Exists(resFile)) return FirewallResult.Fail("The firewall helper finished without reporting a result.");
            var result = JsonSerializer.Deserialize<FirewallResult>(await File.ReadAllTextAsync(resFile, ct).ConfigureAwait(false), Json);
            return result ?? FirewallResult.Fail("The firewall helper returned an unreadable result.");
        }
        finally
        {
            TryDelete(reqFile);
            TryDelete(resFile);
        }
    }

    /// <summary>Entry point of the elevated child. Returns the process exit code.</summary>
    public static int Execute(string id)
    {
        if (!IdPattern().IsMatch(id)) return 2;
        var reqFile = System.IO.Path.Combine(AppPaths.Ipc, id + ".req.json");
        var resFile = System.IO.Path.Combine(AppPaths.Ipc, id + ".res.json");
        FirewallResult result;
        try
        {
            if (!Elevation.IsElevated) result = FirewallResult.Fail("The firewall helper is not running with administrator rights.");
            else if (!File.Exists(reqFile)) result = FirewallResult.Fail("The firewall request was not found.");
            else
            {
                var info = new FileInfo(reqFile);
                // Reject stale or oversized request files.
                if (info.Length > 8192 || DateTime.UtcNow - info.LastWriteTimeUtc > TimeSpan.FromMinutes(2))
                    result = FirewallResult.Fail("The firewall request was rejected (stale or invalid).");
                else
                {
                    var req = JsonSerializer.Deserialize<FirewallRequest>(File.ReadAllText(reqFile), Json);
                    TryDelete(reqFile);
                    result = req is null ? FirewallResult.Fail("The firewall request could not be read.") : Perform(req);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error("FirewallHelper", "Elevated operation failed", ex);
            result = FirewallResult.Fail(FriendlyError.Describe(ex));
        }

        try { File.WriteAllText(resFile, JsonSerializer.Serialize(result, Json)); } catch { return 3; }
        Log.Info("FirewallHelper", (result.Ok ? "OK: " : "FAILED: ") + result.Message);
        Log.Flush();
        return result.Ok ? 0 : 1;
    }

    /// <summary>The fixed operation table. Used by both the elevated child and an already-elevated UI.</summary>
    public static FirewallResult Perform(FirewallRequest req)
    {
        if (!Enum.IsDefined(req.Op)) return FirewallResult.Fail("Unknown firewall operation.");
        return req.Op switch
        {
            FirewallOp.Block => FirewallOperations.Block(req.Path ?? "", RuleNaming.IsValidPrefix(req.Prefix) ? req.Prefix! : RuleNaming.DefaultPrefix),
            FirewallOp.Unblock => FirewallOperations.Unblock(req.Path ?? ""),
            FirewallOp.Delete => FirewallOperations.Delete(req.Name ?? ""),
            FirewallOp.Enable => FirewallOperations.SetEnabled(req.Name ?? "", true),
            FirewallOp.Disable => FirewallOperations.SetEnabled(req.Name ?? "", false),
            FirewallOp.RemoveAll => FirewallOperations.RemoveAll(),
            _ => FirewallResult.Fail("Unknown firewall operation.")
        };
    }

    private static void TryDelete(string f)
    {
        try { if (File.Exists(f)) File.Delete(f); } catch { }
    }

    /// <summary>Removes request/response files left behind by a crash.</summary>
    public static void CleanStale()
    {
        try
        {
            if (!Directory.Exists(AppPaths.Ipc)) return;
            foreach (var f in Directory.EnumerateFiles(AppPaths.Ipc, "*.json"))
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(f) > TimeSpan.FromMinutes(10)) TryDelete(f);
        }
        catch { }
    }
}
