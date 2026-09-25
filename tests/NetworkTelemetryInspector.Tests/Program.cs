using System.Diagnostics;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Network;
using NetworkTelemetryInspector.Processes;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;
using NetworkTelemetryInspector.ViewModels;

namespace NetworkTelemetryInspector.Tests;

internal static class Program
{
    private static int _passed, _failed;
    private static readonly string Temp = Path.Combine(Path.GetTempPath(), "nti-tests-" + Guid.NewGuid().ToString("N")[..8]);

    private static void Test(string name, Action body)
    {
        try
        {
            body();
            _passed++;
            Console.WriteLine("  PASS  " + name);
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine("  FAIL  " + name + " — " + ex.Message);
        }
    }

    private static void Assert(bool condition, string message = "assertion failed")
    {
        if (!condition) throw new Exception(message);
    }

    private static void Equal<T>(T expected, T actual, string? what = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"{what ?? "value"}: expected <{expected}>, got <{actual}>");
    }

    [STAThread]
    private static int Main()
    {
        Directory.CreateDirectory(Temp);
        AppPaths.OverrideRoot(Temp);
        AppPaths.EnsureCreated();
        Console.WriteLine("Network & Telemetry Inspector tests");

        RuleNamingTests();
        PathValidatorTests();
        FirewallGateTests();
        ClassifierTests();
        HistoryTests();
        FormatTests();
        NativeTests();
        SettingsTests();

        try { Directory.Delete(Temp, true); } catch { }
        Console.WriteLine($"{_passed} passed, {_failed} failed");
        return _failed == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------ firewall naming & safety

    private static void RuleNamingTests()
    {
        Test("Prefix validation", () =>
        {
            Assert(RuleNaming.IsValidPrefix("NTI_BLOCK"));
            Assert(RuleNaming.IsValidPrefix("Ab"));
            Assert(!RuleNaming.IsValidPrefix("A"), "too short");
            Assert(!RuleNaming.IsValidPrefix("1ABC"), "must start with a letter");
            Assert(!RuleNaming.IsValidPrefix("NTI BLOCK"), "no spaces");
            Assert(!RuleNaming.IsValidPrefix("NTI\"; rm"), "no quotes");
            Assert(!RuleNaming.IsValidPrefix(new string('A', 25)), "max 24");
            Assert(!RuleNaming.IsValidPrefix(null));
        });
        Test("Rule name format NTI_BLOCK_<App>_<Hash>", () =>
        {
            var name = RuleNaming.BuildName("NTI_BLOCK", @"C:\Program Files\Google\Chrome\Application\chrome.exe");
            Assert(System.Text.RegularExpressions.Regex.IsMatch(name, "^NTI_BLOCK_chrome_[0-9A-F]{8}$"), name);
        });
        Test("Path hash is stable and case-insensitive", () =>
        {
            Equal(RuleNaming.PathHash(@"C:\A\b.exe"), RuleNaming.PathHash(@"c:\a\B.EXE"));
            Assert(RuleNaming.PathHash(@"C:\A\b.exe") != RuleNaming.PathHash(@"C:\A\c.exe"), "different paths differ");
        });
        Test("Unsafe characters in app names are sanitised", () =>
        {
            var name = RuleNaming.BuildName("NTI_BLOCK", @"C:\x\my app (v2)&x.exe");
            Assert(!name.Contains(' ') && !name.Contains('(') && !name.Contains('&'), name);
        });
        Test("Invalid prefix falls back to default", () =>
            Assert(RuleNaming.BuildName("bad prefix", @"C:\x\a.exe").StartsWith("NTI_BLOCK_")));
        Test("Ownership requires group AND marker", () =>
        {
            Assert(RuleNaming.IsOwned(RuleNaming.Group, RuleNaming.BuildDescription(@"C:\a.exe")));
            Assert(!RuleNaming.IsOwned(RuleNaming.Group, "user rule"), "group only");
            Assert(!RuleNaming.IsOwned("Other", RuleNaming.Marker + " x"), "marker only");
            Assert(!RuleNaming.IsOwned(null, null));
            Assert(!RuleNaming.IsOwned(RuleNaming.Group.ToLowerInvariant(), RuleNaming.Marker), "group match is exact");
        });
    }

    private static void PathValidatorTests()
    {
        var self = Environment.ProcessPath!;
        Test("Existing absolute .exe accepted", () => Assert(PathValidator.TryValidate(self, out var n, out var e) && n == self, e));
        Test("Relative path rejected", () => Assert(!PathValidator.TryValidate("chrome.exe", out _, out _)));
        Test("UNC path rejected", () => Assert(!PathValidator.TryValidate(@"\\server\share\a.exe", out _, out _)));
        Test("Quote / injection characters rejected", () =>
        {
            Assert(!PathValidator.TryValidate("C:\\a.exe\" & calc", out _, out _));
            Assert(!PathValidator.TryValidate("C:\\a\0.exe", out _, out _));
        });
        Test("Non-exe rejected", () => Assert(!PathValidator.TryValidate(@"C:\Windows\win.ini", out _, out _)));
        Test("Missing file rejected", () => Assert(!PathValidator.TryValidate(@"C:\does\not\exist.exe", out _, out var e) && e.Contains("no longer exists"), e));
        Test("Dot-segments rejected (path must already be canonical)", () =>
            Assert(!PathValidator.TryValidate(@"C:\Windows\System32\..\System32\notepad.exe", out _, out _)));
        Test("svchost.exe refused with an explanation", () =>
        {
            Assert(!PathValidator.TryValidate(@"C:\Windows\System32\svchost.exe", out _, out var e));
            Assert(e.Contains("whole PC"), e);
            Assert(PathValidator.RefusalReason(@"C:\Windows\System32\svchost.exe") is not null);
            Assert(PathValidator.RefusalReason(self) is null);
        });
    }

    private static void FirewallGateTests()
    {
        Test("Unknown operation rejected before touching the firewall", () =>
            Assert(!ElevatedFirewallHelper.Perform(new FirewallRequest { Op = (FirewallOp)99 }).Ok));
        Test("Block with invalid path fails validation before any COM call", () =>
        {
            var r = ElevatedFirewallHelper.Perform(new FirewallRequest { Op = FirewallOp.Block, Path = "relative.exe" });
            Assert(!r.Ok && r.Message.Contains("fully qualified"), r.Message);
        });
        Test("Elevated helper rejects a malformed request id", () =>
        {
            Equal(2, ElevatedFirewallHelper.Execute("../../etc"));
            Equal(2, ElevatedFirewallHelper.Execute("ABCDEF"));
        });
        Test("Read-only mode blocks mutations in the service", () =>
        {
            var s = new AppSettings { ReadOnlyMode = true };
            var fw = new FirewallService(() => s);
            var r = fw.BlockAsync(Environment.ProcessPath!).GetAwaiter().GetResult();
            Assert(!r.Ok && r.Message.Contains("Read-only"), r.Message);
            r = fw.RemoveAllAsync().GetAwaiter().GetResult();
            Assert(!r.Ok, "remove all refused");
        });
        Test("Owned rules readable without elevation", () =>
            Assert(FirewallOperations.ReadOwnedRules(out var err) is not null, err ?? ""));
    }

    // ------------------------------------------------------------------ classification

    private static ProcessDetails P(string name, string? path = null, params string[] services) => new()
    {
        Pid = 1234, Name = name, Path = path ?? @"C:\Apps\" + name, Services = services, Signature = SignatureStatus.Valid, Signer = "Test"
    };

    private static void ClassifierTests()
    {
        var c = new TelemetryClassifier(new ClassificationRules());
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        ClassificationInput I(ProcessDetails p, string[]? hosts = null, bool window = true, DateTime? fg = null, DateTime? started = null, bool bg = true) => new()
        {
            Process = p, Hostnames = hosts ?? [], HasVisibleWindow = window, LastForeground = fg, Now = now,
            MonitoringStarted = started ?? now.AddMinutes(-30), MonitorBackground = bg
        };

        Test("Telemetry hostname → Possible Telemetry with evidence", () =>
        {
            var r = c.Classify(I(P("app.exe"), ["v10.events.data.microsoft.com"], fg: now));
            Equal(ActivityClass.PossibleTelemetry, r.Class);
            Assert(r.Reasons.Any(x => x.Contains("v10.events.data.microsoft.com")), "reason names the host");
        });
        Test("DiagTrack service → Possible Telemetry", () =>
            Equal(ActivityClass.PossibleTelemetry, c.Classify(I(P("svchost.exe", @"C:\Windows\System32\svchost.exe", "DiagTrack"), window: false)).Class));
        Test("Updater process → Update Service", () =>
            Equal(ActivityClass.UpdateService, c.Classify(I(P("GoogleUpdate.exe"), window: false)).Class));
        Test("wuauserv host → Update Service", () =>
            Equal(ActivityClass.UpdateService, c.Classify(I(P("svchost.exe", null, "wuauserv"), window: false)).Class));
        Test("Browser visiting one update host is not an updater", () =>
            Equal(ActivityClass.Normal, c.Classify(I(P("chrome.exe"), ["dl.google.com", "www.example.com"], fg: now)).Class));
        Test("No window → Background", () =>
            Equal(ActivityClass.Background, c.Classify(I(P("agent.exe"), window: false)).Class));
        Test("Window, recently focused → Normal", () =>
            Equal(ActivityClass.Normal, c.Classify(I(P("editor.exe"), fg: now.AddSeconds(-20))).Class));
        Test("Window, unfocused for 5 min → Background", () =>
            Equal(ActivityClass.Background, c.Classify(I(P("editor.exe"), fg: now.AddMinutes(-5))).Class));
        Test("Window never focused but monitoring just started → Normal", () =>
            Equal(ActivityClass.Normal, c.Classify(I(P("editor.exe"), started: now.AddSeconds(-30))).Class));
        Test("Background monitoring off → Normal", () =>
            Equal(ActivityClass.Normal, c.Classify(I(P("agent.exe"), window: false, bg: false)).Class));
        Test("Path unknown → Unknown", () =>
            Equal(ActivityClass.Unknown, c.Classify(I(new ProcessDetails { Pid = 99, Name = "x.exe" })).Class));
        Test("System kernel → Normal", () =>
            Equal(ActivityClass.Normal, c.Classify(I(new ProcessDetails { Pid = 4, Name = "System" })).Class));
        Test("Wildcard matching is case-insensitive and anchored", () =>
        {
            var w = new WildcardSet(["*.example.com", "exact.host"]);
            Assert(w.Match("A.EXAMPLE.COM") is not null);
            Assert(w.Match("example.com.evil") is null);
            Assert(w.Match("exact.host") is not null && w.Match("xexact.host") is null);
        });
        Test("Disclaimer text present", () => Assert(TelemetryClassifier.Disclaimer.Contains("does not prove")));
    }

    // ------------------------------------------------------------------ history

    private static void HistoryTests()
    {
        HistoryEntry E(DateTime t, string app, string ip, string status = "Allowed", string proto = "TCP", string? host = null) =>
            new() { Time = t, Application = app, RemoteAddress = ip, Status = status, Protocol = proto, Hostname = host, Port = 443, Action = "Opened" };

        Test("Filter by app / ip / hostname / status / protocol / date", () =>
        {
            var e = E(new DateTime(2026, 9, 1, 10, 0, 0), "chrome.exe", "142.250.1.1", host: "www.google.com");
            Assert(new HistoryFilter { Application = "CHROME" }.Matches(e));
            Assert(!new HistoryFilter { Application = "edge" }.Matches(e));
            Assert(new HistoryFilter { Ip = "142.250" }.Matches(e));
            Assert(new HistoryFilter { Hostname = "google" }.Matches(e));
            Assert(!new HistoryFilter { Hostname = "bing" }.Matches(e));
            Assert(!new HistoryFilter { Status = "Blocked" }.Matches(e));
            Assert(new HistoryFilter { Protocol = "TCP" }.Matches(E(e.Time, "a", "1", proto: "TCPv6")), "TCP matches TCPv6");
            Assert(!new HistoryFilter { Protocol = "UDP" }.Matches(e));
            Assert(new HistoryFilter { From = new DateTime(2026, 9, 1), To = new DateTime(2026, 9, 2) }.Matches(e));
            Assert(!new HistoryFilter { From = new DateTime(2026, 9, 2) }.Matches(e));
        });

        Test("History persists to local JSONL and reloads", () =>
        {
            using (var store = new HistoryStore())
            {
                store.Clear();
                store.Add(E(DateTime.Now.AddMinutes(-2), "a.exe", "1.1.1.1"));
                store.Add(E(DateTime.Now.AddMinutes(-1), "b.exe", "8.8.8.8", "Blocked"));
                store.Flush();
            }
            Assert(Directory.EnumerateFiles(AppPaths.History, "*.jsonl").Any(), "day file written");
            using var reloaded = new HistoryStore();
            reloaded.Load(14);
            Equal(2, reloaded.Count, "reloaded count");
            var newest = reloaded.Query(new HistoryFilter(), 10);
            Equal("b.exe", newest[0].Application, "newest first");
            Equal(1, reloaded.Query(new HistoryFilter { Status = "Blocked" }).Count, "blocked filter");
        });

        Test("Corrupt history line does not lose the rest", () =>
        {
            var f = Path.Combine(AppPaths.History, DateTime.Today.ToString("yyyy-MM-dd") + ".jsonl");
            File.AppendAllText(f, "{not json\n");
            using var s = new HistoryStore();
            s.Load(14);
            Equal(2, s.Count);
        });

        Test("Retention deletes old day files", () =>
        {
            var old = Path.Combine(AppPaths.History, DateTime.Today.AddDays(-40).ToString("yyyy-MM-dd") + ".jsonl");
            File.WriteAllText(old, "");
            using var s = new HistoryStore();
            s.Prune(14);
            Assert(!File.Exists(old), "old file removed");
        });

        Test("Clear History removes memory and files", () =>
        {
            using var s = new HistoryStore();
            s.Load(14);
            s.Clear();
            Equal(0, s.Count);
            Assert(!Directory.EnumerateFiles(AppPaths.History, "*.jsonl").Any(), "files deleted");
        });

        Test("Recording disabled writes nothing", () =>
        {
            using var s = new HistoryStore { Enabled = false };
            s.Add(E(DateTime.Now, "x.exe", "1.2.3.4"));
            Equal(0, s.Count);
        });

        Test("CSV export escapes and neutralises formulas", () =>
        {
            Equal("plain", HistoryViewModel.Csv("plain"));
            Equal("\"a,b\"", HistoryViewModel.Csv("a,b"));
            Equal("\"say \"\"hi\"\"\"", HistoryViewModel.Csv("say \"hi\""));
            Equal("'=cmd|' /C calc'!A0", HistoryViewModel.Csv("=cmd|' /C calc'!A0"));
            Equal("", HistoryViewModel.Csv(null));
        });
    }

    // ------------------------------------------------------------------ formatting & addresses

    private static void FormatTests()
    {
        Test("Rates and byte sizes", () =>
        {
            Equal("0 B/s", Format.Rate(0));
            Equal("1.00 KB/s", Format.Rate(1024));
            Equal("2.50 MB/s", Format.Rate(2.5 * 1024 * 1024));
            Equal("—", Format.Rate(-1));
        });
        Test("IPv6 endpoints are bracketed", () =>
        {
            Equal("[::1]:443", Format.Endpoint("::1", 443));
            Equal("1.2.3.4:80", Format.Endpoint("1.2.3.4", 80));
        });
        Test("Private / loopback / unspecified detection", () =>
        {
            Assert(NetworkAddress.IsPrivate("192.168.1.10") && NetworkAddress.IsPrivate("10.0.0.1") && NetworkAddress.IsPrivate("172.20.1.1"));
            Assert(!NetworkAddress.IsPrivate("8.8.8.8") && !NetworkAddress.IsPrivate("172.32.0.1"));
            Assert(NetworkAddress.IsPrivate("fe80::1") && NetworkAddress.IsPrivate("fd00::1"));
            Assert(NetworkAddress.IsLoopback("127.0.0.1") && NetworkAddress.IsLoopback("::1"));
            Assert(NetworkAddress.IsUnspecified("0.0.0.0") && NetworkAddress.IsUnspecified("::"));
        });
        Test("Network-order port conversion", () =>
        {
            Equal(443, ConnectionTable.Port(0xBB01));
            Equal(80, ConnectionTable.Port(0x5000));
        });
    }

    // ------------------------------------------------------------------ native APIs on this machine

    private static void NativeTests()
    {
        Test("Connection table reads without elevation", () =>
        {
            using var t = new ConnectionTable();
            var rows = t.Read(includeUdp: true);
            Assert(rows.Count > 0, "no rows");
            Assert(rows.Any(r => r.Protocol is Protocol.Udp or Protocol.Udp6), "UDP rows present");
            Assert(rows.Where(r => r.Protocol == Protocol.Tcp).All(r => r.RawRow is { Length: 20 }), "IPv4 ESTATS rows are 20 bytes");
            Assert(rows.Where(r => r.Protocol == Protocol.Tcp6).All(r => r.RawRow is { Length: 52 }), "IPv6 ESTATS rows are 52 bytes");
        });
        Test("A listening socket we open is found with our PID", () =>
        {
            var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            l.Start();
            try
            {
                var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
                using var t = new ConnectionTable();
                var me = Environment.ProcessId;
                Assert(t.Read(false).Any(r => r.Pid == me && r.Key.LocalPort == port && r.State == TcpState.Listen), "own listener not found");
            }
            finally { l.Stop(); }
        });
        Test("Kernel process table: own PID, name and start time", () =>
        {
            var table = SystemProcessTable.Snapshot();
            Assert(table.TryGetValue(Environment.ProcessId, out var e), "own pid missing");
            Assert(e.Name.StartsWith("NetworkTelemetryInspector.Tests", StringComparison.OrdinalIgnoreCase), e.Name);
            var real = Process.GetCurrentProcess().StartTime;
            Assert(e.StartTime is { } st && Math.Abs((st - real).TotalSeconds) < 2, "start time");
        });
        Test("Kernel image path equals the real path", () =>
            Equal(Environment.ProcessPath!.ToLowerInvariant(), SystemProcessTable.ImagePath(Environment.ProcessId)?.ToLowerInvariant()));
        Test("SYSTEM service path resolves for a standard user", () =>
        {
            var svchost = Process.GetProcessesByName("svchost").FirstOrDefault();
            Assert(svchost is not null, "no svchost");
            Equal(@"c:\windows\system32\svchost.exe", SystemProcessTable.ImagePath(svchost!.Id)?.ToLowerInvariant());
        });
        Test("Catalog-signed Windows binary verifies offline", () =>
        {
            var r = SignatureVerifier.Verify(@"C:\Windows\System32\svchost.exe");
            Equal(SignatureStatus.Valid, r.Status, "status");
            Assert(r.Signer?.Contains("Microsoft") == true, r.Signer ?? "no signer");
        });
        Test("Unsigned file reported as unsigned, not invalid", () =>
        {
            var copy = Path.Combine(Temp, "unsigned.exe");
            File.WriteAllBytes(copy, File.ReadAllBytes(typeof(Program).Assembly.Location));
            Equal(SignatureStatus.Unsigned, SignatureVerifier.Verify(copy).Status);
        });
        Test("Process inspector resolves own process", () =>
        {
            var pi = new ProcessInspector();
            var d = pi.Get(Environment.ProcessId);
            Equal(Environment.ProcessPath!.ToLowerInvariant(), d.Path?.ToLowerInvariant());
            Assert(d.StartTime is not null);
            Equal(d.Path!.ToLowerInvariant(), d.GroupKey);
            pi.WaitForSignatures(10000);
            Assert(pi.Get(Environment.ProcessId).Signature != SignatureStatus.Unknown, "signature finished");
        });
        Test("Adapters enumerate with a primary route", () =>
        {
            var a = new AdapterService().GetAdapters();
            Assert(a.Count > 0);
            Assert(a.Count(x => x.IsPrimary) <= 1, "at most one primary");
        });
        Test("DNS cache reader does not throw", () =>
        {
            var r = new DnsCacheReader();
            for (var i = 0; i < 20; i++) r.ReadCachedNames(); // repeated reads: the free path must be safe
        });
        Test("Public IP lookup never runs when disabled", () =>
            Equal(null, new PublicIpService().LookupAsync(false, CancellationToken.None).GetAwaiter().GetResult()));
    }

    private static void SettingsTests()
    {
        Test("Settings normalise out-of-range values", () =>
        {
            var s = new AppSettings { RefreshIntervalMs = 5, HistoryRetentionDays = 0, RulePrefix = "bad prefix!" };
            s.Normalize();
            Equal(1000, s.RefreshIntervalMs);
            Equal(1, s.HistoryRetentionDays);
            Equal("NTI_BLOCK", s.RulePrefix);
        });
        Test("Defaults match the specification", () =>
        {
            var s = new AppSettings();
            Assert(s.PublicIpLookup, "public IP lookup default ON");
            Assert(s.RequireBlockConfirmation);
            Assert(!s.ReadOnlyMode);
            Assert(!s.NotifyNewApplication && !s.NotifyUnusualBackground, "minimal notifications");
            Equal("NTI_BLOCK", s.RulePrefix);
        });
        Test("Settings round-trip through the file", () =>
        {
            var svc = new SettingsService();
            svc.Load();
            svc.Update(x => { x.RefreshIntervalMs = 3000; x.Theme = ThemeMode.Light; });
            var again = new SettingsService();
            again.Load();
            Equal(3000, again.Current.RefreshIntervalMs);
            Equal(ThemeMode.Light, again.Current.Theme);
        });
    }
}
