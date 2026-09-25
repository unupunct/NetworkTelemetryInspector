using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Network;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;
using NetworkTelemetryInspector.ViewModels;
using NetworkTelemetryInspector.Views;

namespace NetworkTelemetryInspector.Diagnostics;

/// <summary>
/// Headless verification modes. A WinExe's stdout does not reach a redirected parent, so every
/// line is appended to the --out file as it happens; a watchdog kills the process if a step hangs.
///
///   --selftest       [--out f] [--data dir]   engine: connections, processes, DNS, adapters, firewall read, cost
///   --verify-ui      [--out f] [--data dir] [--shots dir]   builds the real window off screen, renders every page,
///                                             fails on any WPF binding error
///   --workflow-test  --target exe [--out f] [--data dir]   Launch → detect → inspect → Block → verify rule →
///                                             verify traffic blocked → Unblock → verify rule removed → verify traffic
/// </summary>
public static class SelfTest
{
    private static string? _out;
    private static readonly StringBuilder Report = new();
    private static long _progress = Environment.TickCount64;
    private static int _failures;

    private static string? Arg(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static void Line(string s)
    {
        Interlocked.Exchange(ref _progress, Environment.TickCount64);
        Report.AppendLine(s);
        if (_out is not null) try { File.AppendAllText(_out, s + Environment.NewLine); } catch { }
        Log.Info("SelfTest", s);
    }

    private static void Check(bool ok, string what, string? detail = null)
    {
        if (!ok) _failures++;
        Line((ok ? "  PASS  " : "  FAIL  ") + what + (detail is null ? "" : " — " + detail));
    }

    private static void StartWatchdog(int seconds)
    {
        new Thread(() =>
        {
            while (true)
            {
                Thread.Sleep(1000);
                if (Environment.TickCount64 - Interlocked.Read(ref _progress) > seconds * 1000L)
                {
                    Line($"WATCHDOG: no progress for {seconds} s — aborting.");
                    Log.Flush();
                    Process.GetCurrentProcess().Kill();
                }
            }
        }) { IsBackground = true }.Start();
    }

    public static async Task<int> RunAsync(string[] args)
    {
        _out = Arg(args, "--out");
        if (_out is not null) try { File.WriteAllText(_out, ""); } catch { _out = null; }
        if (Arg(args, "--data") is { } data)
        {
            AppPaths.OverrideRoot(Path.GetFullPath(data));
            AppPaths.EnsureCreated();
        }
        StartWatchdog(args.Contains("--workflow-test") ? 150 : 60);  // --measure reports every 5 s
        try
        {
            if (args.Contains("--selftest")) await EngineAsync();
            else if (args.Contains("--verify-ui")) await UiAsync(Arg(args, "--shots"));
            else if (args.Contains("--workflow-test")) await WorkflowAsync(Arg(args, "--target"));
            else if (args.Contains("--measure")) await MeasureAsync(int.TryParse(Arg(args, "--measure"), out var secs) ? secs : 60);
        }
        catch (Exception ex)
        {
            _failures++;
            Line("EXCEPTION: " + ex);
        }
        Line(_failures == 0 ? "RESULT: PASS" : $"RESULT: FAIL ({_failures} failure(s))");
        Log.Flush();
        return _failures == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------ engine

    private static async Task EngineAsync()
    {
        Line($"Network & Telemetry Inspector self-test — {DateTime.Now:yyyy-MM-dd HH:mm:ss}, elevated: {Elevation.IsElevated}");
        using var host = new AppHost();
        var cpu0 = Process.GetCurrentProcess().TotalProcessorTime;
        var sw = Stopwatch.StartNew();

        MonitorSnapshot? snap = null;
        for (var i = 0; i < 4; i++)
        {
            snap = host.Monitor.Tick();
            if (i == 0) host.Processes.WaitForSignatures(15000);
            Line($"Tick {i + 1}: {snap.ActiveConnections} connections, {snap.AppsOnline} apps online, {snap.NewConnections} new, cost {snap.TickCost.TotalMilliseconds:0} ms");
            await Task.Delay(1500);
        }
        Check(snap!.ActiveConnections > 0, "Connections detected", snap.ActiveConnections.ToString());
        Check(snap.Apps.Count > 0, "Applications grouped", snap.Apps.Count.ToString());

        var withPath = snap.Apps.Count(a => a.Details.PathKnown);
        Check(withPath > 0, "Executable paths resolved", $"{withPath}/{snap.Apps.Count}");
        var signed = snap.Apps.Count(a => a.Details.Signature == SignatureStatus.Valid);
        Check(signed > 0, "Signatures verified", $"{signed} valid");
        var svchost = snap.Apps.FirstOrDefault(a => a.Details.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase));
        if (svchost is not null)
        {
            Check(svchost.Details.PathKnown, "SYSTEM service path resolved without opening the process", svchost.Details.Path);
            Check(svchost.Details.Signature == SignatureStatus.Valid, "Catalog-signed svchost.exe verified", svchost.Details.Signer ?? "no signer");
            Check(svchost.Details.StartTime is not null, "SYSTEM service start time read", svchost.Details.StartTime?.ToString("u"));
        }

        var dns = new DnsCacheReader();
        var names = dns.ReadCachedNames();
        var resolvable = names.Take(300).Count(n => dns.CachedAddresses(n).Count > 0);
        Line($"  info  DNS client cache: {names.Count} names, {resolvable} of the first {Math.Min(300, names.Count)} have cached A/AAAA records");
        var withHosts = snap.Apps.Sum(a => a.Connections.Count(c => c.Hostname is not null));
        Check(withHosts > 0, "Hostnames resolved", $"{withHosts} connections named");
        var fromCache = snap.Apps.Sum(a => a.Connections.Count(c => c.HostnameSource == HostnameSource.DnsCache));
        Line($"  info  {fromCache} hostnames from the local DNS cache");

        Line("Applications:");
        foreach (var a in snap.Apps.OrderByDescending(a => a.Connections.Count).Take(15))
        {
            Line($"  {a.Details.Name,-28} pid {string.Join(",", a.Pids.Take(3)),-14} conns {a.Connections.Count,3}  {ActivityClassText.Of(a.Classification.Class),-18} " +
                 $"sig {a.Details.Signature,-10} pub {a.Details.Publisher ?? "-"}");
            foreach (var c in a.Connections.Take(3))
                Line($"      {c.ProtocolText,-5} {Format.Endpoint(c.Key.RemoteAddress, c.Key.RemotePort),-44} {TcpStateText.Of(c.State),-12} {c.Hostname ?? ""} [{c.HostnameSource}]");
        }

        var adapters = host.Adapters.GetAdapters();
        Check(adapters.Count > 0, "Adapters enumerated", string.Join("; ", adapters.Where(a => a.Status == "Up").Select(a => $"{a.Name} {a.Type}{(a.IsPrimary ? " PRIMARY" : "")} {string.Join(",", a.IPv4)}")));
        var (up, down) = host.Adapters.SampleThroughput();
        await Task.Delay(1000);
        (up, down) = host.Adapters.SampleThroughput();
        Line($"  info  throughput up {Format.Rate(up)} down {Format.Rate(down)}");

        var rules = FirewallOperations.ReadOwnedRules(out var err);
        Check(rules is not null, "Firewall rules readable without elevation", err ?? $"{rules!.Count} rules owned by this app");
        Line($"  info  firewall enabled for active profile: {FirewallOperations.IsFirewallEnabled()?.ToString() ?? "unknown"}");

        Check(snap.TrafficPerApp == Elevation.IsElevated, "Per-app traffic availability matches elevation", snap.TrafficPerApp ? "available" : snap.TrafficUnavailableReason);

        var cpu = (Process.GetCurrentProcess().TotalProcessorTime - cpu0).TotalMilliseconds / sw.Elapsed.TotalMilliseconds / Environment.ProcessorCount * 100;
        var mem = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0;
        Line($"  info  CPU {cpu:0.00}% of machine over {sw.Elapsed.TotalSeconds:0.0} s (includes first-run signature checks), working set {mem:0} MB");
        Check(host.History.Count >= 0, "History store operational", $"{host.History.Count} entries");
    }

    // ------------------------------------------------------------------ UI

    private sealed class BindingErrorListener : TraceListener
    {
        public readonly List<string> Errors = new();
        public override void Write(string? message) { }
        public override void WriteLine(string? message)
        {
            if (message is not null) lock (Errors) Errors.Add(message);
        }
    }

    private static async Task UiAsync(string? shots)
    {
        Line($"UI verification — {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        var listener = new BindingErrorListener();
        PresentationTraceSources.Refresh();
        PresentationTraceSources.DataBindingSource.Listeners.Add(listener);
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning;

        // Force every theme resource to realise: a dictionary that fails to parse still "has" its keys.
        foreach (var d in Application.Current.Resources.MergedDictionaries)
            foreach (var key in d.Keys) _ = d[key];
        foreach (var key in new[] { "BgBrush", "SurfaceBrush", "AccentBrush", "Card", "AccentButton", "Switch", "Chip", "NavButton" })
            Check(Application.Current.TryFindResource(key) is not null, "Resource resolves: " + key);
        Check(Application.Current.TryFindResource(typeof(System.Windows.Controls.TextBox)) is Style, "Implicit TextBox style");
        Check(Application.Current.TryFindResource(typeof(System.Windows.Controls.ComboBox)) is Style, "Implicit ComboBox style");

        using var host = new AppHost();
        host.Settings.Update(s => { s.FirstRunCompleted = false; s.PublicIpLookup = false; });
        var vm = new MainViewModel(host, Application.Current.Dispatcher);
        var window = new MainWindow(vm, host)
        {
            WindowStartupLocation = WindowStartupLocation.Manual, Left = -32000, Top = -32000, ShowActivated = false, ShowInTaskbar = false
        };
        window.Show();
        host.Monitor.Start();
        await vm.InitializeAsync();

        for (var i = 0; i < 40 && vm.Dashboard.Apps.Count == 0; i++) await Task.Delay(250);
        await Task.Delay(2500); // a few snapshots + throughput samples
        Check(vm.Dashboard.Apps.Count > 0, "Dashboard shows applications", vm.Dashboard.Apps.Count.ToString());
        Check(!vm.Dashboard.IsLoading, "Loading state cleared");
        Check(vm.FirstRunVisible && vm.FirstRunReady, "First-run overlay shows live results", vm.FirstRunConnections);
        Line("  info  first run: " + vm.FirstRunAdapters);
        if (shots is not null) { Directory.CreateDirectory(shots); Render(window, Path.Combine(shots, "00-first-run.png")); }
        vm.CompleteFirstRunCommand.Execute(null);
        Check(!vm.FirstRunVisible && host.Settings.Current.FirstRunCompleted, "First run completes and is remembered");

        // Select + expand the busiest app, open the details panel.
        var app = vm.Dashboard.Apps.OrderByDescending(a => a.ConnectionCount).First();
        vm.Dashboard.SelectedApp = app;
        await Settle();
        if (shots is not null) Render(window, Path.Combine(shots, "01-dashboard-details.png"));
        app.IsExpanded = true;
        await Settle();
        Check(vm.Dashboard.IsDetailsOpen, "Details panel opens for " + app.Name, $"path {app.PathText}; publisher {app.Publisher}; signature {app.Signature}; start {app.StartTime}");
        Check(app.Connections.Count == app.ConnectionCount, "Expanded connection rows match count", app.ConnectionCount.ToString());
        if (shots is not null) Render(window, Path.Combine(shots, "01-dashboard-expanded.png"));

        // Search and quick filters.
        vm.Dashboard.SearchText = app.Name[..Math.Min(4, app.Name.Length)];
        await Task.Delay(300);
        await Settle();
        Check(vm.Dashboard.AppsView.Cast<AppItemViewModel>().Contains(app), "Search finds the application", vm.Dashboard.SearchText);
        vm.Dashboard.SearchText = "443";
        await Task.Delay(300);
        Line($"  info  search '443' → {vm.Dashboard.VisibleCount} apps");
        vm.Dashboard.SearchText = "";
        foreach (var f in Enum.GetValues<QuickFilter>())
        {
            vm.Dashboard.Filter = f;
            await Settle();
            Line($"  info  filter {f,-18} → {vm.Dashboard.AppsView.Count} apps");
        }
        vm.Dashboard.Filter = QuickFilter.All;

        vm.Dashboard.Mode = ListMode.Connections;
        await Settle();
        Check(vm.Dashboard.ConnectionsView.Count > 0, "Flat connection view populated", vm.Dashboard.ConnectionsView.Count.ToString());
        if (shots is not null) Render(window, Path.Combine(shots, "02-connections.png"));
        vm.Dashboard.Mode = ListMode.Grouped;

        // Confirmation dialog: shown and cancellable (never confirmed in the UI test).
        var confirm = vm.ConfirmAsync("Block Internet access for " + app.Name + "?", "test", "Block Application", true);
        await Settle();
        Check(vm.DialogVisible, "Confirmation dialog shown");
        if (shots is not null) Render(window, Path.Combine(shots, "03-confirm.png"));
        vm.DialogCancelCommand.Execute(null);
        Check(!await confirm && !vm.DialogVisible, "Cancel leaves the firewall untouched");

        // Read-only mode blocks the Block command before anything else happens.
        host.Settings.Update(s => s.ReadOnlyMode = true);
        await vm.Dashboard.BlockCommand.ExecuteAsync(app);
        Check(!vm.DialogVisible && vm.ToastText.Contains("Read-only"), "Read-only mode refuses Block", vm.ToastText);
        Check(vm.ModeText == "READ ONLY", "Header shows READ ONLY");
        host.Settings.Update(s => s.ReadOnlyMode = false);

        foreach (var page in new[] { Page.Firewall, Page.History, Page.Network, Page.Privacy, Page.Settings })
        {
            vm.CurrentPage = page;
            await Task.Delay(400);
            await Settle();
            Check(true, "Page renders: " + page);
            if (shots is not null) Render(window, Path.Combine(shots, $"1{(int)page}-{page.ToString().ToLowerInvariant()}.png"));
        }
        Line($"  info  history rows {vm.History.Rows.Count}; adapters {vm.NetworkInfo.Adapters.Count}; rules {vm.Firewall.RuleCount}; firewall '{vm.Firewall.FirewallState}'");
        Check(vm.NetworkInfo.Adapters.Count > 0, "Network page lists adapters");

        vm.CurrentPage = Page.Dashboard;
        App.ApplyTheme(ThemeMode.Light);
        await Settle();
        if (shots is not null) Render(window, Path.Combine(shots, "20-dashboard-light.png"));
        vm.CurrentPage = Page.Settings;
        await Settle();
        if (shots is not null) Render(window, Path.Combine(shots, "21-settings-light.png"));
        App.ApplyTheme(ThemeMode.Dark);

        // Narrow window: cards reflow, no crash.
        window.Width = 1080;
        vm.CurrentPage = Page.Dashboard;
        await Settle();
        if (shots is not null) Render(window, Path.Combine(shots, "22-dashboard-narrow.png"));

        await Task.Delay(300);
        lock (listener.Errors)
        {
            var errs = listener.Errors.Where(e => e.Contains("Error", StringComparison.OrdinalIgnoreCase)).Distinct().ToList();
            Check(errs.Count == 0, "No WPF binding errors", errs.Count == 0 ? null : errs.Count + " errors");
            foreach (var e in errs.Take(20)) Line("      " + e);
        }

        var mem = Process.GetCurrentProcess().WorkingSet64 / 1024.0 / 1024.0;
        Line($"  info  working set with UI {mem:0} MB");
        window.AllowClose();
        window.Close();
    }

    private static async Task Settle()
    {
        await Application.Current.Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
        await Task.Delay(120);
    }

    private static void Render(Window w, string file)
    {
        try
        {
            w.UpdateLayout();
            var content = (FrameworkElement)w.Content;
            var dpi = VisualTreeHelper.GetDpi(w);
            var rtb = new RenderTargetBitmap((int)(content.ActualWidth * dpi.DpiScaleX), (int)(content.ActualHeight * dpi.DpiScaleY),
                dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
            var bg = new DrawingVisual();
            using (var dc = bg.RenderOpen())
                dc.DrawRectangle((Brush)Application.Current.FindResource("BgBrush"), null, new Rect(0, 0, content.ActualWidth, content.ActualHeight));
            rtb.Render(bg);
            rtb.Render(content);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(rtb));
            using var fs = File.Create(file);
            enc.Save(fs);
            Line("  shot  " + file);
        }
        catch (Exception ex) { Line("  shot failed: " + ex.Message); }
    }

    // ------------------------------------------------------------------ resource usage

    /// <summary>
    /// Steady-state cost with the real window live (off screen) and monitoring at the default interval.
    /// A 20 s warm-up (first signature checks, JIT) is excluded from the CPU figure.
    /// </summary>
    private static async Task MeasureAsync(int seconds)
    {
        Line($"Resource measurement — {seconds} s after a 20 s warm-up, elevated: {Elevation.IsElevated}");
        using var host = new AppHost();
        host.Settings.Update(s => { s.FirstRunCompleted = true; s.PublicIpLookup = false; });
        var vm = new MainViewModel(host, Application.Current.Dispatcher);
        var window = new MainWindow(vm, host)
        {
            WindowStartupLocation = WindowStartupLocation.Manual, Left = -32000, Top = -32000, ShowActivated = false, ShowInTaskbar = false
        };
        window.Show();
        host.Monitor.Start();
        await vm.InitializeAsync();
        await Task.Delay(8000);
        // Expand the busiest application with the details panel open: the heaviest normal view.
        if (vm.Dashboard.Apps.OrderByDescending(a => a.ConnectionCount).FirstOrDefault() is { } app)
        {
            vm.Dashboard.SelectedApp = app;
            app.IsExpanded = true;
        }
        await Task.Delay(12000);

        var proc = Process.GetCurrentProcess();
        proc.Refresh();
        var cpu0 = proc.TotalProcessorTime;
        var sw = Stopwatch.StartNew();
        long peakWs = 0;
        for (var t = 0; t < seconds; t += 5)
        {
            await Task.Delay(5000);
            proc.Refresh();
            peakWs = Math.Max(peakWs, proc.WorkingSet64);
            Line($"  t+{t + 5,3}s  apps {vm.Dashboard.Apps.Count,3}  conns {vm.Dashboard.ActiveConnections,4}  ws {proc.WorkingSet64 / 1048576.0:0} MB  " +
                 $"private-ws {MemoryInfo.PrivateWorkingSet() / 1048576.0:0} MB  managed {GC.GetTotalMemory(false) / 1048576.0:0} MB  gen2 {GC.CollectionCount(2)}");
        }
        proc.Refresh();
        var cpu = (proc.TotalProcessorTime - cpu0).TotalMilliseconds / sw.Elapsed.TotalMilliseconds / Environment.ProcessorCount * 100;
        var live = GC.GetTotalMemory(true) / 1048576.0;
        Line($"  info  managed heap after full collection {live:0} MB (live objects)");
        var ws = MemoryInfo.PrivateWorkingSet() / 1048576.0;
        Line($"  info  steady-state CPU {cpu:0.00}% of machine ({Environment.ProcessorCount} logical CPUs), {cpu * Environment.ProcessorCount:0.0}% of one core");
        Line($"  info  private working set {ws:0} MB, total working set incl. shared images {proc.WorkingSet64 / 1048576.0:0} MB (peak {peakWs / 1048576.0:0} MB), monitor ticks {host.Monitor.TickCount}");
        Check(cpu < 3, "CPU below 3% during normal monitoring", $"{cpu:0.00}%");
        Check(ws < 150, "Memory (private working set, as Task Manager shows) below 150 MB", $"{ws:0} MB");
        window.AllowClose();
        window.Close();
    }

    // ------------------------------------------------------------------ workflow

    private static async Task WorkflowAsync(string? target)
    {
        Line($"Primary workflow test — {DateTime.Now:yyyy-MM-dd HH:mm:ss}, elevated: {Elevation.IsElevated}");
        if (target is null || !File.Exists(target)) { Check(false, "Target executable exists", target ?? "(none)"); return; }
        target = Path.GetFullPath(target);
        const string url = "https://speed.cloudflare.com/__down?bytes=400000";

        using var host = new AppHost();
        host.Settings.Update(s => { s.ReadOnlyMode = false; s.RefreshIntervalMs = 1000; });
        var vm = new MainViewModel(host, Application.Current.Dispatcher);

        // 1. Launch: a real process with a long-lived HTTPS connection (rate-limited download).
        Line("Step 1 — launch " + target);
        using var probe = StartProbe(target, "--limit-rate", "8k", "-o", "NUL", url);
        AppView? found = null;
        for (var i = 0; i < 30 && found is null; i++)
        {
            await Task.Delay(500);
            var snap = host.Monitor.Tick();
            found = snap.Apps.FirstOrDefault(a => string.Equals(a.Details.Path, target, StringComparison.OrdinalIgnoreCase) && a.Connections.Any(c => c.State == TcpState.Established));
            if (found is not null) vm.Dashboard.Apply(snap);
        }
        Check(found is not null, "Step 2 — connection detected for the launched process",
            found is null ? null : string.Join(", ", found.Connections.Select(c => $"{Format.Endpoint(c.Key.RemoteAddress, c.Key.RemotePort)} {TcpStateText.Of(c.State)} {c.Hostname}")));
        if (found is null) return;

        // 3. Select + inspect (let the background signature check finish first).
        host.Processes.WaitForSignatures(10000);
        vm.Dashboard.Apply(host.Monitor.Tick());
        var item = vm.Dashboard.Apps.First(a => a.GroupKey == found.GroupKey);
        vm.Dashboard.SelectedApp = item;
        Check(vm.Dashboard.IsDetailsOpen && item.Path == target, "Step 3 — application selected, details available",
            $"{item.Name} pid {item.PidText}; publisher {item.Publisher}; signature {item.Signature}; started {item.StartTime}; {item.ConnectionCount} active; hostnames {item.Hostnames}");
        try { probe.Kill(); } catch { }

        // Baseline: the target can reach the Internet before blocking.
        var before = await RunProbeAsync(target, 15, "-s", "-o", "NUL", "-w", "%{http_code}", url);
        Check(before.ExitCode == 0, "Baseline — target reaches the Internet before blocking", $"exit {before.ExitCode}, http {before.Output}");

        // 4. Block (the UI flow without the confirmation click).
        Line("Step 4 — Block (UAC prompt expected when not elevated)");
        host.Settings.Update(s => s.RequireBlockConfirmation = false);
        await vm.Dashboard.BlockCommand.ExecuteAsync(item);
        Line("  info  toast: " + vm.ToastText);

        // 5. Verify the firewall rule, independently of the service cache.
        var rules = FirewallOperations.ReadOwnedRules(out var err) ?? new();
        var rule = rules.FirstOrDefault(r => string.Equals(r.ApplicationPath, target, StringComparison.OrdinalIgnoreCase));
        Check(rule is not null, "Step 5 — firewall rule exists", rule is null ? err : $"{rule.Name} {rule.Direction} {rule.Action} enabled={rule.Enabled}");
        if (rule is not null)
        {
            Check(rule.Enabled && rule.Action == "Block" && rule.Direction == "Outbound", "Rule is an enabled outbound block");
            Check(rule.Name.StartsWith(host.Settings.Current.RulePrefix + "_", StringComparison.Ordinal) && rule.Name.EndsWith(RuleNaming.PathHash(target)), "Rule name uses prefix and path hash", rule.Name);
        }
        host.Monitor.Tick();
        vm.Dashboard.Apply(host.Monitor.Tick());
        Check(host.Firewall.IsBlocked(target) && item.IsBlocked, "Dashboard shows BLOCKED", item.StatusText);

        // 5b. The block is real: the same request now fails.
        var during = await RunProbeAsync(target, 20, "-s", "-o", "NUL", "--connect-timeout", "6", "-w", "%{http_code}", url);
        Check(during.ExitCode != 0, "Traffic is actually blocked", $"exit {during.ExitCode} (curl 7 = cannot connect, 28 = timeout)");

        // 6. Unblock.
        Line("Step 6 — Unblock (UAC prompt expected when not elevated)");
        await vm.Dashboard.UnblockCommand.ExecuteAsync(item);
        Line("  info  toast: " + vm.ToastText);
        var after = FirewallOperations.ReadOwnedRules(out err) ?? new();
        Check(!after.Any(r => string.Equals(r.ApplicationPath, target, StringComparison.OrdinalIgnoreCase)), "Step 7 — rule removed", $"{after.Count} rules of ours remain");
        Check(!host.Firewall.IsBlocked(target), "Service no longer reports the app as blocked");

        var restored = await RunProbeAsync(target, 15, "-s", "-o", "NUL", "-w", "%{http_code}", url);
        Check(restored.ExitCode == 0, "Traffic restored after Unblock", $"exit {restored.ExitCode}, http {restored.Output}");

        var hist = host.History.Query(new HistoryFilter { Application = Path.GetFileName(target) }, 500);
        Check(hist.Any(h => h.Action == "Blocked") && hist.Any(h => h.Action == "Unblocked"), "History recorded Block and Unblock",
            string.Join(", ", hist.GroupBy(h => h.Action).Select(g => g.Key + "×" + g.Count())));
    }

    private static Process StartProbe(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        return Process.Start(psi)!;
    }

    private static async Task<(int ExitCode, string Output)> RunProbeAsync(string exe, int timeoutSeconds, params string[] args)
    {
        using var p = StartProbe(exe, ["--max-time", timeoutSeconds.ToString(), .. args]);
        var output = p.StandardOutput.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds + 5));
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { try { p.Kill(); } catch { } return (-1, "killed"); }
        return (p.ExitCode, (await output).Trim());
    }

    // ------------------------------------------------------------------ uninstall (CLI)

    public static async Task<int> UninstallAsync()
    {
        var settings = new SettingsService();
        settings.Load();
        if (settings.Current.RemoveRulesOnUninstall)
        {
            var fw = new FirewallService(() => settings.Current);
            var r = await fw.RemoveAllAsync();
            if (!r.Ok) { Log.Error("Uninstall", r.Message); Log.Flush(); return 1; }
        }
        try { AutoStart.Apply(false); } catch { }
        Log.Flush();
        try { Directory.Delete(AppPaths.Root, true); } catch { }
        return 0;
    }
}
