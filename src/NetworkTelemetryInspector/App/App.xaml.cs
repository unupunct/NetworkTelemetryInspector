using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using NetworkTelemetryInspector.Diagnostics;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;
using NetworkTelemetryInspector.ViewModels;
using NetworkTelemetryInspector.Views;

namespace NetworkTelemetryInspector;

public partial class App : Application
{
    private static Mutex? _instanceMutex;
    private static EventWaitHandle? _showSignal;
    private AppHost? _host;
    private TrayService? _tray;
    private MainWindow? _window;
    private bool _uninstalling;

    public static new App Current => (App)Application.Current;
    public static bool IsHeadless { get; private set; }

    public AppHost? Host => _host;
    public MainWindow? Window => _window;

    private static string InstanceId
    {
        get
        {
            try { using var id = WindowsIdentity.GetCurrent(); return id.User?.Value ?? "user"; }
            catch { return "user"; }
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        AppPaths.EnsureCreated();
        HookGlobalErrors();
        var args = e.Args;

        // 1. Elevated one-shot firewall helper: no UI, no single-instance lock.
        var op = Array.IndexOf(args, ElevatedFirewallHelper.Argument);
        if (op >= 0)
        {
            IsHeadless = true;
            var data = Array.IndexOf(args, "--data");
            if (data >= 0 && data + 1 < args.Length && Path.IsPathFullyQualified(args[data + 1]) && Directory.Exists(args[data + 1]))
                AppPaths.OverrideRoot(args[data + 1]);
            var code = op + 1 < args.Length ? ElevatedFirewallHelper.Execute(args[op + 1]) : 2;
            Shutdown(code);
            return;
        }

        // 2. Headless verification modes.
        if (args.Contains("--selftest") || args.Contains("--verify-ui") || args.Contains("--workflow-test") || args.Contains("--measure"))
        {
            IsHeadless = true;
            Log.Info("App", "Headless mode: " + string.Join(' ', args));
            _ = Dispatcher.BeginInvoke(async () => Shutdown(await SelfTest.RunAsync(args)));
            return;
        }

        if (args.Contains("--uninstall"))
        {
            IsHeadless = true;
            _ = Dispatcher.BeginInvoke(async () => Shutdown(await SelfTest.UninstallAsync()));
            return;
        }

        // 3. Normal interactive start: one instance per user.
        var id = InstanceId;
        _instanceMutex = new Mutex(false, @"Local\NetworkTelemetryInspector_" + id);
        var waitMs = args.Contains("--elevated-restart") ? 10000 : 0;
        bool owned;
        try { owned = _instanceMutex.WaitOne(waitMs); }
        catch (AbandonedMutexException) { owned = true; }
        if (!owned)
        {
            try { EventWaitHandle.OpenExisting(@"Local\NetworkTelemetryInspector_Show_" + id).Set(); } catch { }
            Shutdown(0);
            return;
        }
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\NetworkTelemetryInspector_Show_" + id);
        new Thread(() =>
        {
            while (_showSignal.WaitOne())
                Dispatcher.BeginInvoke(ShowMainWindow);
        }) { IsBackground = true, Name = "NTI activation" }.Start();

        Log.Info("App", $"Starting v{typeof(App).Assembly.GetName().Version} (elevated: {Elevation.IsElevated})");
        Log.Prune(30);
        ElevatedFirewallHelper.CleanStale();

        try
        {
            _host = new AppHost();
        }
        catch (Exception ex)
        {
            Log.Error("App", "Startup failed", ex);
            MessageBox.Show("Network & Telemetry Inspector could not start: " + FriendlyError.Describe(ex), "Network & Telemetry Inspector",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        ApplyTheme(_host.Settings.Current.Theme);
        SystemEvents.UserPreferenceChanged += (_, _) =>
        {
            if (_host?.Settings.Current.Theme == ThemeMode.System) Dispatcher.BeginInvoke(() => ApplyTheme(ThemeMode.System));
        };

        var vm = new MainViewModel(_host, Dispatcher);
        _window = new MainWindow(vm, _host);
        _tray = new TrayService(this, vm, _host);
        vm.ShowNotification = _tray.ShowBalloon;

        var minimized = args.Contains("--minimized") && _host.Settings.Current.FirstRunCompleted;
        if (!minimized) _window.Show();

        _host.Monitor.Start();
        _ = vm.InitializeAsync();
    }

    public void ShowMainWindow()
    {
        if (_window is null) return;
        if (!_window.IsVisible) _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true;
        _window.Topmost = false;
        _window.Focus();
    }

    /// <summary>Ends the app for real (the window's close button only hides to the tray).</summary>
    public void ExitApplication()
    {
        _window?.AllowClose();
        _window?.Close();
        Shutdown(0);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _tray?.Dispose(); } catch { }
        try { _host?.Dispose(); } catch { }
        if (!_uninstalling) Log.Info("App", "Exit");
        Log.Flush();
        try { _instanceMutex?.ReleaseMutex(); } catch { }
        base.OnExit(e);
    }

    public static void RestartElevated()
    {
        if (Elevation.RestartElevated("--elevated-restart"))
        {
            // The new instance waits for our single-instance lock; release it by exiting.
            Current.ExitApplication();
        }
        else
        {
            Current._window?.ViewModel.Toast("Administrator permission was not granted.", "Warning");
        }
    }

    /// <summary>Portable uninstall: autostart entry and all local data are removed, then the app exits.</summary>
    public static void UninstallAndExit()
    {
        var app = Current;
        app._uninstalling = true;
        try { AutoStart.Apply(false); } catch { }
        try { app._host?.Dispose(); } catch { }
        app._host = null;
        Log.Flush();
        try { if (Directory.Exists(AppPaths.Root)) Directory.Delete(AppPaths.Root, recursive: true); } catch { /* a log file may still be open; harmless */ }
        app._tray?.Dispose();
        app._tray = null;
        app._window?.AllowClose();
        app._window?.Close();
        app.Shutdown(0);
    }

    public static void ApplyTheme(ThemeMode mode)
    {
        var light = mode == ThemeMode.Light || (mode == ThemeMode.System && WindowsTheme.IsLight());
        var uri = new Uri($"/NetworkTelemetryInspector;component/Resources/Themes/{(light ? "Light" : "Dark")}.xaml", UriKind.Relative);
        var dicts = Current.Resources.MergedDictionaries;
        if (dicts.Count > 0 && dicts[0].Source == uri) return;
        dicts[0] = new ResourceDictionary { Source = uri };
        IsLightTheme = light;
        ThemeChanged?.Invoke(light);
    }

    public static bool IsLightTheme { get; private set; }
    public static event Action<bool>? ThemeChanged;

    private void HookGlobalErrors()
    {
        DispatcherUnhandledException += (_, ex) =>
        {
            Log.Error("Unhandled", "UI thread exception", ex.Exception);
            ex.Handled = true; // never crash for a recoverable UI error
            if (!IsHeadless)
                _window?.ViewModel.Toast("Something went wrong: " + FriendlyError.Describe(ex.Exception) + " (details in the log)", "Danger");
        };
        AppDomain.CurrentDomain.UnhandledException += (_, ex) =>
        {
            if (ex.ExceptionObject is Exception e) Log.Error("Unhandled", "Fatal exception", e);
            Log.Flush();
        };
        TaskScheduler.UnobservedTaskException += (_, ex) =>
        {
            Log.Error("Unhandled", "Background task exception", ex.Exception);
            ex.SetObserved();
        };
    }
}
