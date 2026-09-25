using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Network;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

public enum Page { Dashboard, Firewall, History, Network, Privacy, Settings }
public enum NotificationKind { NewApplication, Blocked, UnusualBackground }

public sealed partial class MainViewModel : ObservableObject
{
    private readonly AppHost _host;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _toastTimer;
    private MonitorSnapshot? _pendingSnapshot;
    private int _snapshotQueued;
    private (double Up, double Down)? _pendingThroughput;
    private int _throughputQueued;
    private TaskCompletionSource<bool>? _dialog;
    private DateTime _lastPublicIp = DateTime.MinValue;

    public MainViewModel(AppHost host, Dispatcher dispatcher)
    {
        _host = host;
        _dispatcher = dispatcher;
        Dashboard = new DashboardViewModel(host, this);
        Firewall = new FirewallViewModel(host, this);
        History = new HistoryViewModel(host, this);
        NetworkInfo = new NetworkViewModel(host, this);
        Settings = new SettingsViewModel(host, this);

        _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _toastTimer.Tick += (_, _) => { _toastTimer.Stop(); ToastVisible = false; };

        host.Monitor.SnapshotReady += OnSnapshot;
        host.Monitor.ThroughputSampled += OnThroughput;
        host.Monitor.Notice += OnNotice;
        host.Monitor.PausedChanged += p => _dispatcher.BeginInvoke(() => { IsPaused = p; OnPropertyChanged(nameof(PauseText)); });
        host.Settings.Changed += _ => { if (_dispatcher.CheckAccess()) UpdateMode(); else _dispatcher.BeginInvoke(UpdateMode); };
        NetworkChange.NetworkAddressChanged += (_, _) => _dispatcher.BeginInvoke(() => _ = RefreshNetworkAsync(publicIp: true));
        NetworkChange.NetworkAvailabilityChanged += (_, _) => _dispatcher.BeginInvoke(() => _ = RefreshNetworkAsync(publicIp: true));

        FirstRunVisible = !host.Settings.Current.FirstRunCompleted;
        UpdateMode();
    }

    public DashboardViewModel Dashboard { get; }
    public FirewallViewModel Firewall { get; }
    public HistoryViewModel History { get; }
    public NetworkViewModel NetworkInfo { get; }
    public SettingsViewModel Settings { get; }

    /// <summary>Set by the tray: shows a Windows notification.</summary>
    public Action<string, string>? ShowNotification { get; set; }

    [ObservableProperty] private Page _currentPage = Page.Dashboard;
    [ObservableProperty] private string _modeText = "";
    [ObservableProperty] private string _modeTone = "Neutral";
    [ObservableProperty] private string _modeTooltip = "";
    [ObservableProperty] private string _networkStatus = "Detecting…";
    [ObservableProperty] private string _networkTone = "Neutral";
    [ObservableProperty] private string _privateIp = "—";
    [ObservableProperty] private string _publicIp = "—";
    [ObservableProperty] private string _publicIpTooltip = "";
    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private bool _isRefreshing;

    [ObservableProperty] private bool _dialogVisible;
    [ObservableProperty] private string _dialogTitle = "";
    [ObservableProperty] private string _dialogMessage = "";
    [ObservableProperty] private string _dialogConfirmText = "OK";
    [ObservableProperty] private bool _dialogDanger;

    [ObservableProperty] private bool _toastVisible;
    [ObservableProperty] private string _toastText = "";
    [ObservableProperty] private string _toastTone = "Neutral";

    [ObservableProperty] private bool _firstRunVisible;
    [ObservableProperty] private string _firstRunAdapters = "Detecting network adapters…";
    [ObservableProperty] private string _firstRunMonitoring = "Starting monitoring…";
    [ObservableProperty] private string _firstRunConnections = "Waiting for the first scan…";
    [ObservableProperty] private bool _firstRunReady;

    public bool IsReadOnly => _host.Settings.Current.ReadOnlyMode;
    public bool IsElevated => Elevation.IsElevated;
    public string PauseText => IsPaused ? "Resume monitoring" : "Pause monitoring";
    public string Version => typeof(MainViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    partial void OnCurrentPageChanged(Page value)
    {
        if (value == Page.History) History.Reload();
        if (value == Page.Network) _ = NetworkInfo.RefreshAsync();
        if (value == Page.Firewall) _ = _host.Firewall.RefreshAsync();
    }

    public async Task InitializeAsync()
    {
        await RefreshNetworkAsync(publicIp: true);
        FirstRunMonitoring = "Monitoring started — connections are read locally from Windows, every "
            + (_host.Settings.Current.RefreshIntervalMs / 1000.0).ToString("0.#") + " s.";
        _ = _host.Firewall.RefreshAsync();
    }

    private void UpdateMode()
    {
        var s = _host.Settings.Current;
        if (s.ReadOnlyMode)
        {
            ModeText = "READ ONLY";
            ModeTone = "Warning";
            ModeTooltip = "Read-only mode: monitoring only. No firewall or system changes are made.";
        }
        else if (Elevation.IsElevated)
        {
            ModeText = "ADMIN MODE";
            ModeTone = "Accent";
            ModeTooltip = "Running as administrator: firewall changes apply directly and per-application traffic is measured.";
        }
        else
        {
            ModeText = "STANDARD";
            ModeTone = "Neutral";
            ModeTooltip = "Running as a standard user. Blocking asks for administrator permission only when you use it.";
        }
        OnPropertyChanged(nameof(IsReadOnly));
    }

    // ---------------- Monitor → UI marshalling (coalesced: at most one queued update) ----------------

    private void OnSnapshot(MonitorSnapshot s)
    {
        _pendingSnapshot = s;
        if (Interlocked.Exchange(ref _snapshotQueued, 1) == 1) return;
        _dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
        {
            Interlocked.Exchange(ref _snapshotQueued, 0);
            var snap = _pendingSnapshot;
            if (snap is null) return;
            try
            {
                Dashboard.Apply(snap);
                if (FirstRunVisible)
                {
                    FirstRunConnections = $"{snap.ActiveConnections} active connections from {snap.AppsOnline} applications.";
                    FirstRunReady = true;
                }
            }
            catch (Exception ex) { Log.Error("UI", "Snapshot could not be displayed", ex); }
        });
    }

    private void OnThroughput(double up, double down)
    {
        _pendingThroughput = (up, down);
        if (Interlocked.Exchange(ref _throughputQueued, 1) == 1) return;
        _dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
        {
            Interlocked.Exchange(ref _throughputQueued, 0);
            if (_pendingThroughput is { } t) Dashboard.ApplyThroughput(t.Up, t.Down);
            if (DateTime.Now - _lastPublicIp > TimeSpan.FromMinutes(30)) _ = RefreshPublicIpAsync();
        });
    }

    private void OnNotice(MonitorNotice n)
    {
        _dispatcher.BeginInvoke(() =>
        {
            if (n.Kind == MonitorNoticeKind.NewApplication) Notify(NotificationKind.NewApplication, "New application connected to the Internet", n.Message);
            else Notify(NotificationKind.UnusualBackground, "Unusual background activity detected", n.Message);
        });
    }

    public void Notify(NotificationKind kind, string title, string message)
    {
        var s = _host.Settings.Current;
        var allowed = kind switch
        {
            NotificationKind.NewApplication => s.NotifyNewApplication,
            NotificationKind.Blocked => s.NotifyBlocked,
            NotificationKind.UnusualBackground => s.NotifyUnusualBackground,
            _ => false
        };
        if (allowed) ShowNotification?.Invoke(title, message);
    }

    // ---------------- Header ----------------

    public async Task RefreshNetworkAsync(bool publicIp)
    {
        try
        {
            var adapters = await Task.Run(_host.Adapters.GetAdapters);
            var primary = adapters.FirstOrDefault(a => a.IsPrimary) ?? adapters.FirstOrDefault(a => a.Status == "Up" && a.Gateways.Count > 0);
            if (primary is null)
            {
                NetworkStatus = NetworkInterface.GetIsNetworkAvailable() ? "Connected · no Internet route" : "Disconnected";
                NetworkTone = "Danger";
                PrivateIp = "—";
            }
            else
            {
                NetworkStatus = $"Connected · {primary.Type}";
                NetworkTone = "Success";
                PrivateIp = primary.IPv4.FirstOrDefault()?.Split('/')[0] ?? primary.IPv6.FirstOrDefault() ?? "—";
            }
            var up = adapters.Count(a => a.Status == "Up");
            FirstRunAdapters = primary is null
                ? $"Detected {adapters.Count} network adapters ({up} up). No active Internet route was found."
                : $"Detected {adapters.Count} network adapters ({up} up) — primary: {primary.Name} ({primary.Type}{(PrivateIp != "—" ? ", " + PrivateIp : "")}).";
            NetworkInfo.SetAdapters(adapters);
        }
        catch (Exception ex)
        {
            Log.Warn("Header", "Network status unavailable: " + ex.Message);
            NetworkStatus = "Network status unavailable";
            NetworkTone = "Warning";
        }
        if (publicIp) await RefreshPublicIpAsync();
    }

    private async Task RefreshPublicIpAsync()
    {
        _lastPublicIp = DateTime.Now;
        var allowed = _host.Settings.Current.PublicIpLookup;
        if (!allowed)
        {
            PublicIp = "Lookup off";
            PublicIpTooltip = "External public IP lookup is disabled in Settings. No request is made.";
            return;
        }
        PublicIpTooltip = $"Public IP lookup uses an external service ({PublicIpService.ServiceHost}). Nothing else is sent. Disable it in Settings.";
        var ip = await _host.PublicIp.LookupAsync(allowed, CancellationToken.None);
        PublicIp = ip ?? "Unavailable";
    }

    [RelayCommand]
    private async Task Refresh()
    {
        IsRefreshing = true;
        _host.Monitor.RefreshNow();
        _host.Processes.RefreshServices();
        await RefreshNetworkAsync(publicIp: true);
        await _host.Firewall.RefreshAsync();
        if (CurrentPage == Page.History) History.Reload();
        IsRefreshing = false;
    }

    [RelayCommand]
    private void OpenSettings() => CurrentPage = Page.Settings;

    [RelayCommand]
    private void Navigate(Page page) => CurrentPage = page;

    [RelayCommand]
    public void TogglePause()
    {
        if (_host.Monitor.IsPaused) _host.Monitor.Resume(); else _host.Monitor.Pause();
    }

    [RelayCommand]
    public void ToggleReadOnly()
    {
        _host.Settings.Update(s => s.ReadOnlyMode = !s.ReadOnlyMode);
        Settings.Reload();
        Toast(_host.Settings.Current.ReadOnlyMode ? "Read-only mode on: monitoring only." : "Read-only mode off: firewall changes are allowed.", "Neutral");
    }

    [RelayCommand]
    private void RestartAsAdmin()
    {
        App.RestartElevated();
    }

    [RelayCommand]
    private void CompleteFirstRun()
    {
        FirstRunVisible = false;
        _host.Settings.Update(s => s.FirstRunCompleted = true);
    }

    // ---------------- Dialog & toast ----------------

    public Task<bool> ConfirmAsync(string title, string message, string confirmText, bool danger)
    {
        _dialog?.TrySetResult(false);
        _dialog = new TaskCompletionSource<bool>();
        DialogTitle = title;
        DialogMessage = message;
        DialogConfirmText = confirmText;
        DialogDanger = danger;
        DialogVisible = true;
        return _dialog.Task;
    }

    [RelayCommand]
    private void DialogConfirm()
    {
        DialogVisible = false;
        _dialog?.TrySetResult(true);
    }

    [RelayCommand]
    private void DialogCancel()
    {
        DialogVisible = false;
        _dialog?.TrySetResult(false);
    }

    public void Toast(string text, string tone)
    {
        ToastText = text;
        ToastTone = tone;
        ToastVisible = true;
        _toastTimer.Stop();
        _toastTimer.Start();
    }

    [RelayCommand]
    private void DismissToast() => ToastVisible = false;
}
