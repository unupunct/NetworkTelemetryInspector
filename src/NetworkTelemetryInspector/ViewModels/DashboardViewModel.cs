using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Network;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

public enum QuickFilter { All, Active, Background, PossibleTelemetry, Updates, Blocked, Unknown }
public enum AppSort { Connections, Traffic, Name, Recent }
public enum ListMode { Grouped, Connections }

public sealed partial class DashboardViewModel : ObservableObject
{
    private readonly AppHost _host;
    private readonly MainViewModel _main;
    private readonly Dictionary<string, AppItemViewModel> _apps = new();
    private readonly Dictionary<ConnectionKey, ConnectionItemViewModel> _flat = new();
    private readonly DispatcherTimer _searchDebounce;

    public DashboardViewModel(AppHost host, MainViewModel main)
    {
        _host = host;
        _main = main;
        AppsView = new ListCollectionView(Apps) { Filter = FilterApp, IsLiveFiltering = true, IsLiveSorting = true };
        foreach (var p in new[] { nameof(AppItemViewModel.Class), nameof(AppItemViewModel.IsBlocked), nameof(AppItemViewModel.IsActive), nameof(AppItemViewModel.IsUnknownProcess) })
            AppsView.LiveFilteringProperties.Add(p);
        ConnectionsView = new ListCollectionView(AllConnections) { Filter = FilterConnection };
        ConnectionsView.SortDescriptions.Add(new SortDescription(nameof(ConnectionItemViewModel.AppName), ListSortDirection.Ascending));
        ApplySort();
        _searchDebounce = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(120) };
        _searchDebounce.Tick += (_, _) => { _searchDebounce.Stop(); RefreshViews(); };
    }

    public ObservableCollection<AppItemViewModel> Apps { get; } = new();
    public ListCollectionView AppsView { get; }
    public ObservableCollection<ConnectionItemViewModel> AllConnections { get; } = new();
    public ListCollectionView ConnectionsView { get; }

    /// <summary>Raised on the UI thread with (download, upload) bytes/sec; the view feeds its graph.</summary>
    public event Action<double, double>? ThroughputSample;

    [ObservableProperty] private bool _isLoading = true;
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private int _appsOnline;
    [ObservableProperty] private string _uploadRate = "—";
    [ObservableProperty] private string _downloadRate = "—";
    [ObservableProperty] private int _blockedCount;
    [ObservableProperty] private int _newConnections;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private QuickFilter _filter = QuickFilter.All;
    [ObservableProperty] private AppSort _sort = AppSort.Connections;
    [ObservableProperty] private ListMode _mode = ListMode.Grouped;
    [ObservableProperty] private AppItemViewModel? _selectedApp;
    [ObservableProperty] private ConnectionItemViewModel? _selectedConnection;
    [ObservableProperty] private bool _trafficPerApp;
    [ObservableProperty] private string _trafficNote = "";
    [ObservableProperty] private int _visibleCount;
    [ObservableProperty] private string _countAll = "All";
    [ObservableProperty] private string _countActive = "Active";
    [ObservableProperty] private string _countBackground = "Background";
    [ObservableProperty] private string _countTelemetry = "Possible Telemetry";
    [ObservableProperty] private string _countUpdates = "Updates";
    [ObservableProperty] private string _countBlocked = "Blocked";
    [ObservableProperty] private string _countUnknown = "Unknown";
    [ObservableProperty] private string _lastUpdate = "";
    /// <summary>View state: the list is narrow, so secondary columns are hidden.</summary>
    [ObservableProperty] private bool _isCompact;

    public bool IsDetailsOpen => SelectedApp is not null;
    public string ClassificationDisclaimer => TelemetryClassifier.Disclaimer;
    public IReadOnlyList<AppSort> SortOptions { get; } = Enum.GetValues<AppSort>();

    partial void OnSelectedAppChanged(AppItemViewModel? value) => OnPropertyChanged(nameof(IsDetailsOpen));

    partial void OnSelectedConnectionChanged(ConnectionItemViewModel? value)
    {
        if (value is not null) SelectedApp = value.Owner;
    }

    partial void OnSearchTextChanged(string value)
    {
        _searchDebounce.Stop();
        _searchDebounce.Start();
    }

    partial void OnFilterChanged(QuickFilter value) => RefreshViews();
    partial void OnSortChanged(AppSort value) => ApplySort();

    private void ApplySort()
    {
        using (AppsView.DeferRefresh())
        {
            AppsView.SortDescriptions.Clear();
            AppsView.LiveSortingProperties.Clear();
            var (prop, dir) = Sort switch
            {
                AppSort.Traffic => (nameof(AppItemViewModel.RateTotal), ListSortDirection.Descending),
                AppSort.Name => (nameof(AppItemViewModel.Name), ListSortDirection.Ascending),
                AppSort.Recent => (nameof(AppItemViewModel.LastSeenTime), ListSortDirection.Descending),
                _ => (nameof(AppItemViewModel.ConnectionCount), ListSortDirection.Descending)
            };
            AppsView.SortDescriptions.Add(new SortDescription(prop, dir));
            AppsView.LiveSortingProperties.Add(prop);
            if (prop != nameof(AppItemViewModel.Name))
                AppsView.SortDescriptions.Add(new SortDescription(nameof(AppItemViewModel.Name), ListSortDirection.Ascending));
        }
    }

    private void RefreshViews()
    {
        AppsView.Refresh();
        ConnectionsView.Refresh();
        VisibleCount = Mode == ListMode.Grouped ? AppsView.Count : ConnectionsView.Count;
    }

    partial void OnModeChanged(ListMode value) => VisibleCount = value == ListMode.Grouped ? AppsView.Count : ConnectionsView.Count;

    private bool MatchesFilter(AppItemViewModel a) => Filter switch
    {
        QuickFilter.Active => a.IsActive,
        QuickFilter.Background => a.Class == ActivityClass.Background,
        QuickFilter.PossibleTelemetry => a.Class == ActivityClass.PossibleTelemetry,
        QuickFilter.Updates => a.Class == ActivityClass.UpdateService,
        QuickFilter.Blocked => a.IsBlocked,
        QuickFilter.Unknown => a.Class == ActivityClass.Unknown || a.IsUnknownProcess,
        _ => true
    };

    private bool FilterApp(object o)
    {
        if (o is not AppItemViewModel a || !MatchesFilter(a)) return false;
        var q = SearchText.Trim();
        return q.Length == 0 || a.Matches(q);
    }

    private bool FilterConnection(object o)
    {
        if (o is not ConnectionItemViewModel c || !MatchesFilter(c.Owner)) return false;
        var q = SearchText.Trim();
        return q.Length == 0 || c.Matches(q) || c.Owner.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               (c.Owner.Path?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
               c.Owner.Publisher.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Applies a monitor snapshot incrementally: rows are updated in place, never rebuilt.</summary>
    public void Apply(MonitorSnapshot s)
    {
        var seen = new HashSet<string>();
        foreach (var v in s.Apps)
        {
            seen.Add(v.GroupKey);
            if (!_apps.TryGetValue(v.GroupKey, out var vm))
            {
                vm = new AppItemViewModel(v.GroupKey);
                vm.Update(v, s.TrafficPerApp, _host.Processes.Icon);
                _apps[v.GroupKey] = vm;
                Apps.Add(vm);
            }
            else vm.Update(v, s.TrafficPerApp, _host.Processes.Icon);
        }
        for (var i = Apps.Count - 1; i >= 0; i--)
        {
            if (seen.Contains(Apps[i].GroupKey)) continue;
            if (ReferenceEquals(SelectedApp, Apps[i])) SelectedApp = null;
            _apps.Remove(Apps[i].GroupKey);
            Apps.RemoveAt(i);
        }

        // Flat connection list = union of every app's rows (same view-model instances).
        var liveKeys = new HashSet<ConnectionKey>();
        foreach (var app in Apps)
        {
            foreach (var c in app.Connections)
            {
                liveKeys.Add(c.Key);
                if (_flat.TryAdd(c.Key, c)) AllConnections.Add(c);
                else if (!ReferenceEquals(_flat[c.Key], c))
                {
                    AllConnections.Remove(_flat[c.Key]);
                    _flat[c.Key] = c;
                    AllConnections.Add(c);
                }
            }
        }
        for (var i = AllConnections.Count - 1; i >= 0; i--)
        {
            if (!liveKeys.Contains(AllConnections[i].Key))
            {
                _flat.Remove(AllConnections[i].Key);
                AllConnections.RemoveAt(i);
            }
        }

        ActiveConnections = s.ActiveConnections;
        AppsOnline = s.AppsOnline;
        BlockedCount = s.Blocked;
        NewConnections = s.NewConnections;
        TrafficPerApp = s.TrafficPerApp;
        TrafficNote = s.TrafficPerApp ? "" : s.TrafficUnavailableReason;
        LastUpdate = s.Time.ToString("HH:mm:ss");

        CountAll = $"All  {Apps.Count}";
        CountActive = $"Active  {Apps.Count(a => a.IsActive)}";
        CountBackground = $"Background  {Apps.Count(a => a.Class == ActivityClass.Background)}";
        CountTelemetry = $"Possible Telemetry  {Apps.Count(a => a.Class == ActivityClass.PossibleTelemetry)}";
        CountUpdates = $"Updates  {Apps.Count(a => a.Class == ActivityClass.UpdateService)}";
        CountBlocked = $"Blocked  {Apps.Count(a => a.IsBlocked)}";
        CountUnknown = $"Unknown  {Apps.Count(a => a.Class == ActivityClass.Unknown || a.IsUnknownProcess)}";

        // Search results depend on connection data, which changes every tick.
        if (SearchText.Trim().Length > 0) RefreshViews();
        else VisibleCount = Mode == ListMode.Grouped ? AppsView.Count : ConnectionsView.Count;
        IsLoading = false;
    }

    public void ApplyThroughput(double up, double down)
    {
        UploadRate = Format.Rate(up);
        DownloadRate = Format.Rate(down);
        ThroughputSample?.Invoke(down, up);
    }

    [RelayCommand]
    private void SetFilter(QuickFilter f) => Filter = f;

    [RelayCommand]
    private void CloseDetails() => SelectedApp = null;

    [RelayCommand]
    private void ClearSearch() => SearchText = "";

    [RelayCommand]
    private async Task Block(AppItemViewModel? app)
    {
        app ??= SelectedApp;
        if (app is null) return;
        var s = _host.Settings.Current;
        if (s.ReadOnlyMode)
        {
            _main.Toast("Read-only mode is on — firewall changes are disabled.", "Warning");
            return;
        }
        if (!app.CanBlock || app.Path is null)
        {
            _main.Toast(app.BlockRefusal ?? "This application cannot be blocked.", "Warning");
            return;
        }

        if (s.RequireBlockConfirmation)
        {
            var ruleName = RuleNaming.BuildName(s.RulePrefix, app.Path);
            var ok = await _main.ConfirmAsync(
                $"Block Internet access for {app.Name}?",
                $"An outbound Windows Defender Firewall rule will block every connection this executable makes:\n\n{app.Path}\n\nRule name: {ruleName}\n" +
                (Elevation.IsElevated ? "" : "\nWindows will ask for administrator permission.") +
                "\nYou can undo this at any time with Unblock.",
                "Block Application", danger: true);
            if (!ok) return;
        }

        app.IsBusy = true;
        var result = await _host.Firewall.BlockAsync(app.Path);
        app.IsBusy = false;
        if (result.Ok)
        {
            _host.Monitor.RecordUserAction(app.Path, app.Name, "Blocked", true);
            _main.Toast(result.Message, "Success");
            _main.Notify(NotificationKind.Blocked, "Application blocked", $"{app.Name} can no longer reach the Internet.");
        }
        else _main.Toast(result.Message, "Danger");
        _host.Monitor.RefreshNow();
    }

    [RelayCommand]
    private async Task Unblock(AppItemViewModel? app)
    {
        app ??= SelectedApp;
        if (app?.Path is null) return;
        if (_host.Settings.Current.ReadOnlyMode)
        {
            _main.Toast("Read-only mode is on — firewall changes are disabled.", "Warning");
            return;
        }
        app.IsBusy = true;
        var result = await _host.Firewall.UnblockAsync(app.Path);
        app.IsBusy = false;
        if (result.Ok) _host.Monitor.RecordUserAction(app.Path, app.Name, "Unblocked", false);
        _main.Toast(result.Message, result.Ok ? "Success" : "Danger");
        _host.Monitor.RefreshNow();
    }

    [RelayCommand]
    private void OpenLocation(AppItemViewModel? app)
    {
        app ??= SelectedApp;
        if (app?.Path is null || !File.Exists(app.Path)) { _main.Toast("The file location is not available.", "Warning"); return; }
        try
        {
            // ArgumentList: the path is passed as one argument, never parsed by a shell.
            var psi = new ProcessStartInfo("explorer.exe") { UseShellExecute = false };
            psi.ArgumentList.Add("/select," + app.Path);
            Process.Start(psi);
        }
        catch (Exception ex) { _main.Toast(FriendlyError.Describe(ex), "Danger"); }
    }

    [RelayCommand]
    private void CopyPath(AppItemViewModel? app)
    {
        app ??= SelectedApp;
        if (app?.Path is null) return;
        try { Clipboard.SetText(app.Path); _main.Toast("Path copied to the clipboard.", "Success"); }
        catch { _main.Toast("The clipboard is busy; try again.", "Warning"); }
    }

    [RelayCommand]
    private void CopyText(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;
        try { Clipboard.SetText(text); _main.Toast("Copied to the clipboard.", "Success"); } catch { }
    }
}
