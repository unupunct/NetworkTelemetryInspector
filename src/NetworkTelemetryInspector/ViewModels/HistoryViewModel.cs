using System.Globalization;
using System.Text;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

public sealed record HistoryRow(string Time, string Application, string Pid, string RemoteAddress, string Hostname, string Port,
    string Protocol, string Action, string Status, bool IsBlocked, HistoryEntry Entry);

public sealed partial class HistoryViewModel : ObservableObject
{
    private const int MaxRows = 5000;
    private readonly AppHost _host;
    private readonly MainViewModel _main;
    private readonly DispatcherTimer _debounce;
    private bool _dirty;

    public HistoryViewModel(AppHost host, MainViewModel main)
    {
        _host = host;
        _main = main;
        _debounce = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(200) };
        _debounce.Tick += (_, _) => { _debounce.Stop(); Reload(); };
        // History grows constantly; refresh at most every 3 s and only while the page is open.
        host.History.Changed += () => _dirty = true;
        var live = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(3) };
        live.Tick += (_, _) => { if (_dirty && _main.CurrentPage == Page.History && AutoRefresh) Reload(); };
        live.Start();
    }

    public IReadOnlyList<string> DateOptions { get; } = ["All dates", "Last hour", "Today", "Yesterday", "Last 7 days"];
    public IReadOnlyList<string> StatusOptions { get; } = ["Blocked and allowed", "Allowed", "Blocked"];
    public IReadOnlyList<string> ProtocolOptions { get; } = ["All protocols", "TCP", "UDP"];

    [ObservableProperty] private IReadOnlyList<HistoryRow> _rows = [];
    [ObservableProperty] private string _applicationFilter = "";
    [ObservableProperty] private string _ipFilter = "";
    [ObservableProperty] private string _hostnameFilter = "";
    [ObservableProperty] private string _dateFilter = "All dates";
    [ObservableProperty] private string _statusFilter = "Blocked and allowed";
    [ObservableProperty] private string _protocolFilter = "All protocols";
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private bool _autoRefresh = true;

    public bool RecordingEnabled => _host.Settings.Current.RecordHistory;
    public string StorageNote => $"Stored only on this PC in {AppPaths.History}. Kept for {_host.Settings.Current.HistoryRetentionDays} days.";

    partial void OnApplicationFilterChanged(string value) => Debounce();
    partial void OnIpFilterChanged(string value) => Debounce();
    partial void OnHostnameFilterChanged(string value) => Debounce();
    partial void OnDateFilterChanged(string value) => Reload();
    partial void OnStatusFilterChanged(string value) => Reload();
    partial void OnProtocolFilterChanged(string value) => Reload();

    private void Debounce()
    {
        _debounce.Stop();
        _debounce.Start();
    }

    public HistoryFilter BuildFilter()
    {
        var f = new HistoryFilter
        {
            Application = ApplicationFilter,
            Ip = IpFilter,
            Hostname = HostnameFilter,
            Status = StatusFilter switch { "Allowed" => "Allowed", "Blocked" => "Blocked", _ => null },
            Protocol = ProtocolFilter switch { "TCP" => "TCP", "UDP" => "UDP", _ => null }
        };
        var today = DateTime.Today;
        switch (DateFilter)
        {
            case "Last hour": f.From = DateTime.Now.AddHours(-1); break;
            case "Today": f.From = today; break;
            case "Yesterday": f.From = today.AddDays(-1); f.To = today; break;
            case "Last 7 days": f.From = today.AddDays(-6); break;
        }
        return f;
    }

    public void Reload()
    {
        _dirty = false;
        try
        {
            var list = _host.History.Query(BuildFilter(), MaxRows);
            Rows = list.Select(e => new HistoryRow(
                e.Time.ToString("yyyy-MM-dd HH:mm:ss"), e.Application, e.Pid == 0 ? "—" : e.Pid.ToString(),
                string.IsNullOrEmpty(e.RemoteAddress) ? "—" : e.RemoteAddress, e.Hostname ?? "", e.Port == 0 ? "—" : e.Port.ToString(),
                e.Protocol, ActionText(e.Action), e.Status, e.Status == "Blocked", e)).ToList();
            var total = _host.History.Count;
            Summary = list.Count >= MaxRows
                ? $"Showing the newest {MaxRows:N0} matching events ({total:N0} in memory). Narrow the filters to see older ones."
                : $"{list.Count:N0} matching events ({total:N0} recorded).";
        }
        catch (Exception ex)
        {
            Log.Error("History", "History query failed", ex);
            Summary = "History could not be displayed.";
        }
        OnPropertyChanged(nameof(RecordingEnabled));
        OnPropertyChanged(nameof(StorageNote));
    }

    private static string ActionText(string a) => a switch
    {
        "Opened" => "Connection opened",
        "Closed" => "Connection closed",
        "BlockedAttempt" => "Blocked attempt",
        "Blocked" => "Application blocked",
        "Unblocked" => "Application unblocked",
        "RuleDeleted" => "Rule deleted",
        _ => a
    };

    [RelayCommand]
    private void ResetFilters()
    {
        ApplicationFilter = IpFilter = HostnameFilter = "";
        DateFilter = "All dates";
        StatusFilter = "Blocked and allowed";
        ProtocolFilter = "All protocols";
        Reload();
    }

    [RelayCommand]
    private async Task Clear()
    {
        if (!await _main.ConfirmAsync("Clear connection history?",
                $"All {_host.History.Count:N0} recorded events and the history files on this PC will be permanently deleted.", "Clear History", true)) return;
        _host.History.Clear();
        Reload();
        _main.Toast("Connection history cleared.", "Success");
    }

    [RelayCommand]
    private void Export()
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export connection history",
            Filter = "CSV file (*.csv)|*.csv",
            FileName = $"nti-history-{DateTime.Now:yyyyMMdd-HHmm}.csv"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var sb = new StringBuilder("Time,Application,Path,PID,RemoteAddress,Hostname,Port,Protocol,Action,Status\r\n");
            foreach (var r in _host.History.Query(BuildFilter(), int.MaxValue))
            {
                sb.Append(Csv(r.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
                  .Append(Csv(r.Application)).Append(',').Append(Csv(r.Path)).Append(',').Append(r.Pid).Append(',')
                  .Append(Csv(r.RemoteAddress)).Append(',').Append(Csv(r.Hostname)).Append(',').Append(r.Port).Append(',')
                  .Append(Csv(r.Protocol)).Append(',').Append(Csv(r.Action)).Append(',').Append(Csv(r.Status)).Append("\r\n");
            }
            File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
            _main.Toast("History exported to " + Path.GetFileName(dlg.FileName), "Success");
        }
        catch (Exception ex) { _main.Toast(FriendlyError.Describe(ex), "Danger"); }
    }

    /// <summary>CSV-escapes a field and neutralises spreadsheet formula injection.</summary>
    public static string Csv(string? v)
    {
        v ??= "";
        if (v.Length > 0 && "=+-@\t\r".Contains(v[0])) v = "'" + v;
        return v.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }
}
