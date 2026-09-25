using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Firewall;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

public sealed partial class FirewallRuleItem : ObservableObject
{
    public required FirewallRuleInfo Rule { get; init; }
    public ImageSource? Icon { get; init; }
    public string Name => Rule.Name;
    public string Application => Rule.ApplicationName;
    public string Path => Rule.ApplicationPath ?? "";
    public string Direction => Rule.Direction;
    public string Action => Rule.Action;
    public bool Enabled => Rule.Enabled;
    public string EnabledText => Rule.Enabled ? "Yes" : "No";
    public string ToggleText => Rule.Enabled ? "Disable" : "Enable";
    public bool FileMissing => Rule.ApplicationPath is not null && !File.Exists(Rule.ApplicationPath);
    [ObservableProperty] private bool _isBusy;
}

public sealed partial class FirewallViewModel : ObservableObject
{
    private readonly AppHost _host;
    private readonly MainViewModel _main;

    public FirewallViewModel(AppHost host, MainViewModel main)
    {
        _host = host;
        _main = main;
        host.Firewall.RulesChanged += () => System.Windows.Application.Current?.Dispatcher.BeginInvoke(Sync);
    }

    public ObservableCollection<FirewallRuleItem> Rules { get; } = new();

    [ObservableProperty] private string _firewallState = "Checking…";
    [ObservableProperty] private string _firewallTone = "Neutral";
    [ObservableProperty] private string? _readError;
    [ObservableProperty] private int _ruleCount;
    [ObservableProperty] private bool _isBusy;

    public string ElevationNote => Elevation.IsElevated
        ? "Running as administrator: rule changes apply immediately."
        : "Creating, changing or removing rules requires administrator rights. Windows asks for permission each time you make a change; monitoring itself never needs it.";

    public string OwnershipNote =>
        $"Only rules created by this application are listed or changed. They are identified by the Windows Firewall group \"{RuleNaming.Group}\" and the {RuleNaming.Marker} marker in the description — never by name alone. Your own rules and Windows' built-in rules are never touched.";

    private void Sync()
    {
        var fw = _host.Firewall;
        ReadError = fw.LastReadError;
        (FirewallState, FirewallTone) = fw.FirewallEnabled switch
        {
            true => ("Windows Defender Firewall is on", "Success"),
            false => ("Windows Defender Firewall is OFF for the active network profile — block rules have no effect until it is turned on", "Danger"),
            _ => ("Windows Defender Firewall state unavailable", "Warning")
        };
        Rules.Clear();
        foreach (var r in fw.Rules)
            Rules.Add(new FirewallRuleItem { Rule = r, Icon = _host.Processes.Icon(r.ApplicationPath) });
        RuleCount = Rules.Count;
    }

    private bool Guard()
    {
        if (!_host.Settings.Current.ReadOnlyMode) return true;
        _main.Toast("Read-only mode is on — firewall changes are disabled.", "Warning");
        return false;
    }

    [RelayCommand]
    private async Task Refresh()
    {
        IsBusy = true;
        await _host.Firewall.RefreshAsync();
        IsBusy = false;
    }

    [RelayCommand]
    private async Task Toggle(FirewallRuleItem? item)
    {
        if (item is null || !Guard()) return;
        item.IsBusy = true;
        var r = await _host.Firewall.SetEnabledAsync(item.Name, !item.Enabled);
        _main.Toast(r.Message, r.Ok ? "Success" : "Danger");
        _host.Monitor.RefreshNow();
    }

    [RelayCommand]
    private async Task Delete(FirewallRuleItem? item)
    {
        if (item is null || !Guard()) return;
        if (!await _main.ConfirmAsync("Delete firewall rule?", $"Rule {item.Name} for {item.Application} will be removed from Windows Defender Firewall.", "Delete Rule", true)) return;
        item.IsBusy = true;
        var r = await _host.Firewall.DeleteAsync(item.Name);
        if (r.Ok) _host.Monitor.RecordUserAction(item.Rule.ApplicationPath, item.Application, "RuleDeleted", false);
        _main.Toast(r.Message, r.Ok ? "Success" : "Danger");
        _host.Monitor.RefreshNow();
    }

    [RelayCommand]
    private async Task Unblock(FirewallRuleItem? item)
    {
        if (item?.Rule.ApplicationPath is null || !Guard()) return;
        item.IsBusy = true;
        var r = await _host.Firewall.UnblockAsync(item.Rule.ApplicationPath);
        if (r.Ok) _host.Monitor.RecordUserAction(item.Rule.ApplicationPath, item.Application, "Unblocked", false);
        _main.Toast(r.Message, r.Ok ? "Success" : "Danger");
        _host.Monitor.RefreshNow();
    }

    [RelayCommand]
    private async Task RemoveAll()
    {
        if (!Guard()) return;
        if (!await _main.ConfirmAsync("Remove all Network & Telemetry Inspector rules?",
                $"All {RuleCount} rule(s) created by this application will be deleted and every application it blocked will regain Internet access.\n\nRules you created yourself and Windows' own rules are not affected.",
                "Remove All Rules", true)) return;
        IsBusy = true;
        var r = await _host.Firewall.RemoveAllAsync();
        IsBusy = false;
        _main.Toast(r.Message, r.Ok ? "Success" : "Danger");
        _host.Monitor.RefreshNow();
    }

    [RelayCommand]
    private void OpenWindowsFirewall()
    {
        try { Process.Start(new ProcessStartInfo("wf.msc") { UseShellExecute = true }); }
        catch (Exception ex) { _main.Toast(FriendlyError.Describe(ex), "Danger"); }
    }
}
