using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.ViewModels;

public sealed record AdapterItem(
    string Name, string Description, string Type, string Status, string StatusTone, string Speed, bool IsPrimary, bool IsVpn,
    string IPv4, string IPv6, string Gateway, string Dns, string Mac, string TypeGlyph);

public sealed partial class NetworkViewModel : ObservableObject
{
    private readonly AppHost _host;
    private readonly MainViewModel _main;

    public NetworkViewModel(AppHost host, MainViewModel main)
    {
        _host = host;
        _main = main;
    }

    public ObservableCollection<AdapterItem> Adapters { get; } = new();

    [ObservableProperty] private bool _showInactive;
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private bool _isBusy;
    private List<AdapterInfo> _all = new();

    partial void OnShowInactiveChanged(bool value) => Rebuild();

    public void SetAdapters(List<AdapterInfo> adapters)
    {
        _all = adapters;
        Rebuild();
    }

    private void Rebuild()
    {
        Adapters.Clear();
        foreach (var a in _all.Where(a => ShowInactive || a.Status == "Up"))
        {
            Adapters.Add(new AdapterItem(
                a.Name, a.Description, a.Type,
                a.Status == "Up" ? "Connected" : a.Status,
                a.Status == "Up" ? "Success" : "Neutral",
                Format.LinkSpeed(a.Speed), a.IsPrimary, a.IsVpn,
                a.IPv4.Count == 0 ? "—" : string.Join("\n", a.IPv4),
                a.IPv6.Count == 0 ? "—" : string.Join("\n", a.IPv6),
                a.Gateways.Count == 0 ? "—" : string.Join("\n", a.Gateways),
                a.DnsServers.Count == 0 ? "—" : string.Join("\n", a.DnsServers),
                string.IsNullOrEmpty(a.Mac) ? "—" : a.Mac,
                a.Type switch { "Wi-Fi" => "\uE701", "VPN" => "\uE705", "Ethernet" => "\uE839", _ => "\uE968" }));
        }
        var up = _all.Count(a => a.Status == "Up");
        var primary = _all.FirstOrDefault(a => a.IsPrimary);
        Summary = $"{_all.Count} adapter{(_all.Count == 1 ? "" : "s")}, {up} connected" + (primary is null ? ". No adapter currently routes Internet traffic." : $". Internet traffic uses {primary.Name} ({primary.Type}).");
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var list = await Task.Run(_host.Adapters.GetAdapters);
            SetAdapters(list);
        }
        catch (Exception ex) { _main.Toast(FriendlyError.Describe(ex), "Danger"); }
        IsBusy = false;
    }
}
