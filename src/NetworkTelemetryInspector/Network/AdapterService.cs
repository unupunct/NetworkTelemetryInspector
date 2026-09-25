using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Network;

/// <summary>
/// Adapter inventory and machine-wide throughput. The primary adapter is the one Windows would
/// route Internet traffic through (GetBestInterface — a routing-table lookup, no packet is sent),
/// so Wi-Fi, Ethernet and VPN are all handled without assuming anything.
/// </summary>
public sealed class AdapterService
{
    [DllImport("iphlpapi.dll")]
    private static extern int GetBestInterface(uint destAddr, out uint bestIfIndex);

    private static readonly string[] VpnMarkers =
        ["vpn", "wireguard", "openvpn", "tap-windows", "tap adapter", "tun", "tailscale", "zerotier", "fortinet", "cisco anyconnect", "globalprotect", "pangp", "nordlynx", "wintun", "sonicwall", "juniper", "pulse secure", "hamachi", "proton"];

    private long _lastSent = -1, _lastReceived = -1;
    private long _lastTick;

    public static bool LooksLikeVpn(NetworkInterface ni)
    {
        if (ni.NetworkInterfaceType is NetworkInterfaceType.Ppp) return true;
        var text = (ni.Name + " " + ni.Description).ToLowerInvariant();
        return VpnMarkers.Any(m => text.Contains(m));
    }

    public List<AdapterInfo> GetAdapters()
    {
        var result = new List<AdapterInfo>();
        int? primaryIndex = PrimaryInterfaceIndex();
        NetworkInterface[] all;
        try { all = NetworkInterface.GetAllNetworkInterfaces(); }
        catch (Exception ex) { Log.Warn("Adapters", "Adapter list unavailable: " + ex.Message); return result; }

        foreach (var ni in all)
        {
            try
            {
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback) continue;
                var props = ni.GetIPProperties();
                int? index = null;
                try { index = props.GetIPv4Properties()?.Index; } catch { }
                if (index is null) try { index = props.GetIPv6Properties()?.Index; } catch { }

                var v4 = props.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address + "/" + a.PrefixLength).ToList();
                var v6 = props.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6)
                    .Select(a => a.Address.ToString()).ToList();

                result.Add(new AdapterInfo
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    Type = FriendlyType(ni),
                    Status = ni.OperationalStatus.ToString(),
                    Speed = SafeSpeed(ni),
                    IsPrimary = primaryIndex is not null && index == primaryIndex,
                    IsVpn = LooksLikeVpn(ni),
                    IPv4 = v4,
                    IPv6 = v6,
                    Gateways = props.GatewayAddresses.Select(g => g.Address.ToString()).Where(g => g != "0.0.0.0" && g != "::").ToList(),
                    DnsServers = props.DnsAddresses.Select(d => d.ToString()).ToList(),
                    Mac = FormatMac(ni.GetPhysicalAddress())
                });
            }
            catch (Exception ex)
            {
                // Adapter vanished mid-enumeration (VPN disconnect, USB NIC unplugged): skip it.
                Log.Debug("Adapters", ni.Name + ": " + ex.Message);
            }
        }
        return result
            .OrderByDescending(a => a.IsPrimary)
            .ThenByDescending(a => a.Status == "Up")
            .ThenBy(a => a.Name)
            .ToList();
    }

    private static long SafeSpeed(NetworkInterface ni)
    {
        try { return ni.OperationalStatus == OperationalStatus.Up ? ni.Speed : 0; } catch { return 0; }
    }

    private static int? PrimaryInterfaceIndex()
    {
        try
        {
            // 1.1.1.1 is used only as a routing-table lookup key: no traffic is generated.
            var dest = BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0);
            return GetBestInterface(dest, out var idx) == 0 ? (int)idx : null;
        }
        catch { return null; }
    }

    private static string FriendlyType(NetworkInterface ni)
    {
        if (LooksLikeVpn(ni)) return "VPN";
        return ni.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => "Wi-Fi",
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT
                or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.Ethernet3Megabit => "Ethernet",
            NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => "Mobile broadband",
            NetworkInterfaceType.Tunnel => "Tunnel",
            NetworkInterfaceType.Ppp => "VPN",
            _ => ni.NetworkInterfaceType.ToString()
        };
    }

    private static string FormatMac(PhysicalAddress mac)
    {
        var b = mac.GetAddressBytes();
        return b.Length == 0 ? "" : string.Join("-", b.Select(x => x.ToString("X2")));
    }

    /// <summary>
    /// Machine-wide bytes/sec since the previous call, summed over physical and VPN adapters that are up.
    /// Tunnel pseudo-interfaces (Teredo/ISATAP/6to4) are skipped to avoid double counting.
    /// </summary>
    public (double Up, double Down) SampleThroughput()
    {
        long sent = 0, received = 0;
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                    var s = ni.GetIPStatistics();
                    sent += s.BytesSent;
                    received += s.BytesReceived;
                }
                catch { /* adapter disappeared */ }
            }
        }
        catch { return (0, 0); }

        var now = Environment.TickCount64;
        double up = 0, down = 0;
        if (_lastSent >= 0 && now > _lastTick)
        {
            var secs = (now - _lastTick) / 1000.0;
            // Counters reset when an adapter goes away; never report a negative rate.
            up = Math.Max(0, sent - _lastSent) / secs;
            down = Math.Max(0, received - _lastReceived) / secs;
        }
        _lastSent = sent;
        _lastReceived = received;
        _lastTick = now;
        return (up, down);
    }
}

/// <summary>
/// Public IP lookup — the only outbound request this application ever makes, and only when
/// "Allow external public IP lookup" is on. It sends a bare GET with no identifying data.
/// </summary>
public sealed class PublicIpService
{
    public const string ServiceHost = "api.ipify.org";
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler { UseCookies = false, AllowAutoRedirect = false, UseProxy = true };
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(6) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("NTI/1.0");
        return c;
    }

    public async Task<string?> LookupAsync(bool allowed, CancellationToken ct)
    {
        if (!allowed) return null; // hard gate: disabled means the request is never made
        try
        {
            var text = (await Http.GetStringAsync("https://" + ServiceHost + "/", ct).ConfigureAwait(false)).Trim();
            return IPAddress.TryParse(text, out _) ? text : null;
        }
        catch (Exception ex)
        {
            Log.Info("PublicIp", "Public IP lookup failed: " + ex.Message);
            return null;
        }
    }
}
