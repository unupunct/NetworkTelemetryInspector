using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Network;

public enum HostnameSource { None, DnsCache, ReverseDns, Local }

public sealed record HostnameInfo(string? Name, HostnameSource Source);

/// <summary>
/// IP → hostname with two sources, in order of trust:
///  1. the local DNS client cache (what an app really looked up; zero network traffic);
///  2. reverse DNS (PTR), throttled to a few concurrent queries, cached with a TTL,
///     failures negatively cached — and only if the user allows it.
/// </summary>
public sealed class HostnameResolver
{
    private readonly DnsCacheReader _cache = new();
    private readonly ConcurrentDictionary<string, HostnameInfo> _byIp = new();
    private readonly ConcurrentDictionary<string, DateTime> _ptrExpiry = new();
    private readonly ConcurrentDictionary<string, byte> _pending = new();
    private readonly HashSet<string> _knownCacheNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _ptrSlots = new(4);
    private DateTime _lastCacheScan = DateTime.MinValue;
    private readonly object _scanLock = new();

    public bool ReverseLookupEnabled { get; set; } = true;
    public bool Enabled { get; set; } = true;

    /// <summary>Raised for each new name that appeared in the DNS cache: (name, addresses).</summary>
    public event Action<string, IReadOnlyList<string>>? DnsLookupObserved;

    /// <summary>Raised when a pending reverse lookup finishes, so the UI can refresh the row.</summary>
    public event Action<string>? Resolved;

    public HostnameInfo Get(string ip)
    {
        if (_byIp.TryGetValue(ip, out var info)) return info;
        if (NetworkAddress.IsLoopback(ip)) return new HostnameInfo("localhost", HostnameSource.Local);
        return new HostnameInfo(null, HostnameSource.None);
    }

    /// <summary>Scans the DNS cache at most every <paramref name="minInterval"/>. Call from a background thread.</summary>
    public void RefreshCache(TimeSpan minInterval)
    {
        if (!Enabled) return;
        lock (_scanLock)
        {
            if (DateTime.UtcNow - _lastCacheScan < minInterval) return;
            _lastCacheScan = DateTime.UtcNow;
            var first = _knownCacheNames.Count == 0;
            foreach (var name in _cache.ReadCachedNames())
            {
                if (_knownCacheNames.Contains(name)) continue;
                var addrs = _cache.CachedAddresses(name);
                if (addrs.Count == 0) continue; // negative / CNAME-only entry; retry on a later scan
                _knownCacheNames.Add(name);
                var list = new List<string>(addrs.Count);
                foreach (var a in addrs)
                {
                    var s = a.IsIPv4MappedToIPv6 ? a.MapToIPv4().ToString() : a.ToString();
                    list.Add(s);
                    // A DNS cache name always beats a PTR name for the same IP.
                    _byIp[s] = new HostnameInfo(name.TrimEnd('.').ToLowerInvariant(), HostnameSource.DnsCache);
                }
                if (!first) DnsLookupObserved?.Invoke(name, list);
            }
            if (_knownCacheNames.Count > 20000) _knownCacheNames.Clear();
        }
    }

    /// <summary>Queues a throttled reverse lookup when nothing better is known.</summary>
    public void Request(string ip)
    {
        if (!Enabled || !ReverseLookupEnabled) return;
        if (_byIp.TryGetValue(ip, out var known) && (known.Source == HostnameSource.DnsCache ||
            (_ptrExpiry.TryGetValue(ip, out var exp) && exp > DateTime.UtcNow))) return;
        if (NetworkAddress.IsLoopback(ip) || NetworkAddress.IsUnspecified(ip) || ip == "*") return;
        if (_pending.Count > 64 || !_pending.TryAdd(ip, 0)) return;

        _ = Task.Run(async () =>
        {
            await _ptrSlots.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!IPAddress.TryParse(ip, out var addr)) return;
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                var entry = await Dns.GetHostEntryAsync(addr.ToString(), AddressFamily.Unspecified, cts.Token).ConfigureAwait(false);
                var name = entry.HostName;
                if (!string.IsNullOrWhiteSpace(name) && name != ip)
                {
                    // Don't overwrite a DNS-cache name that arrived while we waited.
                    _byIp.AddOrUpdate(ip, new HostnameInfo(name.ToLowerInvariant(), HostnameSource.ReverseDns),
                        (_, old) => old.Source == HostnameSource.DnsCache ? old : new HostnameInfo(name.ToLowerInvariant(), HostnameSource.ReverseDns));
                }
                _ptrExpiry[ip] = DateTime.UtcNow.AddMinutes(30);
            }
            catch
            {
                // No PTR record / timeout: negative-cache so we don't ask again soon.
                _ptrExpiry[ip] = DateTime.UtcNow.AddMinutes(10);
            }
            finally
            {
                _ptrSlots.Release();
                _pending.TryRemove(ip, out _);
                try { Resolved?.Invoke(ip); } catch { }
            }
        });
    }

    public void Clear()
    {
        _byIp.Clear();
        _ptrExpiry.Clear();
        lock (_scanLock) _knownCacheNames.Clear();
    }
}
