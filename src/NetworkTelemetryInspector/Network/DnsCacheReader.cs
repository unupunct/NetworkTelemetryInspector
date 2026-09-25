using System.Net;
using System.Runtime.InteropServices;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Network;

/// <summary>
/// Reads the local Windows DNS client cache — the names this PC has actually looked up —
/// and resolves each cached name to its cached addresses without sending any query on the wire
/// (DNS_QUERY_NO_WIRE_QUERY). This gives the hostname an application asked for
/// (e.g. "www.google.com") rather than the reverse-DNS name of a CDN edge.
///
/// DnsGetCacheDataTable is exported by dnsapi.dll but undocumented; any failure simply leaves
/// the cache map empty and the resolver falls back to reverse DNS (if the user allows it).
/// </summary>
public sealed unsafe class DnsCacheReader
{
    private const ushort DNS_TYPE_A = 1;
    private const ushort DNS_TYPE_AAAA = 28;
    private const uint DNS_QUERY_NO_WIRE_QUERY = 0x10;
    private const int DnsFreeFlat = 0;
    private const int DnsFreeRecordList = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_CACHE_ENTRY
    {
        public IntPtr pNext;
        public IntPtr pszName;
        public ushort wType;
        public ushort wDataLength;
        public uint dwFlags;
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    private static extern bool DnsGetCacheDataTable(out IntPtr table);

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
    private static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll")]
    private static extern void DnsFree(IntPtr data, int freeType);

    [DllImport("dnsapi.dll")]
    private static extern void DnsRecordListFree(IntPtr list, int freeType);

    private bool _broken;

    /// <summary>Names currently in the DNS client cache (A/AAAA/CNAME entries).</summary>
    public List<string> ReadCachedNames()
    {
        var names = new List<string>();
        if (_broken) return names;
        try
        {
            if (!DnsGetCacheDataTable(out var head) || head == IntPtr.Zero) return names;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var p = head;
            var guard = 0;
            while (p != IntPtr.Zero && guard++ < 20000)
            {
                var entry = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(p);
                if (entry.pszName != IntPtr.Zero)
                {
                    var name = Marshal.PtrToStringUni(entry.pszName);
                    if (!string.IsNullOrWhiteSpace(name) && seen.Add(name)) names.Add(name);
                    DnsFree(entry.pszName, DnsFreeFlat);
                }
                var next = entry.pNext;
                DnsFree(p, DnsFreeFlat);
                p = next;
            }
        }
        catch (Exception ex)
        {
            _broken = true;
            Log.Warn("DnsCache", "DNS client cache could not be read; hostnames will use reverse DNS only. " + ex.Message);
        }
        return names;
    }

    /// <summary>Addresses the cache holds for a name. Never generates network traffic.</summary>
    public List<IPAddress> CachedAddresses(string name)
    {
        var result = new List<IPAddress>();
        foreach (var type in new[] { DNS_TYPE_A, DNS_TYPE_AAAA })
        {
            IntPtr list = IntPtr.Zero;
            try
            {
                if (DnsQuery(name, type, DNS_QUERY_NO_WIRE_QUERY, IntPtr.Zero, out list, IntPtr.Zero) != 0 || list == IntPtr.Zero) continue;
                var p = (byte*)list;
                var guard = 0;
                while (p != null && guard++ < 256)
                {
                    // DNS_RECORD (x64): pNext(8) pName(8) wType(2) wDataLength(2) Flags(4) dwTtl(4) dwReserved(4) Data@32
                    var recType = *(ushort*)(p + 16);
                    if (recType == DNS_TYPE_A) result.Add(new IPAddress(*(uint*)(p + 32)));
                    else if (recType == DNS_TYPE_AAAA) result.Add(new IPAddress(new ReadOnlySpan<byte>(p + 32, 16)));
                    p = *(byte**)p;
                }
            }
            catch { /* malformed record: skip the name */ }
            finally
            {
                if (list != IntPtr.Zero) DnsRecordListFree(list, DnsFreeRecordList);
            }
        }
        return result;
    }
}
