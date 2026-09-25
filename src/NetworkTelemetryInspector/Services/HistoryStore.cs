using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Services;

public sealed class HistoryFilter
{
    public string? Application { get; set; }
    public string? Ip { get; set; }
    public string? Hostname { get; set; }
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    /// <summary>null = any, "Blocked" or "Allowed".</summary>
    public string? Status { get; set; }
    /// <summary>null = any, "TCP" or "UDP" (matches v4 and v6).</summary>
    public string? Protocol { get; set; }

    public bool Matches(HistoryEntry e)
    {
        if (!string.IsNullOrWhiteSpace(Application) && !e.Application.Contains(Application.Trim(), StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrWhiteSpace(Ip) && !e.RemoteAddress.Contains(Ip.Trim(), StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrWhiteSpace(Hostname) && (e.Hostname is null || !e.Hostname.Contains(Hostname.Trim(), StringComparison.OrdinalIgnoreCase))) return false;
        if (From is { } f && e.Time < f) return false;
        if (To is { } t && e.Time >= t) return false;
        if (Status is not null && !string.Equals(e.Status, Status, StringComparison.OrdinalIgnoreCase)) return false;
        if (Protocol is not null && !e.Protocol.StartsWith(Protocol, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }
}

/// <summary>
/// Local connection history as one JSON-lines file per day (history\yyyy-MM-dd.jsonl).
/// Appends are queued and written in batches off the UI thread; the most recent entries are kept
/// in memory (bounded) for instant filtering. No database engine, no cloud.
/// </summary>
public sealed class HistoryStore : IDisposable
{
    public const int MemoryCap = 50_000;
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    private readonly LinkedList<HistoryEntry> _entries = new();
    private readonly object _lock = new();
    private readonly BlockingCollection<HistoryEntry> _pending = new(20_000);
    private readonly Thread _writer;
    private volatile bool _disposed;

    public HistoryStore()
    {
        _writer = new Thread(WriteLoop) { IsBackground = true, Name = "NTI history writer", Priority = ThreadPriority.BelowNormal };
        _writer.Start();
    }

    public bool Enabled { get; set; } = true;

    public event Action? Changed;

    public int Count { get { lock (_lock) return _entries.Count; } }

    public void Add(HistoryEntry entry)
    {
        if (!Enabled || _disposed) return;
        lock (_lock)
        {
            _entries.AddFirst(entry);
            while (_entries.Count > MemoryCap) _entries.RemoveLast();
        }
        _pending.TryAdd(entry);
    }

    public void NotifyChanged() => Changed?.Invoke();

    /// <summary>Newest first.</summary>
    public List<HistoryEntry> Query(HistoryFilter filter, int max = 5000)
    {
        var result = new List<HistoryEntry>(Math.Min(max, 1024));
        lock (_lock)
        {
            foreach (var e in _entries)
            {
                if (!filter.Matches(e)) continue;
                result.Add(e);
                if (result.Count >= max) break;
            }
        }
        return result;
    }

    /// <summary>Loads the retained days from disk (newest last in file → newest first in memory).</summary>
    public void Load(int retentionDays)
    {
        Prune(retentionDays);
        try
        {
            if (!Directory.Exists(AppPaths.History)) return;
            var files = Directory.EnumerateFiles(AppPaths.History, "*.jsonl").OrderBy(f => f, StringComparer.Ordinal).ToList();
            var loaded = new List<HistoryEntry>();
            foreach (var f in files)
            {
                try
                {
                    using var reader = new StreamReader(new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
                    string? line;
                    while ((line = reader.ReadLine()) is not null)
                    {
                        if (line.Length == 0) continue;
                        try { if (JsonSerializer.Deserialize<HistoryEntry>(line, Json) is { } e) loaded.Add(e); }
                        catch { /* one corrupt line (e.g. crash mid-write) must not lose the rest */ }
                    }
                }
                catch (Exception ex) { Log.Warn("History", Path.GetFileName(f) + ": " + ex.Message); }
            }
            lock (_lock)
            {
                foreach (var e in loaded.Skip(Math.Max(0, loaded.Count - MemoryCap))) _entries.AddFirst(e);
            }
        }
        catch (Exception ex) { Log.Warn("History", "History could not be loaded: " + ex.Message); }
    }

    public void Prune(int retentionDays)
    {
        try
        {
            if (!Directory.Exists(AppPaths.History)) return;
            var cutoff = DateTime.Today.AddDays(-retentionDays);
            foreach (var f in Directory.EnumerateFiles(AppPaths.History, "*.jsonl"))
            {
                if (DateTime.TryParseExact(Path.GetFileNameWithoutExtension(f), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day) && day < cutoff)
                    File.Delete(f);
            }
            lock (_lock)
            {
                while (_entries.Last is { } last && last.Value.Time < cutoff) _entries.RemoveLast();
            }
        }
        catch (Exception ex) { Log.Warn("History", "Retention cleanup failed: " + ex.Message); }
    }

    public void Clear()
    {
        lock (_lock) _entries.Clear();
        while (_pending.TryTake(out _)) { }
        try
        {
            if (Directory.Exists(AppPaths.History))
                foreach (var f in Directory.EnumerateFiles(AppPaths.History, "*.jsonl")) File.Delete(f);
        }
        catch (Exception ex) { Log.Warn("History", "History files could not be deleted: " + ex.Message); }
        Changed?.Invoke();
    }

    private void WriteLoop()
    {
        var byDay = new Dictionary<string, StringBuilder>();
        try
        {
            foreach (var first in _pending.GetConsumingEnumerable())
            {
                // Batch whatever else is queued, then write once per day file.
                Thread.Sleep(250);
                byDay.Clear();
                AppendTo(byDay, first);
                while (_pending.TryTake(out var more)) AppendTo(byDay, more);
                foreach (var (day, sb) in byDay)
                {
                    try
                    {
                        Directory.CreateDirectory(AppPaths.History);
                        File.AppendAllText(Path.Combine(AppPaths.History, day + ".jsonl"), sb.ToString(), Encoding.UTF8);
                    }
                    catch (Exception ex) { Log.Warn("History", "History write failed: " + ex.Message); }
                }
            }
        }
        catch (ObjectDisposedException) { }
        catch (InvalidOperationException) { }
    }

    private static void AppendTo(Dictionary<string, StringBuilder> byDay, HistoryEntry e)
    {
        var day = e.Time.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        if (!byDay.TryGetValue(day, out var sb)) byDay[day] = sb = new StringBuilder();
        sb.AppendLine(JsonSerializer.Serialize(e, Json));
    }

    public void Flush(int timeoutMs = 2000)
    {
        var until = Environment.TickCount64 + timeoutMs;
        while (_pending.Count > 0 && Environment.TickCount64 < until) Thread.Sleep(25);
        Thread.Sleep(300);
    }

    public void Dispose()
    {
        if (_disposed) return;
        Flush();
        _disposed = true;
        _pending.CompleteAdding();
    }
}
