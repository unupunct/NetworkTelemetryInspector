using System.Collections.Concurrent;
using System.Text;

namespace NetworkTelemetryInspector.Utilities;

public enum LogLevel { Debug, Info, Warning, Error }

public sealed record LogEntry(DateTime Time, LogLevel Level, string Source, string Message);

/// <summary>
/// Local, file-based application log (logs\nti-yyyyMMdd.log). Writes are queued and flushed on a
/// background thread so logging never blocks the UI. Nothing is ever sent anywhere.
/// </summary>
public static class Log
{
    private static readonly BlockingCollection<LogEntry> Queue = new(new ConcurrentQueue<LogEntry>(), 5000);
    private static readonly ConcurrentQueue<LogEntry> RecentEntries = new();
    private static Thread? _writer;
    private static readonly object StartLock = new();

    public static event Action<LogEntry>? EntryWritten;

    public static LogLevel MinimumLevel { get; set; } = LogLevel.Info;

    public static IReadOnlyList<LogEntry> Recent => RecentEntries.ToArray();

    public static string CurrentFile => Path.Combine(AppPaths.Logs, $"nti-{DateTime.Now:yyyyMMdd}.log");

    public static void Debug(string source, string message) => Write(LogLevel.Debug, source, message);
    public static void Info(string source, string message) => Write(LogLevel.Info, source, message);
    public static void Warn(string source, string message) => Write(LogLevel.Warning, source, message);
    public static void Error(string source, string message) => Write(LogLevel.Error, source, message);

    public static void Error(string source, string message, Exception ex) =>
        Write(LogLevel.Error, source, message + " | " + ex.GetType().Name + ": " + ex.Message +
              (ex.StackTrace is { } st ? Environment.NewLine + st : ""));

    public static void Write(LogLevel level, string source, string message)
    {
        if (level < MinimumLevel) return;
        var entry = new LogEntry(DateTime.Now, level, source, message);
        RecentEntries.Enqueue(entry);
        while (RecentEntries.Count > 300 && RecentEntries.TryDequeue(out _)) { }
        EnsureWriter();
        Queue.TryAdd(entry);
        try { EntryWritten?.Invoke(entry); } catch { /* listeners must never break logging */ }
    }

    private static void EnsureWriter()
    {
        if (_writer is not null) return;
        lock (StartLock)
        {
            if (_writer is not null) return;
            _writer = new Thread(WriterLoop) { IsBackground = true, Name = "NTI log writer", Priority = ThreadPriority.BelowNormal };
            _writer.Start();
        }
    }

    private static void WriterLoop()
    {
        var sb = new StringBuilder();
        foreach (var first in Queue.GetConsumingEnumerable())
        {
            sb.Clear();
            Append(sb, first);
            while (Queue.TryTake(out var more)) Append(sb, more);
            try
            {
                Directory.CreateDirectory(AppPaths.Logs);
                File.AppendAllText(CurrentFile, sb.ToString(), Encoding.UTF8);
            }
            catch { /* disk full / locked: the in-memory tail is still available */ }
        }
    }

    private static void Append(StringBuilder sb, LogEntry e) =>
        sb.Append(e.Time.ToString("yyyy-MM-dd HH:mm:ss.fff")).Append(" [").Append(e.Level.ToString().ToUpperInvariant())
          .Append("] ").Append(e.Source).Append(": ").AppendLine(e.Message);

    /// <summary>Blocks briefly until queued entries reach disk (used on exit and by headless modes).</summary>
    public static void Flush(int timeoutMs = 1500)
    {
        var until = Environment.TickCount64 + timeoutMs;
        while (Queue.Count > 0 && Environment.TickCount64 < until) Thread.Sleep(20);
        Thread.Sleep(30);
    }

    /// <summary>Removes log files older than the given number of days.</summary>
    public static void Prune(int keepDays)
    {
        try
        {
            if (!Directory.Exists(AppPaths.Logs)) return;
            foreach (var f in Directory.EnumerateFiles(AppPaths.Logs, "nti-*.log"))
            {
                if (File.GetLastWriteTime(f) < DateTime.Now.AddDays(-keepDays)) File.Delete(f);
            }
        }
        catch { }
    }
}

/// <summary>Turns exceptions into short messages suitable for normal users (no stack traces).</summary>
public static class FriendlyError
{
    public static string Describe(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "Access was denied. This action may require administrator rights.",
        System.ComponentModel.Win32Exception { NativeErrorCode: 1223 } => "The administrator prompt was cancelled.",
        System.ComponentModel.Win32Exception w => $"Windows reported an error ({w.NativeErrorCode}): {w.Message}",
        System.Runtime.InteropServices.COMException c when (uint)c.HResult == 0x80070005 => "Access was denied by Windows Firewall. Administrator rights are required.",
        System.Runtime.InteropServices.COMException c => $"Windows Firewall reported an error (0x{c.HResult:X8}).",
        TimeoutException => "The operation timed out.",
        IOException io => "A file could not be read or written: " + io.Message,
        OperationCanceledException => "The operation was cancelled.",
        _ => ex.Message
    };
}
