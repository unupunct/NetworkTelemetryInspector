using System.Globalization;

namespace NetworkTelemetryInspector.Utilities;

public static class Format
{
    public const string Unavailable = "Information unavailable";

    public static string Rate(double bytesPerSecond)
    {
        if (double.IsNaN(bytesPerSecond) || bytesPerSecond < 0) return "—";
        return Bytes(bytesPerSecond) + "/s";
    }

    public static string Bytes(double bytes)
    {
        if (double.IsNaN(bytes) || bytes < 0) return "—";
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var i = 0;
        while (bytes >= 1024 && i < units.Length - 1) { bytes /= 1024; i++; }
        return i == 0
            ? bytes.ToString("0", CultureInfo.CurrentCulture) + " " + units[i]
            : bytes.ToString(bytes >= 100 ? "0" : bytes >= 10 ? "0.0" : "0.00", CultureInfo.CurrentCulture) + " " + units[i];
    }

    public static string LinkSpeed(long bitsPerSecond)
    {
        if (bitsPerSecond <= 0) return "Unknown";
        if (bitsPerSecond >= 1_000_000_000) return (bitsPerSecond / 1_000_000_000d).ToString("0.#", CultureInfo.CurrentCulture) + " Gbps";
        if (bitsPerSecond >= 1_000_000) return (bitsPerSecond / 1_000_000d).ToString("0.#", CultureInfo.CurrentCulture) + " Mbps";
        return (bitsPerSecond / 1000d).ToString("0.#", CultureInfo.CurrentCulture) + " Kbps";
    }

    public static string Ago(DateTime time)
    {
        var span = DateTime.Now - time;
        if (span.TotalSeconds < 5) return "now";
        if (span.TotalSeconds < 60) return $"{(int)span.TotalSeconds}s ago";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes}m ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours}h ago";
        return time.ToString("g", CultureInfo.CurrentCulture);
    }

    public static string Endpoint(string address, int port) =>
        address.Contains(':') ? $"[{address}]:{port}" : $"{address}:{port}";
}
