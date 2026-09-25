namespace NetworkTelemetryInspector.Utilities;

/// <summary>
/// Every file the application writes lives under %LOCALAPPDATA%\NetworkTelemetryInspector.
/// Nothing is written next to the executable, so the exe stays portable and read-only.
/// </summary>
public static class AppPaths
{
    public static string Root { get; private set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkTelemetryInspector");

    public static string Settings => Path.Combine(Root, "settings.json");
    public static string Rules => Path.Combine(Root, "classification-rules.json");
    public static string History => Path.Combine(Root, "history");
    public static string Logs => Path.Combine(Root, "logs");
    public static string Ipc => Path.Combine(Root, "ipc");

    /// <summary>Test hook: redirect all storage to a throwaway folder.</summary>
    public static void OverrideRoot(string root)
    {
        Root = root;
        IsOverridden = true;
    }

    public static bool IsOverridden { get; private set; }

    public static void EnsureCreated()
    {
        foreach (var dir in new[] { Root, History, Logs, Ipc })
        {
            try { Directory.CreateDirectory(dir); } catch { /* reported when the first write fails */ }
        }
    }

    /// <summary>The path of the running executable (the single-file exe when published).</summary>
    public static string ExecutablePath =>
        Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "NetworkTelemetryInspector.exe";
}
