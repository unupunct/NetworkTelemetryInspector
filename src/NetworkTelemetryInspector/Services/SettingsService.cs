using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using NetworkTelemetryInspector.Models;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Services;

public sealed class SettingsService
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public AppSettings Current { get; private set; } = new();

    public event Action<AppSettings>? Changed;

    public void Load()
    {
        try
        {
            if (File.Exists(AppPaths.Settings))
            {
                Current = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(AppPaths.Settings), Json) ?? new AppSettings();
            }
        }
        catch (Exception ex)
        {
            Log.Warn("Settings", "Settings file unreadable, defaults used: " + ex.Message);
            Current = new AppSettings();
        }
        Current.Normalize();
    }

    public void Save(AppSettings updated)
    {
        updated.Normalize();
        Current = updated;
        try
        {
            AppPaths.EnsureCreated();
            var tmp = AppPaths.Settings + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(updated, Json));
            File.Move(tmp, AppPaths.Settings, overwrite: true);
        }
        catch (Exception ex) { Log.Error("Settings", "Settings could not be saved: " + ex.Message); }
        try { AutoStart.Apply(updated.StartWithWindows); } catch (Exception ex) { Log.Warn("Settings", "Autostart: " + ex.Message); }
        Changed?.Invoke(updated);
    }

    public void Update(Action<AppSettings> change)
    {
        var copy = Current.Clone();
        change(copy);
        Save(copy);
    }
}

/// <summary>Per-user autostart via HKCU\...\Run (no admin, no scheduled task, easy to remove).</summary>
public static class AutoStart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "NetworkTelemetryInspector";

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(ValueName) is string;
    }

    public static void Apply(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
        if (enabled)
        {
            // Quoted so a path with spaces can never be split into a different program.
            key.SetValue(ValueName, "\"" + AppPaths.ExecutablePath + "\" --minimized", RegistryValueKind.String);
        }
        else if (key.GetValue(ValueName) is not null)
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }
}

/// <summary>Reads "AppsUseLightTheme" to support the Follow Windows appearance option.</summary>
public static class WindowsTheme
{
    public static bool IsLight()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 1;
        }
        catch { return false; }
    }
}
