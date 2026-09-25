using System.Security.Principal;

namespace NetworkTelemetryInspector.Utilities;

public static class Elevation
{
    private static readonly Lazy<bool> Elevated = new(() =>
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    });

    public static bool IsElevated => Elevated.Value;

    /// <summary>
    /// Restarts this exe elevated (UAC). Returns false when the user cancelled the prompt.
    /// Only a fixed, application-owned argument is passed; no user text reaches the command line.
    /// </summary>
    public static bool RestartElevated(string? extraArgument = null)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(AppPaths.ExecutablePath)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = extraArgument ?? "--elevated-restart"
            };
            System.Diagnostics.Process.Start(psi);
            return true;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return false;
        }
    }
}
