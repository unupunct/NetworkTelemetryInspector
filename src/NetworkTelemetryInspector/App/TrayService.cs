using System.Windows;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.Utilities;
using NetworkTelemetryInspector.ViewModels;
using Forms = System.Windows.Forms;

namespace NetworkTelemetryInspector;

/// <summary>System tray icon: Open / Pause / Resume / Read-only / Exit, and Windows notifications.</summary>
public sealed class TrayService : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _pause, _resume, _readOnly;
    private readonly MainViewModel _vm;
    private readonly AppHost _host;

    public TrayService(App app, MainViewModel vm, AppHost host)
    {
        _vm = vm;
        _host = host;
        _icon = new Forms.NotifyIcon
        {
            Text = "Network & Telemetry Inspector",
            Icon = LoadIcon(),
            Visible = true
        };

        var menu = new Forms.ContextMenuStrip { ShowImageMargin = false, ShowCheckMargin = true };
        var open = new Forms.ToolStripMenuItem("Open Inspector", null, (_, _) => app.ShowMainWindow()) { Font = new System.Drawing.Font(Forms.Control.DefaultFont, System.Drawing.FontStyle.Bold) };
        _pause = new Forms.ToolStripMenuItem("Pause Monitoring", null, (_, _) => host.Monitor.Pause());
        _resume = new Forms.ToolStripMenuItem("Resume Monitoring", null, (_, _) => host.Monitor.Resume());
        _readOnly = new Forms.ToolStripMenuItem("Read-only Mode", null, (_, _) => app.Dispatcher.Invoke(vm.ToggleReadOnly));
        var exit = new Forms.ToolStripMenuItem("Exit", null, (_, _) => app.Dispatcher.BeginInvoke(app.ExitApplication));
        menu.Items.AddRange([open, new Forms.ToolStripSeparator(), _pause, _resume, _readOnly, new Forms.ToolStripSeparator(), exit]);
        menu.Opening += (_, _) =>
        {
            _pause.Enabled = !host.Monitor.IsPaused;
            _resume.Enabled = host.Monitor.IsPaused;
            _readOnly.Checked = host.Settings.Current.ReadOnlyMode;
        };
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => app.ShowMainWindow();
        _icon.BalloonTipClicked += (_, _) => app.ShowMainWindow();
    }

    private static System.Drawing.Icon LoadIcon()
    {
        try
        {
            var res = Application.GetResourceStream(new Uri("pack://application:,,,/Resources/app.ico"));
            if (res is not null)
            {
                using var s = res.Stream;
                return new System.Drawing.Icon(s, Forms.SystemInformation.SmallIconSize);
            }
        }
        catch (Exception ex) { Log.Debug("Tray", "Icon: " + ex.Message); }
        return System.Drawing.SystemIcons.Application;
    }

    public void ShowBalloon(string title, string message)
    {
        try { _icon.ShowBalloonTip(5000, title, message, Forms.ToolTipIcon.None); }
        catch (Exception ex) { Log.Debug("Tray", "Notification failed: " + ex.Message); }
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
