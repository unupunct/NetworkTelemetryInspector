using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using CommunityToolkit.Mvvm.Input;
using NetworkTelemetryInspector.Services;
using NetworkTelemetryInspector.ViewModels;

namespace NetworkTelemetryInspector.Views;

public partial class MainWindow : Window
{
    private readonly AppHost _host;
    private bool _allowClose;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    public MainWindow(MainViewModel vm, AppHost host)
    {
        _host = host;
        ViewModel = vm;
        DataContext = vm;
        FocusSearchCommand = new RelayCommand(() =>
        {
            vm.CurrentPage = Page.Dashboard;
            DashboardPage.FocusSearch();
        });
        InitializeComponent();
        SourceInitialized += (_, _) => ApplyTitleBarTheme(App.IsLightTheme);
        App.ThemeChanged += ApplyTitleBarTheme;
        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Minimized && _host.Settings.Current.MinimizeToTray && !App.IsHeadless) Hide();
        };
    }

    public MainViewModel ViewModel { get; }
    public ICommand FocusSearchCommand { get; }

    public void AllowClose() => _allowClose = true;

    protected override void OnClosing(CancelEventArgs e)
    {
        // Closing the window keeps monitoring in the tray when "Minimize to tray" is on.
        if (!_allowClose && !App.IsHeadless && _host.Settings.Current.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        if (!_allowClose && !App.IsHeadless)
        {
            _allowClose = true;
            Application.Current.Dispatcher.BeginInvoke(() => App.Current.ExitApplication());
        }
        base.OnClosing(e);
    }

    /// <summary>Native dark title bar (DWMWA_USE_IMMERSIVE_DARK_MODE) so the chrome matches the theme.</summary>
    private void ApplyTitleBarTheme(bool light)
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;
            var dark = light ? 0 : 1;
            if (DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, 19, ref dark, sizeof(int)); // pre-20H1 attribute id
        }
        catch { /* cosmetic only */ }
    }
}
