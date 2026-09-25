using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetworkTelemetryInspector.ViewModels;

namespace NetworkTelemetryInspector.Views;

public partial class DashboardView : UserControl
{
    private DashboardViewModel? _vm;

    public DashboardView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_vm is not null) _vm.ThroughputSample -= OnSample;
            _vm = DataContext as DashboardViewModel;
            if (_vm is not null) _vm.ThroughputSample += OnSample;
        };
        SizeChanged += (_, e) =>
        {
            var narrow = e.NewSize.Width < 1180;
            Cards.Columns = narrow ? 2 : 3;
            Cards.Rows = narrow ? 3 : 2;
        };
        ListCard.SizeChanged += (_, e) => { if (_vm is not null) _vm.IsCompact = e.NewSize.Width < 960; };
        // Double-clicking an application row expands or collapses its connections.
        AppList.PreviewMouseDoubleClick += (_, e) =>
        {
            if (_vm?.SelectedApp is { } app && e.OriginalSource is FrameworkElement fe && fe.DataContext == app) app.IsExpanded = !app.IsExpanded;
        };
    }

    private void OnSample(double down, double up) => Graph.Push(down, up);

    public void FocusSearch()
    {
        SearchBox.Focus();
        SearchBox.SelectAll();
        Keyboard.Focus(SearchBox);
    }
}
