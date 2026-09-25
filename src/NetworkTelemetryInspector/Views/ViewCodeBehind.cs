using System.Windows;
using System.Windows.Controls;

namespace NetworkTelemetryInspector.Views;

public partial class FirewallView : UserControl
{
    public FirewallView() => InitializeComponent();
}

public partial class HistoryView : UserControl
{
    public HistoryView() => InitializeComponent();
}

public partial class NetworkView : UserControl
{
    public NetworkView() => InitializeComponent();
}

public partial class PrivacyView : UserControl
{
    public PrivacyView() => InitializeComponent();
}

public partial class SettingsView : UserControl
{
    public SettingsView() => InitializeComponent();
}

public partial class FirstRunStep : UserControl
{
    public static readonly DependencyProperty NumberProperty = DependencyProperty.Register(nameof(Number), typeof(string), typeof(FirstRunStep));
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(nameof(Title), typeof(string), typeof(FirstRunStep));
    public static readonly DependencyProperty DetailProperty = DependencyProperty.Register(nameof(Detail), typeof(string), typeof(FirstRunStep));

    public FirstRunStep() => InitializeComponent();

    public string Number { get => (string)GetValue(NumberProperty); set => SetValue(NumberProperty, value); }
    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string Detail { get => (string)GetValue(DetailProperty); set => SetValue(DetailProperty, value); }
}
