using System.Windows;
using System.Windows.Controls;
using NetworkTelemetryInspector.Models;

namespace NetworkTelemetryInspector.Controls;

/// <summary>Coloured label for an activity classification. Colours come from theme triggers, so they follow Dark/Light.</summary>
public sealed class ClassBadge : Control
{
    static ClassBadge() => DefaultStyleKeyProperty.OverrideMetadata(typeof(ClassBadge), new FrameworkPropertyMetadata(typeof(ClassBadge)));

    public static readonly DependencyProperty KindProperty = DependencyProperty.Register(nameof(Kind), typeof(ActivityClass), typeof(ClassBadge),
        new PropertyMetadata(ActivityClass.Unknown, (d, _) => ((ClassBadge)d).Text = ActivityClassText.Of(((ClassBadge)d).Kind)));

    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(nameof(Text), typeof(string), typeof(ClassBadge),
        new PropertyMetadata("Unknown"));

    public ActivityClass Kind { get => (ActivityClass)GetValue(KindProperty); set => SetValue(KindProperty, value); }
    public string Text { get => (string)GetValue(TextProperty); private set => SetValue(TextProperty, value); }
}

/// <summary>Generic small pill with a text and a tone (Accent, Success, Warning, Danger, Neutral).</summary>
public sealed class Pill : Control
{
    static Pill() => DefaultStyleKeyProperty.OverrideMetadata(typeof(Pill), new FrameworkPropertyMetadata(typeof(Pill)));

    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(nameof(Text), typeof(string), typeof(Pill), new PropertyMetadata(""));
    public static readonly DependencyProperty ToneProperty = DependencyProperty.Register(nameof(Tone), typeof(string), typeof(Pill), new PropertyMetadata("Neutral"));

    public string Text { get => (string)GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public string Tone { get => (string)GetValue(ToneProperty); set => SetValue(ToneProperty, value); }
}
