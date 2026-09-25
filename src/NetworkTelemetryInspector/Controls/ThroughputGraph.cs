using System.Globalization;
using System.Windows;
using System.Windows.Media;
using NetworkTelemetryInspector.Utilities;

namespace NetworkTelemetryInspector.Controls;

/// <summary>
/// Rolling 60-second download/upload graph. Self-rendering (no chart library, no animation clock):
/// it redraws only when a new sample is pushed, i.e. once per second.
/// </summary>
public sealed class ThroughputGraph : FrameworkElement
{
    public const int Capacity = 60;
    private readonly double[] _down = new double[Capacity];
    private readonly double[] _up = new double[Capacity];
    private int _count;
    private int _head;

    public static readonly DependencyProperty DownBrushProperty = DependencyProperty.Register(nameof(DownBrush), typeof(Brush), typeof(ThroughputGraph),
        new FrameworkPropertyMetadata(Brushes.Cyan, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty UpBrushProperty = DependencyProperty.Register(nameof(UpBrush), typeof(Brush), typeof(ThroughputGraph),
        new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty GridBrushProperty = DependencyProperty.Register(nameof(GridBrush), typeof(Brush), typeof(ThroughputGraph),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty LabelBrushProperty = DependencyProperty.Register(nameof(LabelBrush), typeof(Brush), typeof(ThroughputGraph),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public Brush DownBrush { get => (Brush)GetValue(DownBrushProperty); set => SetValue(DownBrushProperty, value); }
    public Brush UpBrush { get => (Brush)GetValue(UpBrushProperty); set => SetValue(UpBrushProperty, value); }
    public Brush GridBrush { get => (Brush)GetValue(GridBrushProperty); set => SetValue(GridBrushProperty, value); }
    public Brush LabelBrush { get => (Brush)GetValue(LabelBrushProperty); set => SetValue(LabelBrushProperty, value); }

    public int SampleCount => _count;

    public void Push(double down, double up)
    {
        _down[_head] = down;
        _up[_head] = up;
        _head = (_head + 1) % Capacity;
        if (_count < Capacity) _count++;
        InvalidateVisual();
    }

    private double At(double[] series, int i) => series[(_head - _count + i + Capacity * 2) % Capacity];

    protected override void OnRender(DrawingContext dc)
    {
        var w = ActualWidth;
        var h = ActualHeight;
        if (w < 20 || h < 20) return;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        var max = 1024.0 * 8; // never scale below 8 KB/s so an idle link looks idle
        for (var i = 0; i < _count; i++) max = Math.Max(max, Math.Max(At(_down, i), At(_up, i)));
        max = NiceCeiling(max);

        var gridPen = new Pen(GridBrush, 1);
        gridPen.Freeze();
        var labelTop = 12.0;
        var plotH = h - labelTop;
        for (var g = 0; g <= 2; g++)
        {
            var y = Math.Round(labelTop + plotH * g / 2.0) + 0.5;
            dc.DrawLine(gridPen, new Point(0, y), new Point(w, y));
        }

        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var label = new FormattedText(Format.Rate(max), CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface("Segoe UI"), 10, LabelBrush, dpi);
        dc.DrawText(label, new Point(2, 0));

        if (_count < 2) return;
        DrawSeries(dc, _down, DownBrush, w, plotH, labelTop, max, fill: true);
        DrawSeries(dc, _up, UpBrush, w, plotH, labelTop, max, fill: false);
    }

    private void DrawSeries(DrawingContext dc, double[] series, Brush brush, double w, double plotH, double top, double max, bool fill)
    {
        var step = w / (Capacity - 1);
        var startX = w - step * (_count - 1);
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            for (var i = 0; i < _count; i++)
            {
                var p = new Point(startX + i * step, top + plotH - plotH * Math.Min(1, At(series, i) / max));
                if (i == 0) ctx.BeginFigure(p, false, false); else ctx.LineTo(p, true, true);
            }
        }
        geo.Freeze();
        var pen = new Pen(brush, 1.6) { LineJoin = PenLineJoin.Round };
        pen.Freeze();

        if (fill)
        {
            var area = new StreamGeometry();
            using (var ctx = area.Open())
            {
                ctx.BeginFigure(new Point(startX, top + plotH), true, true);
                for (var i = 0; i < _count; i++)
                    ctx.LineTo(new Point(startX + i * step, top + plotH - plotH * Math.Min(1, At(series, i) / max)), false, false);
                ctx.LineTo(new Point(startX + (_count - 1) * step, top + plotH), false, false);
            }
            area.Freeze();
            var fillBrush = brush.CloneCurrentValue();
            fillBrush.Opacity = 0.14;
            fillBrush.Freeze();
            dc.DrawGeometry(fillBrush, null, area);
        }
        dc.DrawGeometry(null, pen, geo);
    }

    private static double NiceCeiling(double v)
    {
        var exp = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1.0, 2.0, 2.5, 5.0, 10.0 })
            if (m * exp >= v) return m * exp;
        return 10 * exp;
    }
}
