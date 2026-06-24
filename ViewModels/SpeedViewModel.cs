using System.Collections.ObjectModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using LANManager.Services;

namespace LANManager.ViewModels;

public class SpeedViewModel
{
    private const int MaxPoints = 60;

    private readonly ObservableCollection<ObservablePoint> _uploadPoints = new();
    private readonly ObservableCollection<ObservablePoint> _downloadPoints = new();
    private int _tick;

    public ISeries[] SpeedSeries { get; }

    public Axis[] XAxes { get; } =
    {
        new Axis
        {
            IsVisible = false,
            MinLimit = 0,
            MaxLimit = MaxPoints
        }
    };

    public Axis[] YAxes { get; } =
    {
        new Axis
        {
            Labeler = v => FormatBps(v),
            MinLimit = 0,
            TextSize = 10,
            LabelsPaint = new SolidColorPaint(new SKColor(148, 163, 184))
        }
    };

    public SpeedViewModel()
    {
        SpeedSeries = new ISeries[]
        {
            new LineSeries<ObservablePoint>
            {
                Name = "Upload",
                Values = _uploadPoints,
                Stroke = new SolidColorPaint(new SKColor(167, 139, 250), 2),
                Fill = new LinearGradientPaint(
                    new[] { new SKColor(124, 58, 237, 80), new SKColor(124, 58, 237, 0) },
                    new SKPoint(0.5f, 0), new SKPoint(0.5f, 1)),
                GeometrySize = 0,
                LineSmoothness = 0.5
            },
            new LineSeries<ObservablePoint>
            {
                Name = "Download",
                Values = _downloadPoints,
                Stroke = new SolidColorPaint(new SKColor(34, 197, 94), 2),
                Fill = new LinearGradientPaint(
                    new[] { new SKColor(34, 197, 94, 80), new SKColor(34, 197, 94, 0) },
                    new SKPoint(0.5f, 0), new SKPoint(0.5f, 1)),
                GeometrySize = 0,
                LineSmoothness = 0.5
            }
        };
    }

    public void AddSample(NetworkSpeedSample s)
    {
        _uploadPoints.Add(new ObservablePoint(_tick, s.SmoothedUploadBps));
        _downloadPoints.Add(new ObservablePoint(_tick, s.SmoothedDownloadBps));
        _tick++;

        while (_uploadPoints.Count > MaxPoints) _uploadPoints.RemoveAt(0);
        while (_downloadPoints.Count > MaxPoints) _downloadPoints.RemoveAt(0);

        XAxes[0].MinLimit = _tick - MaxPoints;
        XAxes[0].MaxLimit = _tick;
    }

    private static string FormatBps(double bps) => bps switch
    {
        >= 1_000_000 => $"{bps / 1_000_000:F0}M",
        >= 1_000 => $"{bps / 1_000:F0}K",
        _ => $"{bps:F0}B"
    };
}
