using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using LANManager.Models;

namespace LANManager.Services;

public class TrayIconService : IDisposable
{
    private const int Size = 32;
    private readonly Queue<double> _sparklineHistory = new();
    private const int SparklinePoints = 20;

    private Icon? _lastIcon;

    public Icon GenerateNumeric(double downloadBps, double uploadBps)
    {
        var bmp = new Bitmap(Size, Size);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);

        // Background pill
        using var bgBrush = new SolidBrush(Color.FromArgb(220, 30, 30, 46));
        g.FillRectangle(bgBrush, 0, 0, Size, Size);

        var (value, unit) = FormatCompact(downloadBps);

        using var font = new Font("Segoe UI", 8.5f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var unitFont = new Font("Segoe UI", 6f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var brush = new SolidBrush(Color.FromArgb(34, 197, 94)); // green for download

        var valStr = value;
        var valSize = g.MeasureString(valStr, font);
        var unitSize = g.MeasureString(unit, unitFont);

        float totalH = valSize.Height + unitSize.Height - 2;
        float startY = (Size - totalH) / 2f;

        g.DrawString(valStr, font, brush,
            (Size - valSize.Width) / 2f, startY);
        using var unitBrush = new SolidBrush(Color.FromArgb(148, 163, 184));
        g.DrawString(unit, unitFont, unitBrush,
            (Size - unitSize.Width) / 2f, startY + valSize.Height - 2);

        return BitmapToIcon(bmp);
    }

    public Icon GenerateSparkline(double downloadBps)
    {
        _sparklineHistory.Enqueue(downloadBps);
        while (_sparklineHistory.Count > SparklinePoints) _sparklineHistory.Dequeue();

        var bmp = new Bitmap(Size, Size);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);

        using var bgBrush = new SolidBrush(Color.FromArgb(220, 30, 30, 46));
        g.FillRectangle(bgBrush, 0, 0, Size, Size);

        var samples = _sparklineHistory.ToArray();
        if (samples.Length < 2) return BitmapToIcon(bmp);

        double max = samples.Max();
        if (max <= 0) max = 1;

        int pad = 3;
        int w = Size - pad * 2;
        int h = Size - pad * 2;

        var points = samples.Select((v, i) => new PointF(
            pad + i * (w / (float)(samples.Length - 1)),
            pad + h - (float)(v / max * h)
        )).ToArray();

        // Fill under curve
        var fillPoints = points.Prepend(new PointF(points[0].X, Size - pad))
                               .Append(new PointF(points[^1].X, Size - pad))
                               .ToArray();
        using var fillBrush = new SolidBrush(Color.FromArgb(60, 34, 197, 94));
        g.FillPolygon(fillBrush, fillPoints);

        // Line
        using var pen = new Pen(Color.FromArgb(34, 197, 94), 1.5f);
        g.DrawLines(pen, points);

        // Dot at latest point
        var last = points[^1];
        using var dotBrush = new SolidBrush(Color.White);
        g.FillEllipse(dotBrush, last.X - 1.5f, last.Y - 1.5f, 3, 3);

        return BitmapToIcon(bmp);
    }

    private static (string value, string unit) FormatCompact(double bps) => bps switch
    {
        >= 1_000_000 => ($"{bps / 1_000_000:F1}", "MB/s"),
        >= 1_000 => ($"{bps / 1_000:F0}", "KB/s"),
        _ => ($"{bps:F0}", "B/s")
    };

    private Icon BitmapToIcon(Bitmap bmp)
    {
        _lastIcon?.Dispose();
        var ptr = bmp.GetHicon();
        _lastIcon = Icon.FromHandle(ptr);
        return _lastIcon;
    }

    public void Dispose() => _lastIcon?.Dispose();
}
