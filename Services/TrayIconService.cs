using System.Drawing;
using System.Drawing.Drawing2D;

namespace LANManager.Services;

/// <summary>
/// Generates a colored activity-dot tray icon.
/// Green = idle, teal = moderate, yellow = busy, red = heavy.
/// </summary>
public class TrayIconService : IDisposable
{
    private const int Size = 32;

    private Icon? _lastIcon;
    private double _lastBps = -1;

    // Only regenerate the icon when the activity tier changes, not every sample
    public Icon GetActivityIcon(double downloadBps)
    {
        var tier = GetTier(downloadBps);
        var lastTier = GetTier(_lastBps);

        if (_lastIcon != null && tier == lastTier)
            return _lastIcon;

        _lastBps = downloadBps;
        return GenerateIcon(tier);
    }

    private Icon GenerateIcon(ActivityTier tier)
    {
        var bmp = new Bitmap(Size, Size);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);

        var (outerColor, innerColor) = tier switch
        {
            ActivityTier.Idle    => (Color.FromArgb(80, 100, 116, 139),  Color.FromArgb(100, 116, 139)),
            ActivityTier.Low     => (Color.FromArgb(80, 34, 197, 94),    Color.FromArgb(34, 197, 94)),
            ActivityTier.Medium  => (Color.FromArgb(80, 234, 179, 8),    Color.FromArgb(234, 179, 8)),
            ActivityTier.High    => (Color.FromArgb(80, 239, 68, 68),    Color.FromArgb(239, 68, 68)),
            _                    => (Color.FromArgb(80, 100, 116, 139),  Color.FromArgb(100, 116, 139))
        };

        // Outer glow
        using var glowBrush = new SolidBrush(outerColor);
        g.FillEllipse(glowBrush, 2, 2, Size - 4, Size - 4);

        // Inner filled dot
        int pad = 7;
        using var dotBrush = new SolidBrush(innerColor);
        g.FillEllipse(dotBrush, pad, pad, Size - pad * 2, Size - pad * 2);

        // Small white highlight
        using var highlightBrush = new SolidBrush(Color.FromArgb(80, 255, 255, 255));
        g.FillEllipse(highlightBrush, pad + 2, pad + 2, 5, 5);

        _lastIcon?.Dispose();
        _lastIcon = Icon.FromHandle(bmp.GetHicon());
        bmp.Dispose();
        return _lastIcon;
    }

    private static ActivityTier GetTier(double bps) => bps switch
    {
        < 0             => ActivityTier.Idle,
        < 10_000        => ActivityTier.Idle,     // < 10 KB/s
        < 1_000_000     => ActivityTier.Low,      // 10 KB/s – 1 MB/s
        < 10_000_000    => ActivityTier.Medium,   // 1 – 10 MB/s
        _               => ActivityTier.High      // > 10 MB/s
    };

    public void Dispose() => _lastIcon?.Dispose();

    private enum ActivityTier { Idle, Low, Medium, High }
}
