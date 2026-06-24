using System.Net.NetworkInformation;
using LANManager.Models;

namespace LANManager.Services;

public class NetworkSpeedSample
{
    public DateTime Time { get; set; }
    public double UploadBps { get; set; }
    public double DownloadBps { get; set; }
    // Smoothed values (rolling average)
    public double SmoothedUploadBps { get; set; }
    public double SmoothedDownloadBps { get; set; }
}

public class NetworkSpeedService : IDisposable
{
    private System.Threading.Timer? _timer;
    private long _lastBytesSent;
    private long _lastBytesReceived;
    private DateTime _lastSampleTime;

    private readonly Queue<double> _uploadHistory = new();
    private readonly Queue<double> _downloadHistory = new();

    private AppSettings _settings;

    public event Action<NetworkSpeedSample>? SampleReady;

    public NetworkSpeedService(AppSettings settings)
    {
        _settings = settings;
        var iface = GetPrimaryInterface();
        if (iface != null)
        {
            var stats = iface.GetIPStatistics();
            _lastBytesSent = stats.BytesSent;
            _lastBytesReceived = stats.BytesReceived;
        }
        _lastSampleTime = DateTime.UtcNow;
        StartTimer();
    }

    private void StartTimer()
    {
        _timer?.Dispose();
        var interval = TimeSpan.FromSeconds(Math.Max(1, _settings.PollIntervalSeconds));
        _timer = new System.Threading.Timer(Sample, null, interval, interval);
    }

    public void ApplySettings(AppSettings settings)
    {
        _settings = settings;
        StartTimer();
    }

    private void Sample(object? _)
    {
        var iface = GetPrimaryInterface();
        if (iface == null) return;

        var stats = iface.GetIPStatistics();
        var now = DateTime.UtcNow;
        var elapsed = (now - _lastSampleTime).TotalSeconds;
        if (elapsed <= 0) return;

        var rawUp = Math.Max(0, (stats.BytesSent - _lastBytesSent) / elapsed);
        var rawDown = Math.Max(0, (stats.BytesReceived - _lastBytesReceived) / elapsed);

        _lastBytesSent = stats.BytesSent;
        _lastBytesReceived = stats.BytesReceived;
        _lastSampleTime = now;

        // Rolling average
        int window = Math.Max(1, _settings.SmoothingWindowSamples);
        _uploadHistory.Enqueue(rawUp);
        _downloadHistory.Enqueue(rawDown);
        while (_uploadHistory.Count > window) _uploadHistory.Dequeue();
        while (_downloadHistory.Count > window) _downloadHistory.Dequeue();

        SampleReady?.Invoke(new NetworkSpeedSample
        {
            Time = now,
            UploadBps = rawUp,
            DownloadBps = rawDown,
            SmoothedUploadBps = _uploadHistory.Average(),
            SmoothedDownloadBps = _downloadHistory.Average()
        });
    }

    private static NetworkInterface? GetPrimaryInterface() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .OrderByDescending(n => n.GetIPStatistics().BytesReceived)
            .FirstOrDefault();

    public void Dispose() => _timer?.Dispose();
}
