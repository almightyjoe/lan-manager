using System.Net.NetworkInformation;

namespace LANManager.Services;

public class NetworkSpeedSample
{
    public DateTime Time { get; set; }
    public double UploadBps { get; set; }
    public double DownloadBps { get; set; }
}

public class NetworkSpeedService : IDisposable
{
    private readonly System.Threading.Timer _timer;
    private long _lastBytesSent;
    private long _lastBytesReceived;
    private DateTime _lastSampleTime;

    public event Action<NetworkSpeedSample>? SampleReady;

    public NetworkSpeedService()
    {
        var iface = GetPrimaryInterface();
        if (iface != null)
        {
            var stats = iface.GetIPStatistics();
            _lastBytesSent = stats.BytesSent;
            _lastBytesReceived = stats.BytesReceived;
        }
        _lastSampleTime = DateTime.UtcNow;
        _timer = new System.Threading.Timer(Sample, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    private void Sample(object? _)
    {
        var iface = GetPrimaryInterface();
        if (iface == null) return;

        var stats = iface.GetIPStatistics();
        var now = DateTime.UtcNow;
        var elapsed = (now - _lastSampleTime).TotalSeconds;

        var upload = (stats.BytesSent - _lastBytesSent) / elapsed;
        var download = (stats.BytesReceived - _lastBytesReceived) / elapsed;

        _lastBytesSent = stats.BytesSent;
        _lastBytesReceived = stats.BytesReceived;
        _lastSampleTime = now;

        SampleReady?.Invoke(new NetworkSpeedSample
        {
            Time = now,
            UploadBps = Math.Max(0, upload),
            DownloadBps = Math.Max(0, download)
        });
    }

    private static NetworkInterface? GetPrimaryInterface() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .OrderByDescending(n => n.GetIPStatistics().BytesReceived)
            .FirstOrDefault();

    public void Dispose() => _timer.Dispose();
}
