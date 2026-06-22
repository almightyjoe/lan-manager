using LANManager.Models;

namespace LANManager.Services;

public class AlertService
{
    private readonly List<BandwidthAlert> _alerts = new();
    private readonly HashSet<string> _activeAlerts = new();

    public IReadOnlyList<BandwidthAlert> Alerts => _alerts.AsReadOnly();

    public event Action<string>? AlertTriggered;

    public void AddAlert(BandwidthAlert alert) => _alerts.Add(alert);
    public void RemoveAlert(BandwidthAlert alert) => _alerts.Remove(alert);

    public void Check(IReadOnlyList<ProcessBandwidth> processes)
    {
        foreach (var alert in _alerts.Where(a => a.IsEnabled))
        {
            var proc = processes.FirstOrDefault(p =>
                p.Name.Equals(alert.ProcessName, StringComparison.OrdinalIgnoreCase));

            if (proc == null) continue;

            var mbps = proc.TotalBps / 1_000_000.0;
            var key = alert.ProcessName;

            if (mbps > alert.ThresholdMbps && !_activeAlerts.Contains(key))
            {
                _activeAlerts.Add(key);
                AlertTriggered?.Invoke(
                    $"{alert.ProcessName} exceeded {alert.ThresholdMbps:F1} MB/s ({mbps:F1} MB/s current)");
            }
            else if (mbps <= alert.ThresholdMbps)
            {
                _activeAlerts.Remove(key);
            }
        }
    }
}
