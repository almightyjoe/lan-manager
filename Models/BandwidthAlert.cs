namespace LANManager.Models;

public class BandwidthAlert
{
    public string ProcessName { get; set; } = string.Empty;
    public double ThresholdMbps { get; set; }
    public bool NotifyOnly { get; set; } = true;
    public bool IsEnabled { get; set; } = true;
}
