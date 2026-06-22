namespace LANManager.Models;

public class LanDevice
{
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public DateTime LastSeen { get; set; }
    public bool IsOnline { get; set; }
}
