using System.IO;
using System.Text.Json;

namespace LANManager.Models;

public class AppSettings
{
    public int PollIntervalSeconds { get; set; } = 1;
    public int SmoothingWindowSamples { get; set; } = 4;
    public TrayDisplayMode TrayDisplay { get; set; } = TrayDisplayMode.Numeric;
    public string SpeedUnit { get; set; } = "Auto"; // Auto, KB/s, MB/s
    public List<BandwidthAlert> Alerts { get; set; } = new();

    private static readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "LANManager", "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (!File.Exists(_path)) return new AppSettings();
            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch { return new AppSettings(); }
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

public enum TrayDisplayMode
{
    Numeric,
    Sparkline
}
