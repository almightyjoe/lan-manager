namespace LANManager.Models;

public class ProcessBandwidth
{
    public int Pid { get; set; }
    public string Name { get; set; } = string.Empty;
    public double UploadBps { get; set; }
    public double DownloadBps { get; set; }
    public double TotalBps => UploadBps + DownloadBps;

    public string UploadFormatted => FormatBps(UploadBps);
    public string DownloadFormatted => FormatBps(DownloadBps);

    private static string FormatBps(double bps) => bps switch
    {
        >= 1_000_000 => $"{bps / 1_000_000:F1} MB/s",
        >= 1_000 => $"{bps / 1_000:F1} KB/s",
        _ => $"{bps:F0} B/s"
    };
}
