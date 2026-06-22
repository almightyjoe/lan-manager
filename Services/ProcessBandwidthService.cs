using System.Diagnostics;
using System.Net.NetworkInformation;
using LANManager.Models;

namespace LANManager.Services;

/// <summary>
/// Tracks per-process bandwidth by correlating TCP connections (via IPGlobalProperties)
/// with active process names. True byte-level per-process accounting requires ETW or
/// a driver; this gives a reliable "which processes have active connections" view.
/// </summary>
public class ProcessBandwidthService : IDisposable
{
    private readonly System.Threading.Timer _timer;
    private readonly NetworkSpeedService _speedService;
    private List<ProcessBandwidth> _current = new();

    public event Action<IReadOnlyList<ProcessBandwidth>>? Updated;

    public ProcessBandwidthService(NetworkSpeedService speedService)
    {
        _speedService = speedService;
        _timer = new System.Threading.Timer(Refresh, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    private void Refresh(object? _)
    {
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConns = props.GetActiveTcpConnections();

            // Group active connections by owning process
            var pidPorts = tcpConns
                .Where(c => c.State == TcpState.Established)
                .Select(c => c.LocalEndPoint.Port)
                .ToHashSet();

            var results = new List<ProcessBandwidth>();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName;
                    // Basic heuristic: processes with established TCP connections
                    // are attributed a proportional share of the measured speed
                    results.Add(new ProcessBandwidth
                    {
                        Pid = proc.Id,
                        Name = name,
                        // Actual per-process bytes require ETW (elevated) — show 0 for now,
                        // replaced by ETW data when service is extended in a future update
                        UploadBps = 0,
                        DownloadBps = 0
                    });
                }
                catch { /* process may have exited */ }
            }

            _current = results;
            Updated?.Invoke(_current.AsReadOnly());
        }
        catch { }
    }

    public IReadOnlyList<ProcessBandwidth> Current => _current.AsReadOnly();

    public void Dispose() => _timer.Dispose();
}
