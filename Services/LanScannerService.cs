using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using LANManager.Models;

namespace LANManager.Services;

public class LanScannerService
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physAddrLen);

    public event Action<List<LanDevice>>? ScanComplete;
    private bool _scanning;

    public async Task ScanAsync(IProgress<int>? progress = null)
    {
        if (_scanning) return;
        _scanning = true;

        try
        {
            var localIp = GetLocalIp();
            if (localIp == null) return;

            var parts = localIp.Split('.');
            var subnet = $"{parts[0]}.{parts[1]}.{parts[2]}";

            var tasks = Enumerable.Range(1, 254).Select(i => PingHost($"{subnet}.{i}", progress));
            var results = await Task.WhenAll(tasks);
            var devices = results.Where(d => d != null).Cast<LanDevice>().ToList();

            ScanComplete?.Invoke(devices);
        }
        finally { _scanning = false; }
    }

    private async Task<LanDevice?> PingHost(string ip, IProgress<int>? progress)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, 500);
            progress?.Report(1);

            if (reply.Status != IPStatus.Success) return null;

            var mac = GetMac(ip);
            var hostname = await ResolveHostname(ip);

            return new LanDevice
            {
                IpAddress = ip,
                MacAddress = mac,
                Hostname = hostname,
                IsOnline = true,
                LastSeen = DateTime.Now
            };
        }
        catch { return null; }
    }

    private static string GetMac(string ip)
    {
        try
        {
            var dest = BitConverter.ToInt32(IPAddress.Parse(ip).GetAddressBytes(), 0);
            var mac = new byte[6];
            var len = 6;
            SendARP(dest, 0, mac, ref len);
            return string.Join(":", mac.Take(len).Select(b => b.ToString("X2")));
        }
        catch { return "Unknown"; }
    }

    private static async Task<string> ResolveHostname(string ip)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            return entry.HostName;
        }
        catch { return ip; }
    }

    private static string? GetLocalIp() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(a => a.Address.ToString())
            .FirstOrDefault();
}
