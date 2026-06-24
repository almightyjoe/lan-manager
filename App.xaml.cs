using System.Windows;
using System.Windows.Forms;
using LANManager.Models;
using LANManager.Services;
using LANManager.Views;

namespace LANManager;

public partial class App : System.Windows.Application
{
    private NotifyIcon? _trayIcon;
    private MainWindow? _mainWindow;
    private NetworkSpeedService? _speedService;
    private TrayIconService? _trayIconService;
    private AppSettings _settings = AppSettings.Load();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        _trayIconService = new TrayIconService();
        _speedService = new NetworkSpeedService(_settings);
        _mainWindow = new MainWindow(_speedService, _settings);

        _trayIcon = new NotifyIcon
        {
            Text = "LAN Manager",
            Icon = SystemIcons.Application,
            Visible = true,
            ContextMenuStrip = BuildContextMenu()
        };

        _trayIcon.DoubleClick += (_, _) => ShowWindow();
        _speedService.SampleReady += OnSpeedSample;
    }

    private void OnSpeedSample(NetworkSpeedSample s)
    {
        if (_trayIcon == null || _trayIconService == null) return;

        var icon = _settings.TrayDisplay == TrayDisplayMode.Sparkline
            ? _trayIconService.GenerateSparkline(s.SmoothedDownloadBps)
            : _trayIconService.GenerateNumeric(s.SmoothedDownloadBps, s.SmoothedUploadBps);

        _trayIcon.Icon = icon;

        var (dl, dlUnit) = FormatFull(s.SmoothedDownloadBps);
        var (ul, ulUnit) = FormatFull(s.SmoothedUploadBps);
        _trayIcon.Text = $"↓ {dl} {dlUnit}  ↑ {ul} {ulUnit}";
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open LAN Manager", null, (_, _) => ShowWindow());
        menu.Items.Add("Settings", null, (_, _) => OpenSettings());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApp());
        return menu;
    }

    private void OpenSettings()
    {
        var win = new SettingsWindow(_settings);
        win.ShowDialog();
        if (win.Saved)
        {
            _speedService?.ApplySettings(_settings);
            _mainWindow?.ApplySettings(_settings);
        }
    }

    private void ShowWindow()
    {
        if (_mainWindow == null) return;
        _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }

    private void ExitApp()
    {
        _trayIcon?.Dispose();
        _trayIconService?.Dispose();
        _speedService?.Dispose();
        _mainWindow?.Close();
        Shutdown();
    }

    private static (string value, string unit) FormatFull(double bps) => bps switch
    {
        >= 1_000_000 => ($"{bps / 1_000_000:F1}", "MB/s"),
        >= 1_000 => ($"{bps / 1_000:F1}", "KB/s"),
        _ => ($"{bps:F0}", "B/s")
    };
}
