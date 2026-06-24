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
    private FlyoutWindow? _flyout;
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
        _flyout = new FlyoutWindow();

        _trayIcon = new NotifyIcon
        {
            Text = "LAN Manager",
            Icon = SystemIcons.Application,
            Visible = true,
            ContextMenuStrip = BuildContextMenu()
        };

        // Single click → flyout toggle
        _trayIcon.Click += (s, ev) =>
        {
            if (ev is MouseEventArgs me && me.Button == MouseButtons.Left)
                ToggleFlyout();
        };

        // Double click → main window
        _trayIcon.DoubleClick += (_, _) => ShowMainWindow();

        _speedService.SampleReady += OnSpeedSample;
    }

    private void ToggleFlyout()
    {
        if (_flyout == null) return;
        if (_flyout.IsVisible)
            _flyout.Hide();
        else
            _flyout.ShowNearTray();
    }

    private void OnSpeedSample(NetworkSpeedSample s)
    {
        if (_trayIcon == null || _trayIconService == null) return;

        // Update tray icon color tier
        _trayIcon.Icon = _trayIconService.GetActivityIcon(s.DownloadBps);

        // Tooltip shows exact current speeds
        var (dl, dlU) = FormatFull(s.DownloadBps);
        var (ul, ulU) = FormatFull(s.UploadBps);
        _trayIcon.Text = $"LAN Manager\n↓ {dl} {dlU}  ↑ {ul} {ulU}";

        // Push to flyout (updates even when hidden so graph is current when opened)
        _flyout?.PushSample(s);
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open LAN Manager", null, (_, _) => ShowMainWindow());
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

    private void ShowMainWindow()
    {
        if (_mainWindow == null) return;
        _flyout?.Hide();
        _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }

    private void ExitApp()
    {
        _trayIcon?.Dispose();
        _trayIconService?.Dispose();
        _speedService?.Dispose();
        _flyout?.Close();
        _mainWindow?.Close();
        Shutdown();
    }

    private static (string value, string unit) FormatFull(double bps) => bps switch
    {
        >= 1_000_000 => ($"{bps / 1_000_000:F1}", "MB/s"),
        >= 1_000     => ($"{bps / 1_000:F1}", "KB/s"),
        _            => ($"{bps:F0}", "B/s")
    };
}
