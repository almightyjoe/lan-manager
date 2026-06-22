using System.Windows;
using System.Windows.Forms;
using LANManager.Views;

namespace LANManager;

public partial class App : System.Windows.Application
{
    private NotifyIcon? _trayIcon;
    private MainWindow? _mainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        _mainWindow = new MainWindow();

        _trayIcon = new NotifyIcon
        {
            Text = "LAN Manager",
            Icon = SystemIcons.Application,
            Visible = true,
            ContextMenuStrip = BuildContextMenu()
        };

        _trayIcon.DoubleClick += (_, _) => ShowWindow();
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open LAN Manager", null, (_, _) => ShowWindow());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApp());
        return menu;
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
        _mainWindow?.Close();
        Shutdown();
    }
}
