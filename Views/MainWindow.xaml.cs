using System.Windows;
using System.Windows.Input;
using LANManager.Models;
using LANManager.Services;
using LANManager.ViewModels;

namespace LANManager.Views;

public partial class MainWindow : Window
{
    private readonly NetworkSpeedService _speedService;
    private readonly ProcessBandwidthService _procService;
    private readonly LanScannerService _lanScanner;
    private readonly AlertService _alertService;
    private readonly SpeedViewModel _vm;
    private int _scanProgress;

    public MainWindow(NetworkSpeedService speedService, AppSettings settings)
    {
        InitializeComponent();

        _speedService = speedService;
        _procService = new ProcessBandwidthService(_speedService);
        _lanScanner = new LanScannerService();
        _alertService = new AlertService();

        // Load persisted alerts
        foreach (var a in settings.Alerts) _alertService.AddAlert(a);
        AlertGrid.ItemsSource = _alertService.Alerts;

        _vm = new SpeedViewModel();
        DataContext = _vm;

        _speedService.SampleReady += OnSpeedSample;
        _procService.Updated += OnProcessesUpdated;
        _lanScanner.ScanComplete += OnScanComplete;
        _alertService.AlertTriggered += OnAlertTriggered;
    }

    public void ApplySettings(AppSettings settings)
    {
        // Settings are applied at the service level; nothing extra needed here yet
    }

    private void OnSpeedSample(NetworkSpeedSample s)
    {
        Dispatcher.Invoke(() =>
        {
            _vm.AddSample(s);
            // Show smoothed values in the big labels
            UploadLabel.Text = FormatBps(s.SmoothedUploadBps);
            DownloadLabel.Text = FormatBps(s.SmoothedDownloadBps);
        });
    }

    private void OnProcessesUpdated(IReadOnlyList<ProcessBandwidth> procs)
    {
        Dispatcher.Invoke(() =>
        {
            var sorted = procs.OrderByDescending(p => p.TotalBps).ToList();
            ProcessGrid.ItemsSource = sorted;
            _alertService.Check(procs);
        });
    }

    private void OnScanComplete(List<LanDevice> devices)
    {
        Dispatcher.Invoke(() =>
        {
            DeviceGrid.ItemsSource = devices;
            ScanStatus.Text = $"Found {devices.Count} device(s)";
            ScanBtn.IsEnabled = true;
            ScanProgress.Value = 0;
        });
    }

    private void OnAlertTriggered(string message)
    {
        Dispatcher.Invoke(() =>
        {
            AlertLog.Text = $"[{DateTime.Now:HH:mm:ss}] {message}\n" + AlertLog.Text;
            AlertScroll.ScrollToTop();
        });
    }

    private async void ScanBtn_Click(object sender, RoutedEventArgs e)
    {
        ScanBtn.IsEnabled = false;
        ScanStatus.Text = "Scanning...";
        ScanProgress.Value = 0;
        _scanProgress = 0;

        var progress = new Progress<int>(_ =>
        {
            Dispatcher.Invoke(() => ScanProgress.Value = ++_scanProgress);
        });

        await _lanScanner.ScanAsync(progress);
    }

    private void AddAlert_Click(object sender, RoutedEventArgs e)
    {
        var procName = AlertProcessBox.Text.Trim();
        if (!double.TryParse(AlertThresholdBox.Text, out var threshold) || string.IsNullOrWhiteSpace(procName))
        {
            System.Windows.MessageBox.Show("Enter a valid process name and threshold.", "Invalid Input",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }

        var alert = new BandwidthAlert { ProcessName = procName, ThresholdMbps = threshold };
        _alertService.AddAlert(alert);
        AlertGrid.ItemsSource = null;
        AlertGrid.ItemsSource = _alertService.Alerts;
        AlertProcessBox.Clear();
    }

    private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Hide();

    private static string FormatBps(double bps) => bps switch
    {
        >= 1_000_000 => $"{bps / 1_000_000:F1} MB/s",
        >= 1_000 => $"{bps / 1_000:F1} KB/s",
        _ => $"{bps:F0} B/s"
    };

    protected override void OnClosed(EventArgs e)
    {
        _procService.Dispose();
        base.OnClosed(e);
    }
}
