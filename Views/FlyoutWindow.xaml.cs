using System.Windows;
using LANManager.Services;
using LANManager.ViewModels;

namespace LANManager.Views;

public partial class FlyoutWindow : Window
{
    private readonly FlyoutViewModel _vm;
    private bool _suppressDeactivate;

    public FlyoutWindow()
    {
        InitializeComponent();
        _vm = new FlyoutViewModel();
        DataContext = _vm;
    }

    public void PushSample(NetworkSpeedSample s)
    {
        Dispatcher.Invoke(() =>
        {
            _vm.AddSample(s);
            DownloadLabel.Text = FormatBps(s.DownloadBps);
            UploadLabel.Text = FormatBps(s.UploadBps);
        });
    }

    public void ShowNearTray()
    {
        _suppressDeactivate = true;

        var workArea = SystemParameters.WorkArea;

        Left = workArea.Right - Width - 12;
        Top = workArea.Bottom - Height - 12;

        Show();
        Activate();

        // Re-enable deactivate-to-close after the show settles
        Dispatcher.BeginInvoke(() => _suppressDeactivate = false,
            System.Windows.Threading.DispatcherPriority.Background);
    }

    private void Window_Deactivated(object sender, EventArgs e)
    {
        if (!_suppressDeactivate) Hide();
    }

    private static string FormatBps(double bps) => bps switch
    {
        >= 1_000_000 => $"{bps / 1_000_000:F1} MB/s",
        >= 1_000 => $"{bps / 1_000:F1} KB/s",
        _ => $"{bps:F0} B/s"
    };
}
