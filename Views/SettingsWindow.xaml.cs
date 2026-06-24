using System.Windows;
using LANManager.Models;

namespace LANManager.Views;

public partial class SettingsWindow : Window
{
    private readonly AppSettings _settings;
    public bool Saved { get; private set; }

    public SettingsWindow(AppSettings settings)
    {
        InitializeComponent();
        _settings = settings;
        LoadValues();
    }

    private void LoadValues()
    {
        TrayModeCombo.SelectedIndex = _settings.TrayDisplay == TrayDisplayMode.Sparkline ? 1 : 0;
        PollSlider.Value = _settings.PollIntervalSeconds;
        SmoothSlider.Value = _settings.SmoothingWindowSamples;
        UpdateLabels();
    }

    private void UpdateLabels()
    {
        PollLabel.Text = $"{(int)PollSlider.Value}s";
        SmoothLabel.Text = $"{(int)SmoothSlider.Value}";
    }

    private void PollSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e) => UpdateLabels();
    private void SmoothSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e) => UpdateLabels();

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        _settings.TrayDisplay = TrayModeCombo.SelectedIndex == 1
            ? TrayDisplayMode.Sparkline
            : TrayDisplayMode.Numeric;
        _settings.PollIntervalSeconds = (int)PollSlider.Value;
        _settings.SmoothingWindowSamples = (int)SmoothSlider.Value;
        _settings.Save();
        Saved = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();
}
