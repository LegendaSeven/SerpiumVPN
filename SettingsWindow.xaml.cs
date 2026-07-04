using System;
using System.Threading.Tasks;
using System.Windows;

namespace SerpiumVPN
{
    public partial class SettingsWindow : Window
    {
        private readonly UserRuntimeSettings _settings;
        private readonly Func<bool, Task> _checkAppUpdatesAsync;
        private readonly Func<bool, Task> _checkFilesUpdatesAsync;
        private bool _isLoading;

        public SettingsWindow(
            UserRuntimeSettings settings,
            Func<bool, Task> checkAppUpdatesAsync,
            Func<bool, Task> checkFilesUpdatesAsync)
        {
            _isLoading = true;
            _settings = settings;
            _checkAppUpdatesAsync = checkAppUpdatesAsync;
            _checkFilesUpdatesAsync = checkFilesUpdatesAsync;

            InitializeComponent();

            CheckAutoSwitchStrategies.IsChecked = _settings.AutoSwitchStrategies;
            CheckAutoUpdateFiles.IsChecked = _settings.AutoUpdateFiles;
            CheckAutoUpdateProgram.IsChecked = _settings.AutoUpdateProgram;
            _isLoading = false;
        }

        private void SettingsToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_isLoading || _settings == null)
                return;

            _settings.AutoSwitchStrategies = CheckAutoSwitchStrategies.IsChecked == true;
            _settings.AutoUpdateFiles = CheckAutoUpdateFiles.IsChecked == true;
            _settings.AutoUpdateProgram = CheckAutoUpdateProgram.IsChecked == true;
            _settings.Save();
        }

        private async void CheckAppPatch_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                ButtonCheckAppPatch.IsEnabled = false;
                await _checkAppUpdatesAsync(true);
            }
            finally
            {
                ButtonCheckAppPatch.IsEnabled = true;
            }
        }

        private async void UpdateFiles_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                ButtonUpdateFiles.IsEnabled = false;
                await _checkFilesUpdatesAsync(true);
            }
            finally
            {
                ButtonUpdateFiles.IsEnabled = true;
            }
        }
    }
}
