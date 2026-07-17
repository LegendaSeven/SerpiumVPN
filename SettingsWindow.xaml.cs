using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using MessageBox = System.Windows.MessageBox;

namespace SerpiumVPN
{
    public partial class SettingsWindow : Window
    {
        private readonly UserRuntimeSettings _settings;
        private readonly Func<bool, Task> _checkAppUpdatesAsync;
        private readonly Func<bool, Task> _checkFilesUpdatesAsync;
        private bool _isLoading;
        
        public static Action<string>? LocalUpdateRequested;
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
        private void InstallLocalPatch_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string baseDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);

                string? localZip = Directory
                    .EnumerateFiles(baseDir, "Serpium*.zip", SearchOption.TopDirectoryOnly)
                    .OrderByDescending(File.GetLastWriteTimeUtc)
                    .FirstOrDefault();

                if (localZip is null)
                {
                    MessageBox.Show(
                        "Локальный патч не найден.\n\n" +
                        "Положите архив Serpium*.zip рядом с SerpiumVPN.exe:\n\n" +
                        baseDir + "\n\n" +
                        "Либо нажмите «Выбрать файл вручную…».",
                        "Локальный патч не найден",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                MessageBoxResult result = MessageBox.Show(
                    $"Найден локальный патч:\n\n{Path.GetFileName(localZip)}\n\n" +
                    $"Папка:\n{baseDir}\n\nУстановить его сейчас?",
                    "Локальное обновление",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                    LocalUpdateRequested?.Invoke(localZip);
            }
            catch (Exception ex)
            {
                ShowLocalUpdateError(ex);
            }
        }

        private void SelectLocalPatch_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new()
            {
                Filter = "Serpium Update (*.zip)|*.zip",
                Title = "Выберите архив обновления",
                CheckFileExists = true,
                Multiselect = false
            };

            if (dialog.ShowDialog() != true)
                return;

            try
            {
                LocalUpdateRequested?.Invoke(dialog.FileName);
            }
            catch (Exception ex)
            {
                ShowLocalUpdateError(ex);
            }
        }

        private static void ShowLocalUpdateError(Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Ошибка обновления",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

}
