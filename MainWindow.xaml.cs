using System;
using System.Globalization;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

// Создаем псевдоним, чтобы убрать конфликт с System.Windows.Shapes.Path
using IOPath = System.IO.Path;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;
using MessageBox = System.Windows.MessageBox;
using Color = System.Windows.Media.Color;
using ColorConverter = System.Windows.Media.ColorConverter;
using WpfBrush = System.Windows.Media.Brush;
using WpfBrushes = System.Windows.Media.Brushes;
using Clipboard = System.Windows.Clipboard;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SerpiumVPN.Relay;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Providers.Avo;
using SerpiumVPN.Relay.SingBox;
using SerpiumVPN.Relay.Xray;

namespace SerpiumVPN
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly ZapretManager _zapretManager;
        private readonly TelegramProxyManager _telegramProxyManager;
        private readonly VendorUpdateManager _vendorUpdateManager;
        private readonly AppUpdateManager _appUpdateManager;
        private readonly DispatcherTimer _strategyMonitorTimer;
        private readonly UserRuntimeSettings _settings;
        private Forms.NotifyIcon? _trayIcon;
        private CancellationTokenSource? _strategySelectionCts;
        private bool _isRealExit;
        private bool _isMonitoringStrategy;
        private bool _isLoadingRuntimeSettings;
        private readonly XrayGatewayManager _xrayGatewayManager = new();
        private readonly XrayClientManager _xrayClientManager = new();
        private readonly TailscaleManager _tailscaleManager = new();
        private readonly SerpiumNetManager _serpiumNetManager = new();
        private readonly SerpiumParser _serpiumParser = new();
        private readonly ProviderEnvelopeAdapterRegistry _providerEnvelopeAdapters = new();
        private readonly SerpiumKeyValidationService _serpiumKeyValidationService = new();
        private readonly SerpiumSingBoxValidationService _singBoxValidationService = new();
        private readonly SerpiumXraySessionManager _serpiumXraySessionManager = new();
        private SerpiumConnectionProfile? _validatedRelayProfile;
        private ProviderRuntimeProfile? _validatedProviderRuntimeProfile;
        private string? _relayGatewayUuid;

        public static Action<string>? LocalUpdateRequested;

        // Используем IOPath вместо Path, ведем строго к файлу в bin_files
        private readonly string _listFilePath = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "bin_files", "lists", "list-general-user.txt");

        public MainWindow()
        {
            InitializeComponent();
            Title = "Serpium VPN";
            _zapretManager = new ZapretManager();
            _telegramProxyManager = new TelegramProxyManager();
            _vendorUpdateManager = new VendorUpdateManager();
            _appUpdateManager = new AppUpdateManager();
            _settings = UserRuntimeSettings.Load();
            _providerEnvelopeAdapters.Register(new AvoBareKeyProviderAdapter());
            _xrayGatewayManager.StateChanged += state => SafeDispatcherInvoke(() => UpdateRelayGatewayUi(state));
            _xrayGatewayManager.LogReceived += line => SafeDispatcherInvoke(() =>
            {
                RelayGatewayLogTextBox.AppendText(line + Environment.NewLine);
                RelayGatewayLogTextBox.ScrollToEnd();
            });
            _serpiumXraySessionManager.StateChanged += state =>
                SafeDispatcherInvoke(() => UpdateRelayClientUi(state));
            _serpiumXraySessionManager.LogReceived += line => SafeDispatcherInvoke(() =>
            {
                RelayClientLogTextBox.AppendText(line + Environment.NewLine);
                RelayClientLogTextBox.ScrollToEnd();
            });
            _strategyMonitorTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMinutes(2)
            };
            _strategyMonitorTimer.Tick += StrategyMonitorTimer_TickAsync;

            this.Closing += MainWindow_Closing;
            this.StateChanged += MainWindow_StateChanged;

            // Вызываем правильный метод загрузки при старте
            LoadHostsList();
            LoadRuntimeSettingsIntoUi();
            InitializeTrayIcon();

            Loaded += MainWindow_LoadedAsync;
            SourceInitialized += MainWindow_SourceInitialized;
        }
    
        private const int DwmwaUseImmersiveDarkMode = 20;
        private const int DwmwaUseImmersiveDarkModeLegacy = 19;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(
            IntPtr hwnd,
            int attribute,
            ref int attributeValue,
            int attributeSize);

        private void MainWindow_SourceInitialized(object? sender, EventArgs e)
        {
            try
            {
                IntPtr hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                int enabled = 1;
                int size = Marshal.SizeOf(enabled);

                int result = DwmSetWindowAttribute(
                    hwnd,
                    DwmwaUseImmersiveDarkMode,
                    ref enabled,
                    size);

                if (result != 0)
                {
                    DwmSetWindowAttribute(
                        hwnd,
                        DwmwaUseImmersiveDarkModeLegacy,
                        ref enabled,
                        size);
                }
            }
            catch
            {
                // Dark title-bar support depends on the Windows build.
            }
        }

  
    


        private async void MainWindow_LoadedAsync(object sender, RoutedEventArgs e)
        {
            if (_settings.AutoUpdateFiles)
                await CheckVendorUpdatesAsync(showSuccessMessage: false);

            if (_settings.AutoUpdateProgram)
                await CheckAppUpdatesAsync(showSuccessMessage: false);

            await RestoreSavedStrategyAsync();
        }

        // Читает пользовательский список доменов и выводит его в текстовое поле
        private void LoadHostsList()
        {
            try
            {
                try
                {
                    _zapretManager.EnsureRequiredUserLists();
                }
                catch (Exception ex)
                {
                    HostsTextBox.Text =
                        "# Не удалось создать list-general-user.txt автоматически." + Environment.NewLine +
                        "# Причина: " + ex.Message + Environment.NewLine +
                        "# Запустите программу от имени администратора или переустановите через новый Inno-установщик.";
                    return;
                }

                if (File.Exists(_listFilePath))
                {
                    // Читаем файл (с поддержкой UTF-8 без BOM или дефолтной)
                    string hostsContent = File.ReadAllText(_listFilePath, Encoding.UTF8);
                    HostsTextBox.Text = hostsContent;
                    System.Diagnostics.Debug.WriteLine("[UI] Пользовательский список успешно выведен в окно.");
                }
                else
                {
                    HostsTextBox.Text = "# Файл list-general-user не найден. Нажмите сохранить, чтобы создать его.";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка загрузки списка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Обработчик кнопки «Сохранить список» со строгой валидацией и отменой записи
        /// </summary>
        private void SaveList_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Разбираем текст из TextBox на отдельные строки
                string[] lines = HostsTextBox.Text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

                var validatedLines = new System.Collections.Generic.List<string>();
                var errorMessages = new System.Collections.Generic.List<string>();
                int correctedCount = 0;

                for (int i = 0; i < lines.Length; i++)
                {
                    string rawLine = lines[i];
                    string line = rawLine.Trim();
                    int lineNumber = i + 1; // Номер строки для пользователя

                    // Пропускаем пустые строки или сохраняем комментарии как есть
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                    {
                        validatedLines.Add(rawLine);
                        continue;
                    }

                    if (TryNormalizeDomainLine(line, out string normalizedLine, out bool wasCorrected))
                    {
                        validatedLines.Add(normalizedLine);

                        if (wasCorrected)
                            correctedCount++;
                    }
                    else
                    {
                        // Если даже после попытки исправления это не домен — фиксируем ошибку
                        errorMessages.Add($"Строка {lineNumber}: \"{line}\"");
                    }
                }

                // КРИТИЧЕСКИЙ ТОЧКА: Если есть ошибки, прерываем запись!
                if (errorMessages.Count > 0)
                {
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine("Сохранение отменено! Обнаружены некорректные домены:\n");

                    // Выводим первые 10 ошибок, чтобы не раздувать окно, если их слишком много
                    for (int k = 0; k < Math.Min(errorMessages.Count, 10); k++)
                    {
                        sb.AppendLine(errorMessages[k]);
                    }

                    if (errorMessages.Count > 10)
                    {
                        sb.AppendLine($"...и еще {errorMessages.Count - 10} строк(и).");
                    }

                    sb.AppendLine("\nПожалуйста, исправьте их. Формат: google.com, discord.gg или ссылка вида https://example.com/path");

                    MessageBox.Show(sb.ToString(), "Ошибка формата", MessageBoxButton.OK, MessageBoxImage.Error);
                    return; // Выходим из метода, ничего не записывая в файл!
                }

                Directory.CreateDirectory(IOPath.GetDirectoryName(_listFilePath)!);

                // Если ошибок нет — со спокойной душой пишем в файл
                File.WriteAllLines(_listFilePath, validatedLines, Encoding.UTF8);

                // Показываем отчёт об успешном сохранении
                if (correctedCount > 0)
                {
                    MessageBox.Show($"Список успешно проверен и сохранен!\n\nАвтоматически исправлено (ссылки/www): {correctedCount}",
                                    "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("Список доменов успешно проверен и сохранен!", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                }

                // Обновляем TextBox, чтобы юзер увидел очищенный от 'https://' и 'www.' красивый список
                HostsTextBox.Text = string.Join(Environment.NewLine, validatedLines);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось сохранить файл: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static bool TryNormalizeDomainLine(string input, out string normalizedDomain, out bool wasCorrected)
        {
            normalizedDomain = string.Empty;
            wasCorrected = false;

            string original = input.Trim();
            string candidate = original;

            if (candidate.Contains("://", StringComparison.OrdinalIgnoreCase) &&
                !candidate.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (TryExtractHost(candidate, out string extractedHost))
                candidate = extractedHost;

            candidate = candidate.Trim().TrimEnd('.');

            if (candidate.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                candidate = candidate.Substring(4);

            try
            {
                candidate = new IdnMapping().GetAscii(candidate);
            }
            catch
            {
                return false;
            }

            candidate = candidate.ToLowerInvariant();

            if (!IsValidDomain(candidate))
                return false;

            normalizedDomain = candidate;
            wasCorrected = !string.Equals(original, normalizedDomain, StringComparison.Ordinal);
            return true;
        }

        private static bool TryExtractHost(string value, out string host)
        {
            host = string.Empty;

            if (Uri.TryCreate(value, UriKind.Absolute, out Uri? absoluteUri) &&
                (absoluteUri.Scheme == Uri.UriSchemeHttp || absoluteUri.Scheme == Uri.UriSchemeHttps) &&
                !string.IsNullOrWhiteSpace(absoluteUri.Host))
            {
                host = absoluteUri.Host;
                return true;
            }

            if (value.Contains('/') || value.Contains('?') || value.Contains('#') || value.Contains(':'))
            {
                if (Uri.TryCreate("https://" + value, UriKind.Absolute, out Uri? inferredUri) &&
                    !string.IsNullOrWhiteSpace(inferredUri.Host))
                {
                    host = inferredUri.Host;
                    return true;
                }
            }

            return false;
        }

        private static bool IsValidDomain(string domain)
        {
            if (domain.Length == 0 || domain.Length > 253 || !domain.Contains('.'))
                return false;

            string[] labels = domain.Split('.');
            bool hasLetter = false;

            foreach (string label in labels)
            {
                if (label.Length == 0 || label.Length > 63)
                    return false;

                if (label.StartsWith("-") || label.EndsWith("-"))
                    return false;

                foreach (char c in label)
                {
                    bool isLetter = c is >= 'a' and <= 'z';
                    bool isDigit = c is >= '0' and <= '9';

                    if (!isLetter && !isDigit && c != '-')
                        return false;

                    hasLetter |= isLetter;
                }
            }

            return hasLetter && !IsAllDigits(labels[^1]);
        }

        private static bool IsAllDigits(string value)
        {
            foreach (char c in value)
            {
                if (c is < '0' or > '9')
                    return false;
            }

            return true;
        }

        // Кнопка: Способ 1
        private void Strategy1_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                HideStrategySelectionProgress();
                _zapretManager.StartStrategy(1);
                SaveCurrentStrategySettings();
                StartStrategyMonitor();
                UpdateZapretStatus(true, "Zapret: работает (Способ 1)");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Ошибка запуска");
            }
        }

        // Кнопка: Способ 2
        private async void Strategy2_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                CancelStrategySelection();
                ButtonStrategy2.IsEnabled = false;

                // 1. Считываем состояние чекбоксов из UI
                bool needYoutube = CheckYouTube.IsChecked ?? false;
                bool needDiscord = CheckDiscord.IsChecked ?? false;
                SaveServiceSelectionSettings();

                _strategySelectionCts = new CancellationTokenSource();

                System.Diagnostics.Debug.WriteLine($"[UI] Запуск автоподбора. YouTube: {needYoutube}, Discord: {needDiscord}");

                ShowStrategySelectionProgress("Подбор стратегии...", "Готовимся к проверке стратегий", 0);
                UpdateAutoSelectStatus("Подбираем стратегию...", 0);

                Progress<StrategySelectionProgress> selectionProgress = new Progress<StrategySelectionProgress>(progress =>
                {
                    ShowStrategySelectionProgress("Подбор стратегии...", progress.Message, progress.Percent);
                    UpdateAutoSelectStatus(progress.Message, progress.Percent);
                });

                // 2. Передаем флаги в ZapretManager
                bool isStrategyFound = await _zapretManager.AutoSelectStrategyAsync(
                    needYoutube,
                    needDiscord,
                    preferFirstAcceptable: !_settings.AutoSwitchStrategies,
                    progress: selectionProgress,
                    cancellationToken: _strategySelectionCts.Token
                );

                if (isStrategyFound)
                {
                    SaveCurrentStrategySettings();
                    StartStrategyMonitor();
                    ShowStrategySelectionProgress("Стратегия найдена", $"Запущено: {_zapretManager.CurrentStrategyName}", 100);
                    UpdateZapretStatus(true,  $"Zapret: работает ({_zapretManager.CurrentStrategyName})");
                }
                else
                {
                    UpdateAutoSelectStatus("Ошибка автоподбора", 0);
                    MessageBox.Show(
                        "Подходящая стратегия не найдена.\n\n" +
                        _zapretManager.LastAutoSelectReport + "\n\n" +
                        "Полный лог: " + _zapretManager.LastAutoSelectLogPath,
                        "Диагностика автоподбора",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning
                    );
                }
            }
            catch (OperationCanceledException)
            {
                _zapretManager.Stop();
                ShowStrategySelectionProgress("Подбор отменён", "Пользователь остановил подбор стратегии", 0);
                UpdateZapretStatus(false, "Zapret: отключен");
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"Ошибка интерфейса: {ex.Message}", "Ошибка", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            finally
            {
                _strategySelectionCts?.Dispose();
                _strategySelectionCts = null;
                ButtonStrategy2.IsEnabled = true;
            }
        }

        // Кнопка: Telegram WS-прогон
        private async void Telegram_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                ButtonTelegram.IsEnabled = false;
                HideStrategySelectionProgress();
                UpdateTelegramStatus("Запускаем Telegram WS-прокси...", false);

                TelegramProxyStartResult result = await _telegramProxyManager.StartAsync();

                UpdateTelegramStatus("Telegram WS-прокси активен", true);

                if (result == TelegramProxyStartResult.Started)
                {
                    MessageBox.Show(
                        @"Telegram WS-прокси запущен. Если Telegram Desktop не предложил подключить прокси автоматически, откройте ссылку из папки bin_files\tgws\telegram_proxy_link.txt вручную.",
                        "Telegram WS-прогон",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
            }
            catch (FileNotFoundException ex)
            {
                UpdateTelegramStatus("TgWsProxy не найден", false);
                MessageBox.Show(
                    ex.Message + Environment.NewLine + Environment.NewLine + @"Положите TgWsProxy_windows.exe в папку bin_files\tgws и нажмите кнопку ещё раз.",
                    "Telegram WS-прогон",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }
            catch (Exception ex)
            {
                UpdateTelegramStatus("Ошибка Telegram WS-прокси", false);
                MessageBox.Show($"Ошибка запуска Telegram WS-прокси: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ButtonTelegram.IsEnabled = true;
            }
        }

        private async Task CheckVendorUpdatesAsync(bool showSuccessMessage)
        {
            try
            {
                UpdateFilesStatus("Проверяем обновления файлов...", false);

                _zapretManager.Stop();
                _telegramProxyManager.Stop();

                Progress<string> progress = new Progress<string>(message =>
                {
                    UpdateFilesStatus(message, false);
                });

                VendorUpdateSummary summary = await _vendorUpdateManager.CheckAndUpdateAsync(progress);

                if (summary.HasUpdates)
                {
                    string details = string.Join(
                        Environment.NewLine,
                        summary.Items.Where(item => item.Updated).Select(item => $"{item.Name}: {item.LatestVersion}")
                    );
                    string skippedDetails = summary.SkippedFiles.Count > 0
                        ? Environment.NewLine + Environment.NewLine +
                          "Эти файлы сейчас заняты Windows и были пропущены:" + Environment.NewLine +
                          string.Join(Environment.NewLine, summary.SkippedFiles.Distinct(StringComparer.OrdinalIgnoreCase)) +
                          Environment.NewLine + Environment.NewLine +
                          "Чтобы заменить их тоже, перезагрузите ПК и нажмите проверку обновлений ещё раз до запуска обхода."
                        : string.Empty;

                    UpdateFilesStatus("Файлы обновлены", true);
                    MessageBox.Show(
                        "Файлы успешно обновлены:" + Environment.NewLine + details + skippedDetails,
                        "Обновления",
                        MessageBoxButton.OK,
                        summary.SkippedFiles.Count > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information
                    );

                    LoadHostsList();
                }
                else
                {
                    UpdateFilesStatus("Файлы актуальны", true);

                    if (showSuccessMessage)
                    {
                        MessageBox.Show(
                            "Обновлений нет. Все нужные файлы уже актуальны.",
                            "Обновления",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information
                        );
                    }
                }
            }
            catch (Exception ex)
            {
                UpdateFilesStatus("Ошибка обновления файлов", false);

                if (showSuccessMessage)
                {
                    MessageBox.Show(
                        $"Не удалось проверить или установить обновления: {ex.Message}",
                        "Обновления",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning
                    );
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[UPDATE WARN] {ex}");
                }
            }
            finally
            {
            }
        }

        private async Task CheckAppUpdatesAsync(bool showSuccessMessage)
        {
            try
            {
                UpdateProgramStatus("Проверяем обновление программы...", false);

                Progress<int> progress = new Progress<int>(percent =>
                {
                    UpdateProgramStatus($"Скачиваем обновление программы... {percent}%", false);
                });

                AppUpdateCheckResult result = await _appUpdateManager.CheckDownloadAndApplyAsync(progress);

                switch (result.Status)
                {
                    case AppUpdateCheckStatus.NoUpdates:
                        UpdateProgramStatus("Программа актуальна", true);

                        if (showSuccessMessage)
                        {
                            MessageBox.Show(
                                $"Обновлений программы нет. Текущая версия: {result.Version}.",
                                "Обновление программы",
                                MessageBoxButton.OK,
                                MessageBoxImage.Information
                            );
                        }
                        break;

                    case AppUpdateCheckStatus.ReadyToRestart:
                        UpdateProgramStatus("Обновление скачано и готово к установке", true);

                        MessageBoxResult restart = MessageBox.Show(
                            $"Скачана версия {result.Version}. Перезапустить SerpiumVPN и установить обновление сейчас?",
                            "Обновление программы",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Question
                        );

                        if (restart == MessageBoxResult.Yes)
                        {
                            _zapretManager.Stop();
                            _telegramProxyManager.Stop();
                            _appUpdateManager.RestartAndApply();
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                UpdateProgramStatus("Ошибка обновления программы", false);
                MessageBox.Show(
                    $"Не удалось проверить или установить обновление программы: {ex.Message}",
                    "Обновление программы",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }
            finally
            {
            }
        }

        private void OpenZapretPage_Click(object sender, RoutedEventArgs e)
        {
            MainNavigationTabs.SelectedIndex = 1;
        }

        private void OpenRelayPage_Click(object sender, RoutedEventArgs e)
        {
            MainNavigationTabs.SelectedIndex = 2;
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            MainNavigationTabs.SelectedIndex = 3;
        }

        private void ProgramSettingsToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_isLoadingRuntimeSettings)
                return;

            _settings.AutoUpdateProgram =
                CheckAutoUpdateProgram.IsChecked == true;
            _settings.Save();
        }

        private async void CheckAppPatch_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                ButtonCheckAppPatch.IsEnabled = false;
                await CheckAppUpdatesAsync(showSuccessMessage: true);
            }
            finally
            {
                ButtonCheckAppPatch.IsEnabled = true;
            }
        }

        private void InstallLocalPatch_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string baseDir =
                    IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory);

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
                        "Либо нажмите «Выбрать ZIP вручную».",
                        "Локальный патч не найден",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                MessageBoxResult result = MessageBox.Show(
                    $"Найден локальный патч:\n\n{IOPath.GetFileName(localZip)}\n\n" +
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

        // Кнопка: Остановить
        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                CancelStrategySelection();
                StopStrategyMonitor();
                _zapretManager.Stop();
                _telegramProxyManager.Stop();
                HideStrategySelectionProgress();
                UpdateZapretStatus(false, "Zapret: отключен");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при остановке: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowStrategySelectionProgress(string title, string details, int percent)
        {
            AutoSelectPanel.Visibility = Visibility.Visible;
            AutoSelectTitle.Text = title;
            AutoSelectDetails.Text = details;
            SetAutoSelectProgress(percent);
        }

        private void HideStrategySelectionProgress()
        {
            AutoSelectPanel.Visibility = Visibility.Visible;
            AutoSelectTitle.Text = string.Empty;
            AutoSelectTitle.Visibility = Visibility.Collapsed;
            SetAutoSelectProgress(0);
            AutoSelectDetails.Text = "Готов к поиску рабочей стратегии";
        }

        private void SetAutoSelectProgress(int percent)
        {
            int safePercent = Math.Clamp(percent, 0, 100);

            void ApplyWidth()
            {
                double trackWidth = AutoSelectProgressTrack.ActualWidth;
                AutoSelectProgressFill.Width = trackWidth <= 0
                    ? 0
                    : trackWidth * safePercent / 100.0;
            }

            ApplyWidth();

            if (AutoSelectProgressTrack.ActualWidth <= 0)
            {
                Dispatcher.BeginInvoke((Action)ApplyWidth, DispatcherPriority.Loaded);
            }
        }

        private void UpdateAutoSelectStatus(string details, int percent)
        {
            AutoSelectPanel.Visibility = Visibility.Visible;
            AutoSelectTitle.Visibility = Visibility.Collapsed;
            AutoSelectDetails.Text = details;
            SetAutoSelectProgress(percent);
        }

        private void UpdateFilesStatus(string text, bool success)
        {
            ZapretFilesStatusText.Text = text;
            ZapretFilesStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(success ? "#68D391" : "#D0D0DA"));
        }

        private void UpdateProgramStatus(string text, bool success)
        {
            ProgramUpdateStatusText.Text = text;
            ProgramUpdateStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(success ? "#68D391" : "#D0D0DA"));
        }

        private void UpdateTelegramStatus(string text, bool success)
        {
            TelegramStatusText.Text = text;
            TelegramStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(success ? "#68D391" : "#D0D0DA"));
        }

        // Верхний индикатор отражает только состояние Zapret.
        private void UpdateZapretStatus(bool isRunning, string text)
        {
            StatusText.Text = text;

            string colorHex = isRunning ? "#00FF66" : "#FF4F4F";
            var targetColor = (Color)ColorConverter.ConvertFromString(colorHex);

            StatusDot.Fill = new SolidColorBrush(targetColor);
            DotGlow.Color = targetColor;
        }

        private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            if (!_isRealExit)
            {
                e.Cancel = true;
                Hide();
                _trayIcon?.ShowBalloonTip(
                    2500,
                    "Serpium VPN работает в фоне",
                    "Окно скрыто. Для полного выхода используйте меню иконки в трее.",
                    Forms.ToolTipIcon.Info
                );
                return;
            }

            StopStrategyMonitor();
            _zapretManager.Stop();
            _telegramProxyManager.Stop();
            DisposeValidatedProviderRuntimeProfile();
            try { _serpiumXraySessionManager.Dispose(); } catch { }
            try { _xrayClientManager.Dispose(); } catch { }
            try { _xrayGatewayManager.Dispose(); } catch { }
            try { _serpiumNetManager.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
            _trayIcon?.Dispose();
        }

        private void MainWindow_StateChanged(object? sender, EventArgs e)
        {
            // Обычное сворачивание оставляет SerpiumVPN на панели задач.
            // Скрытие в трей выполняется только при закрытии окна через MainWindow_Closing.
        }

        private void InitializeTrayIcon()
        {
            _trayIcon = new Forms.NotifyIcon
            {
                Icon = LoadTrayIcon(),
                Text = "Serpium VPN",
                Visible = true
            };

            Forms.ContextMenuStrip menu = new Forms.ContextMenuStrip();
            menu.Items.Add("Открыть", null, (_, _) => Dispatcher.Invoke(ShowFromTray));
            menu.Items.Add("Остановить обход", null, (_, _) => Dispatcher.Invoke(() =>
            {
                StopStrategyMonitor();
                _zapretManager.Stop();
                _telegramProxyManager.Stop();
                UpdateZapretStatus(false, "Zapret: отключен");
            }));
            menu.Items.Add("Выход", null, (_, _) => Dispatcher.Invoke(ExitApplication));

            _trayIcon.ContextMenuStrip = menu;
            _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowFromTray);
        }

        private static Drawing.Icon LoadTrayIcon()
        {
            try
            {
                string exePath = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "";
                if (!string.IsNullOrWhiteSpace(exePath))
                {
                    Drawing.Icon? associatedIcon = Drawing.Icon.ExtractAssociatedIcon(exePath);
                    if (associatedIcon != null)
                        return associatedIcon;
                }
            }
            catch
            {
                // fall through to file/default icon
            }

            string iconPath = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "serpium_vpn.ico");
            return File.Exists(iconPath) ? new Drawing.Icon(iconPath) : Drawing.SystemIcons.Application;
        }

        public void ShowFromTray()
        {
            Show();
            WindowState = WindowState.Normal;
            Topmost = true;
            Topmost = false;
            Activate();
        }

        private void ExitApplication()
        {
            _isRealExit = true;

            System.Windows.Application.Current.Shutdown();
        }

        private void CancelStrategySelection()
        {
            if (_strategySelectionCts == null)
                return;

            try
            {
                _strategySelectionCts.Cancel();
            }
            catch
            {
                // ignore cancellation races
            }
        }

        private void LoadRuntimeSettingsIntoUi()
        {
            _isLoadingRuntimeSettings = true;
            try
            {
                CheckYouTube.IsChecked = _settings.CheckYouTube;
                CheckDiscord.IsChecked = _settings.CheckDiscord;
                CheckAutoSwitchStrategies.IsChecked = _settings.AutoSwitchStrategies;
                CheckAutoUpdateFiles.IsChecked = _settings.AutoUpdateFiles;
                CheckAutoUpdateProgram.IsChecked = _settings.AutoUpdateProgram;
                AppVersionTextBlock.Text = AppVersionInfo.Display;
            }
            finally
            {
                _isLoadingRuntimeSettings = false;
            }
        }

        private void ZapretSettingsToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_isLoadingRuntimeSettings)
                return;

            _settings.AutoSwitchStrategies =
                CheckAutoSwitchStrategies.IsChecked == true;
            _settings.AutoUpdateFiles =
                CheckAutoUpdateFiles.IsChecked == true;
            _settings.Save();

            if (_settings.AutoSwitchStrategies && _zapretManager.IsRunning)
                StartStrategyMonitor();
            else
                StopStrategyMonitor();
        }

        private async void UpdateZapretFiles_ClickAsync(
            object sender,
            RoutedEventArgs e)
        {
            try
            {
                ButtonUpdateZapretFiles.IsEnabled = false;
                await CheckVendorUpdatesAsync(showSuccessMessage: true);
            }
            finally
            {
                ButtonUpdateZapretFiles.IsEnabled = true;
            }
        }

        private async Task RestoreSavedStrategyAsync()
        {
            if (!_settings.AutoStartLastStrategy || string.IsNullOrWhiteSpace(_settings.LastStrategyName))
                return;

            try
            {
                UpdateZapretStatus(true, $"Zapret: запускаем сохранённую стратегию ({_settings.LastStrategyName})...");
                _zapretManager.StartStrategy(_settings.LastStrategyName);
                await Task.Delay(2500);

                bool ok = await _zapretManager.CheckConnectionAsync(_settings.CheckYouTube, _settings.CheckDiscord);
                if (ok)
                {
                    StartStrategyMonitor();
                    UpdateZapretStatus(true,  $"Zapret: работает ({_settings.LastStrategyName})");
                    return;
                }

                UpdateZapretStatus(true, "Zapret: сохранённая стратегия просела, подбираем новую...");
                bool selected = await _zapretManager.AutoSelectStrategyAsync(_settings.CheckYouTube, _settings.CheckDiscord, showMessages: false);
                if (selected)
                {
                    SaveCurrentStrategySettings();
                    StartStrategyMonitor();
                    UpdateZapretStatus(true,  $"Zapret: работает ({_zapretManager.CurrentStrategyName})");
                }
                else
                {
                    UpdateZapretStatus(false, "Zapret: нет подходящей стратегии");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RESTORE WARN] {ex}");
                UpdateZapretStatus(false, "Zapret: сохранённая стратегия не запущена");
            }
        }

        private void SaveCurrentStrategySettings()
        {
            SaveServiceSelectionSettings();
            _settings.LastStrategyName = _zapretManager.CurrentStrategyName;
            _settings.LastStrategySavedAt = DateTime.Now;
            _settings.Save();
        }

        private void SaveServiceSelectionSettings()
        {
            _settings.CheckYouTube = CheckYouTube.IsChecked ?? false;
            _settings.CheckDiscord = CheckDiscord.IsChecked ?? false;
            _settings.Save();
        }

        private void StartStrategyMonitor()
        {
            if (_settings.AutoSwitchStrategies)
                _strategyMonitorTimer.Start();
            else
                _strategyMonitorTimer.Stop();
        }

        private void StopStrategyMonitor()
        {
            _strategyMonitorTimer.Stop();
        }

        private async void StrategyMonitorTimer_TickAsync(object? sender, EventArgs e)
        {
            if (_isMonitoringStrategy || !_settings.AutoSwitchStrategies || !_zapretManager.IsRunning)
                return;

            _isMonitoringStrategy = true;

            try
            {
                bool needYoutube = CheckYouTube.IsChecked ?? false;
                bool needDiscord = CheckDiscord.IsChecked ?? false;

                CancelStrategySelection();
                _strategySelectionCts = new CancellationTokenSource();

                bool currentOk = await _zapretManager.CheckConnectionAsync(
                    needYoutube,
                    needDiscord,
                    cancellationToken: _strategySelectionCts.Token
                );

                if (currentOk)
                {
                    UpdateZapretStatus(true,  $"Zapret: работает ({_zapretManager.CurrentStrategyName})");
                    return;
                }

                UpdateZapretStatus(true, "Zapret: качество просело, меняем стратегию...");

                bool switched = await _zapretManager.AutoSelectStrategyAsync(
                    needYoutube,
                    needDiscord,
                    showMessages: false,
                    cancellationToken: _strategySelectionCts.Token
                );
                if (switched)
                {
                    SaveCurrentStrategySettings();
                    UpdateZapretStatus(true,  $"Zapret: автосмена: {_zapretManager.CurrentStrategyName}");
                }
                else
                {
                    UpdateZapretStatus(false, "Zapret: нет стратегии с подходящей скоростью");
                }
            }
            catch (OperationCanceledException)
            {
                _zapretManager.Stop();
                UpdateZapretStatus(false, "Zapret: отключен");
            }
            finally
            {
                _strategySelectionCts?.Dispose();
                _strategySelectionCts = null;
                _isMonitoringStrategy = false;
            }
        }

      
        private async void StartRelayGateway_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!int.TryParse(RelayGatewayPortTextBox.Text.Trim(), out int port) || port is < 1 or > 65535)
                    throw new FormatException("Порт должен быть числом от 1 до 65535.");

                RelayStatusTextBlock.Text = "Статус: запускаем Xray и встроенную сеть SerpiumNet…";
                RelayStatusTextBlock.Foreground = System.Windows.Media.Brushes.Goldenrod;
                RelayGatewayTailscaleStateTextBlock.Text = "SerpiumNet: подключение…";
                RelayGeneratedKeyTextBox.Clear();
                RelayGatewayLogTextBox.Clear();

                _relayGatewayUuid ??= Guid.NewGuid().ToString();
                string relayDir = IOPath.Combine(IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory), "bin_files", "relay");
                await _xrayGatewayManager.StartAsync(
                    IOPath.Combine(relayDir, "xray.exe"),
                    IOPath.Combine(relayDir, "configs", "gateway-server.json"),
                    "127.0.0.1", port, _relayGatewayUuid);

                string tailscaleIp = await _serpiumNetManager.StartGatewayAsync(this, port);
                RelayGatewayHostTextBox.Text = tailscaleIp;
                RelayGatewayTailscaleStateTextBlock.Text = $"SerpiumNet: встроенная сеть ({tailscaleIp})";
                RelayGatewayTailscaleStateTextBlock.Foreground = System.Windows.Media.Brushes.LightGreen;

                bool localPortReady = await RelayConnectionProbe.CanConnectAsync(
                    "127.0.0.1", port, TimeSpan.FromSeconds(4));
                if (!localPortReady)
                    throw new InvalidOperationException("Xray запущен, но порт шлюза не отвечает.");

                RelayKey key = new()
                {
                    Schema = 1,
                    Name = "Serpium Home Gateway",
                    Transport = "tailscale",
                    Protocol = "vless",
                    Host = tailscaleIp,
                    Port = port,
                    Uuid = _relayGatewayUuid,
                    Network = "tcp"
                };
                RelayGeneratedKeyTextBox.Text = RelayKeyBuilder.Build(key);
                RelayGatewayAvailabilityTextBlock.Text = $"Шлюз: доступен локально на порту {port}";
                RelayGatewayAvailabilityTextBlock.Foreground = System.Windows.Media.Brushes.LightGreen;
                RelayStatusTextBlock.Text = $"Статус: шлюз готов — {tailscaleIp}:{port}. Ключ создан.";
                RelayStatusTextBlock.Foreground = System.Windows.Media.Brushes.LightGreen;
            }
            catch (Exception ex)
            {
                RelayGatewayAvailabilityTextBlock.Text = "Шлюз: недоступен";
                RelayGatewayAvailabilityTextBlock.Foreground = System.Windows.Media.Brushes.OrangeRed;
                RelayStatusTextBlock.Text = "Статус: ошибка запуска шлюза — " + ex.Message;
                RelayStatusTextBlock.Foreground = System.Windows.Media.Brushes.OrangeRed;
                UpdateRelayGatewayUi(_xrayGatewayManager.State);
            }
        }

        private async void StopRelayGateway_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                await _serpiumNetManager.StopAsync();
                await _xrayGatewayManager.StopAsync();
                RelayGatewayAvailabilityTextBlock.Text = "Шлюз: остановлен";
                RelayGatewayAvailabilityTextBlock.Foreground = System.Windows.Media.Brushes.Gray;
                RelayStatusTextBlock.Text = "Статус: шлюз остановлен.";
                RelayStatusTextBlock.Foreground = System.Windows.Media.Brushes.Goldenrod;
            }
            catch (Exception ex)
            {
                RelayStatusTextBlock.Text = "Статус: ошибка остановки — " + ex.Message;
                RelayStatusTextBlock.Foreground = System.Windows.Media.Brushes.OrangeRed;
            }
        }

        private void UpdateRelayGatewayUi(RelayGatewayState state)
        {
            ButtonStartRelayGateway.IsEnabled = state is RelayGatewayState.Stopped or RelayGatewayState.Failed;
            ButtonStopRelayGateway.IsEnabled = state is RelayGatewayState.Starting or RelayGatewayState.Running or RelayGatewayState.Stopping || _xrayGatewayManager.HasLiveProcess;
            RelayGatewayStateTextBlock.Text = state switch
            {
                RelayGatewayState.Starting => "Xray: запускается…",
                RelayGatewayState.Running => "Xray: работает",
                RelayGatewayState.Stopping => "Xray: останавливается…",
                RelayGatewayState.Failed => "Xray: ошибка",
                _ => "Xray: остановлен"
            };
        }

        private async void StartRelayClient_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                SerpiumParseResult parseResult = _serpiumParser.Parse(RelayClientKeyTextBox.Text);
                if (!parseResult.Success)
                    throw new FormatException(parseResult.Error);

                if (parseResult.Envelope is ProviderEnvelope envelope)
                {
                    IProviderEnvelopeAdapter? adapter =
                        _providerEnvelopeAdapters.Find(envelope.Scheme);
                    if (adapter is null)
                    {
                        RelayDetectedProfileTextBlock.Text = BuildProviderEnvelopeSummary(envelope);
                        throw new NotSupportedException(BuildProviderEnvelopeUnavailableMessage(envelope));
                    }

                    SetRelayStatus(
                        $"Статус: раскрываем {envelope.DisplayScheme}-профиль локально…",
                        WpfBrushes.DeepSkyBlue);

                    ProviderResolveResult resolved = await adapter.ResolveAsync(envelope);
                    if (!resolved.Success || resolved.RuntimeProfile is null)
                        throw new InvalidOperationException(resolved.Error);

                    ProviderRuntimeProfile candidateProfile = resolved.RuntimeProfile;
                    string singBoxRelayDir = IOPath.Combine(
                        IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                        "bin_files",
                        "relay");

                    SetRelayStatus(
                        "Статус: профиль раскрыт — выполняем sing-box check без записи JSON на диск…",
                        WpfBrushes.DeepSkyBlue);

                    SingBoxCheckResult engineCheck;
                    try
                    {
                        engineCheck = await _singBoxValidationService.ValidateAsync(
                            IOPath.Combine(singBoxRelayDir, "sing-box.exe"),
                            candidateProfile);
                    }
                    catch
                    {
                        candidateProfile.Dispose();
                        throw;
                    }

                    if (!engineCheck.Success)
                    {
                        RelayDetectedProfileTextBlock.Text =
                            BuildProviderRuntimeProfileSummary(candidateProfile) +
                            Environment.NewLine + Environment.NewLine +
                            "Проверка движком:" + Environment.NewLine +
                            "• " + engineCheck.EngineVersion + Environment.NewLine +
                            "• " + engineCheck.Message;
                        candidateProfile.Dispose();
                        throw new InvalidOperationException(engineCheck.Message);
                    }

                    DisposeValidatedProviderRuntimeProfile();
                    _validatedProviderRuntimeProfile = candidateProfile;
                    RelayDetectedProfileTextBlock.Text =
                        BuildProviderRuntimeProfileSummary(_validatedProviderRuntimeProfile) +
                        Environment.NewLine + Environment.NewLine +
                        "Проверка движком:" + Environment.NewLine +
                        "• " + engineCheck.EngineVersion + Environment.NewLine +
                        "• " + engineCheck.Message;

                    SetRelayStatus(
                        "Статус: AVO-профиль принят sing-box. Реальный запуск TUN будет включён в MVP7.0A.6.",
                        WpfBrushes.Goldenrod);
                    return;
                }

                if (parseResult.Profile is null)
                    throw new FormatException("Serpium Parser не вернул профиль подключения.");

                if (!int.TryParse(RelayClientSocksPortTextBox.Text.Trim(), out int socksPort) ||
                    socksPort is < 1 or > 65535)
                {
                    throw new FormatException("SOCKS5-порт должен быть числом от 1 до 65535.");
                }

                SerpiumConnectionProfile profile = parseResult.Profile;
                _validatedRelayProfile = profile;
                RelayDetectedProfileTextBlock.Text = BuildRelayProfileSummary(profile);
                RelayClientLogTextBox.Clear();
                SetRelayStatus("Статус: подключение через Xray…", WpfBrushes.DeepSkyBlue);
                RelayClientSocksStateTextBlock.Text = "SOCKS5: запускается…";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.DeepSkyBlue;

                string relayDir = IOPath.Combine(
                    IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                    "bin_files",
                    "relay");

                await _serpiumXraySessionManager.StartAsync(
                    IOPath.Combine(relayDir, "xray.exe"),
                    IOPath.Combine(relayDir, "configs", "key-client.json"),
                    profile,
                    socksPort);

                RelayClientSocksStateTextBlock.Text = $"SOCKS5: активен (127.0.0.1:{socksPort})";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.LightGreen;
                SetRelayStatus(
                    $"Статус: подключено через Xray — {profile.Protocol.ToUpperInvariant()}, " +
                    $"SOCKS5 127.0.0.1:{socksPort}",
                    WpfBrushes.LightGreen);
            }
            catch (Exception ex)
            {
                RelayClientSocksStateTextBlock.Text = "SOCKS5: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                SetRelayStatus("Статус: ошибка подключения — " + ex.Message, WpfBrushes.OrangeRed);
                UpdateRelayClientUi(_serpiumXraySessionManager.State);
            }
        }

        private async void StopRelayClient_ClickAsync(object sender, RoutedEventArgs e)
        {
            try
            {
                SetRelayStatus("Статус: отключение…", WpfBrushes.Goldenrod);
                await _serpiumXraySessionManager.StopAsync();
                RelayClientSocksStateTextBlock.Text = "SOCKS5: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                SetRelayStatus("Статус: отключено.", WpfBrushes.Gray);
            }
            catch (Exception ex)
            {
                SetRelayStatus("Статус: ошибка отключения — " + ex.Message, WpfBrushes.OrangeRed);
            }
        }

        private void UpdateRelayClientUi(RelayGatewayState state)
        {
            bool isBusy = state is RelayGatewayState.Starting or RelayGatewayState.Stopping;
            bool isRunning = state == RelayGatewayState.Running ||
                             _serpiumXraySessionManager.HasLiveProcess;

            ButtonStartRelayClient.IsEnabled = !isBusy && !isRunning;
            ButtonStopRelayClient.IsEnabled = isBusy || isRunning;
            ButtonValidateRelayKey.IsEnabled = !isBusy && !isRunning;
            RelayClientKeyTextBox.IsReadOnly = isBusy || isRunning;

            RelayClientStateTextBlock.Text = state switch
            {
                RelayGatewayState.Starting => "Xray: запускается…",
                RelayGatewayState.Running => "Xray: работает",
                RelayGatewayState.Stopping => "Xray: останавливается…",
                RelayGatewayState.Failed => "Xray: ошибка",
                _ => "Xray: остановлен"
            };

            RelayClientStateTextBlock.Foreground = state switch
            {
                RelayGatewayState.Running => WpfBrushes.LightGreen,
                RelayGatewayState.Failed => WpfBrushes.OrangeRed,
                RelayGatewayState.Starting => WpfBrushes.DeepSkyBlue,
                RelayGatewayState.Stopping => WpfBrushes.Goldenrod,
                _ => WpfBrushes.Gray
            };

            if (state == RelayGatewayState.Failed &&
                !string.IsNullOrWhiteSpace(_serpiumXraySessionManager.LastError))
            {
                RelayClientSocksStateTextBlock.Text = "SOCKS5: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                SetRelayStatus(
                    "Статус: соединение завершилось с ошибкой — " +
                    _serpiumXraySessionManager.LastError,
                    WpfBrushes.OrangeRed);
            }
        }

        private void CopyRelayKey_Click(object sender, RoutedEventArgs e)
        {
            // Legacy SerpiumNet gateway action. The gateway UI is hidden in MVP7.
        }

        private void PasteRelayKey_Click(object sender, RoutedEventArgs e)
        {
            if (Clipboard.ContainsText())
            {
                RelayClientKeyTextBox.Text = Clipboard.GetText().Trim();
                SetRelayStatus("Статус: ключ вставлен. Нажмите «Проверить ключ».", WpfBrushes.Gray);
            }
            else
            {
                SetRelayStatus("Статус: в буфере обмена нет текста.", WpfBrushes.Goldenrod);
            }
        }

        private async void ValidateRelayKey_Click(object sender, RoutedEventArgs e)
        {
            ButtonValidateRelayKey.IsEnabled = false;
            try
            {
                SerpiumParseResult parseResult = _serpiumParser.Parse(RelayClientKeyTextBox.Text);
                if (!parseResult.Success)
                {
                    _validatedRelayProfile = null;
                    RelayDetectedProfileTextBlock.Text = "Ключ не распознан.";
                    SetRelayStatus("Статус: ключ отклонён — " + parseResult.Error, WpfBrushes.OrangeRed);
                    return;
                }

                if (parseResult.Envelope is ProviderEnvelope envelope)
                {
                    _validatedRelayProfile = null;
                    DisposeValidatedProviderRuntimeProfile();
                    RelayDetectedProfileTextBlock.Text = BuildProviderEnvelopeSummary(envelope);

                    IProviderEnvelopeAdapter? adapter =
                        _providerEnvelopeAdapters.Find(envelope.Scheme);
                    if (adapter is null)
                    {
                        SetRelayStatus(
                            $"Статус: контейнер {envelope.DisplayScheme} корректен, " +
                            "но адаптер не зарегистрирован.",
                            WpfBrushes.Goldenrod);
                        return;
                    }

                    SetRelayStatus(
                        $"Статус: локально проверяем и расшифровываем {envelope.DisplayScheme}-ключ…",
                        WpfBrushes.DeepSkyBlue);

                    ProviderResolveResult resolved = await adapter.ResolveAsync(envelope);
                    if (!resolved.Success || resolved.RuntimeProfile is null)
                    {
                        SetRelayStatus(
                            "Статус: AVO-ключ отклонён — " + resolved.Error,
                            WpfBrushes.OrangeRed);
                        return;
                    }

                    ProviderRuntimeProfile candidateProfile = resolved.RuntimeProfile;
                    string singBoxRelayDir = IOPath.Combine(
                        IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                        "bin_files",
                        "relay");

                    SetRelayStatus(
                        "Статус: профиль расшифрован — проверяем конфигурацию встроенным sing-box…",
                        WpfBrushes.DeepSkyBlue);

                    SingBoxCheckResult engineCheck;
                    try
                    {
                        engineCheck = await _singBoxValidationService.ValidateAsync(
                            IOPath.Combine(singBoxRelayDir, "sing-box.exe"),
                            candidateProfile);
                    }
                    catch
                    {
                        candidateProfile.Dispose();
                        throw;
                    }

                    if (!engineCheck.Success)
                    {
                        RelayDetectedProfileTextBlock.Text =
                            BuildProviderRuntimeProfileSummary(candidateProfile) +
                            Environment.NewLine + Environment.NewLine +
                            "Проверка движком:" + Environment.NewLine +
                            "• " + engineCheck.EngineVersion + Environment.NewLine +
                            "• " + engineCheck.Message;
                        candidateProfile.Dispose();
                        SetRelayStatus(
                            "Статус: AVO-профиль расшифрован, но sing-box отклонил конфигурацию — " +
                            engineCheck.Message,
                            WpfBrushes.OrangeRed);
                        return;
                    }

                    _validatedProviderRuntimeProfile = candidateProfile;
                    RelayDetectedProfileTextBlock.Text =
                        BuildProviderRuntimeProfileSummary(_validatedProviderRuntimeProfile) +
                        Environment.NewLine + Environment.NewLine +
                        "Проверка движком:" + Environment.NewLine +
                        "• " + engineCheck.EngineVersion + Environment.NewLine +
                        "• " + engineCheck.Message;

                    string protocols = _validatedProviderRuntimeProfile.Protocols.Count > 0
                        ? string.Join(", ", _validatedProviderRuntimeProfile.Protocols.Select(
                            item => item.ToUpperInvariant()))
                        : "тип протоколов не указан";

                    SetRelayStatus(
                        $"Статус: AVO-ключ работает — sing-box принял конфигурацию; {protocols}.",
                        WpfBrushes.LightGreen);
                    return;
                }

                if (parseResult.Profile is null)
                {
                    _validatedRelayProfile = null;
                    RelayDetectedProfileTextBlock.Text = "Профиль подключения не создан.";
                    SetRelayStatus(
                        "Статус: Serpium Parser не вернул профиль подключения.",
                        WpfBrushes.OrangeRed);
                    return;
                }

                SerpiumConnectionProfile profile = parseResult.Profile;
                _validatedRelayProfile = profile;
                RelayDetectedProfileTextBlock.Text = BuildRelayProfileSummary(profile);
                SetRelayStatus(
                    $"Статус: проверяем {profile.Protocol.ToUpperInvariant()}-ключ и Xray-конфигурацию…",
                    WpfBrushes.DeepSkyBlue);

                string relayDir = IOPath.Combine(
                    IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                    "bin_files",
                    "relay");
                int socksPort = int.TryParse(RelayClientSocksPortTextBox.Text, out int port)
                    ? port
                    : 10808;

                SerpiumKeyValidationResult validation =
                    await _serpiumKeyValidationService.ValidateAsync(
                        IOPath.Combine(relayDir, "xray.exe"),
                        profile,
                        socksPort);

                if (!validation.ConfigValid)
                {
                    SetRelayStatus(
                        "Статус: Xray отклонил ключ — " + validation.Message,
                        WpfBrushes.OrangeRed);
                    return;
                }

                if (validation.ServerReachable)
                {
                    SetRelayStatus(
                        $"Статус: ключ распознан — {profile.Protocol.ToUpperInvariant()}; " +
                        $"сервер {profile.Server}:{profile.Port} доступен.",
                        WpfBrushes.LightGreen);
                }
                else
                {
                    SetRelayStatus(
                        $"Статус: ключ корректен, но сервер {profile.Server}:{profile.Port} " +
                        "не ответил на TCP-проверку.",
                        WpfBrushes.Goldenrod);
                }
            }
            catch (Exception ex)
            {
                SetRelayStatus("Статус: ошибка проверки — " + ex.Message, WpfBrushes.OrangeRed);
            }
            finally
            {
                ButtonValidateRelayKey.IsEnabled =
                    !_serpiumXraySessionManager.HasLiveProcess &&
                    _serpiumXraySessionManager.State is not RelayGatewayState.Starting and
                    not RelayGatewayState.Stopping;
            }
        }

        private void RelayClientKeyTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            _validatedRelayProfile = null;
            DisposeValidatedProviderRuntimeProfile();
            if (!IsLoaded)
                return;

            RelayDetectedProfileTextBlock.Text = string.IsNullOrWhiteSpace(RelayClientKeyTextBox.Text)
                ? "Формат ещё не определён."
                : "Ключ изменён — требуется повторная проверка.";
        }

        private void DisposeValidatedProviderRuntimeProfile()
        {
            ProviderRuntimeProfile? profile = _validatedProviderRuntimeProfile;
            _validatedProviderRuntimeProfile = null;
            try { profile?.Dispose(); } catch { }
        }

        private static string BuildProviderRuntimeProfileSummary(
            ProviderRuntimeProfile profile)
        {
            StringBuilder summary = new();
            summary.Append("AVO · ПРОФИЛЬ SING-BOX ПОДГОТОВЛЕН");
            summary.AppendLine();
            summary.Append("Профиль: ");
            summary.Append(profile.MaskedProfileId);
            summary.AppendLine();
            summary.Append("Движок: ");
            summary.Append(profile.Engine);
            summary.AppendLine();
            summary.Append("Конфигурация: ");
            summary.Append(profile.ConfigurationByteCount);
            summary.Append(" Б в оперативной памяти процесса");
            summary.AppendLine();
            summary.Append("Входы / выходы: ");
            summary.Append(profile.InboundCount);
            summary.Append(" / ");
            summary.Append(profile.OutboundCount);
            summary.AppendLine();
            summary.Append("Маршруты / DNS: ");
            summary.Append(profile.RouteRuleCount);
            summary.Append(" / ");
            summary.Append(profile.DnsServerCount);
            summary.AppendLine();
            summary.Append("Протоколы: ");
            summary.Append(profile.Protocols.Count > 0
                ? string.Join(", ", profile.Protocols.Select(item => item.ToUpperInvariant()))
                : "не определены");
            summary.AppendLine();
            summary.AppendLine();
            summary.AppendLine("Безопасная схема и результат маппинга:");
            summary.AppendLine(profile.SafeSchemaSummary);
            summary.Append("Адреса, пароли и полный JSON не выводятся в журнал.");
            return summary.ToString();
        }

        private string BuildProviderEnvelopeUnavailableMessage(ProviderEnvelope envelope)
        {
            IProviderEnvelopeAdapter? adapter =
                _providerEnvelopeAdapters.Find(envelope.Scheme);
            if (adapter is null)
            {
                return $"Обнаружен защищённый контейнер {envelope.DisplayScheme}. " +
                       "Его структура корректна, но провайдерский адаптер ещё не установлен.";
            }

            return $"Контейнер {envelope.DisplayScheme} распознан. " +
                   "После проверки будет подготовлен sing-box профиль в памяти.";
        }

        private static string BuildProviderEnvelopeSummary(ProviderEnvelope envelope)
        {
            StringBuilder summary = new();
            summary.Append("ПРОВАЙДЕРСКИЙ КОНТЕЙНЕР · ");
            summary.Append(envelope.DisplayScheme);
            summary.AppendLine();
            summary.Append("Провайдер: ");
            summary.Append(envelope.ProviderName);
            summary.AppendLine();
            summary.Append("Профиль: ");
            summary.Append(envelope.MaskedProfileId);
            summary.AppendLine();
            summary.Append("Защищённый пакет: ");
            summary.Append(envelope.PayloadByteCount);
            summary.Append(" Б");
            summary.AppendLine();
            summary.Append("Содержимое не выводится в журнал.");
            return summary.ToString();
        }

        private static string BuildRelayProfileSummary(SerpiumConnectionProfile profile)
        {
            StringBuilder summary = new();
            summary.Append(profile.Protocol.ToUpperInvariant());
            summary.Append(" · ");
            summary.Append(profile.Transport.ToUpperInvariant());
            summary.Append(" · ");
            summary.Append(profile.Security.ToUpperInvariant());
            summary.AppendLine();
            summary.Append("Сервер: ");
            summary.Append(profile.Server);
            summary.Append(':');
            summary.Append(profile.Port);

            if (!string.IsNullOrWhiteSpace(profile.ServerName) &&
                !string.Equals(profile.ServerName, profile.Server, StringComparison.OrdinalIgnoreCase))
            {
                summary.AppendLine();
                summary.Append("SNI: ");
                summary.Append(profile.ServerName);
            }

            if (!string.IsNullOrWhiteSpace(profile.Name))
            {
                summary.AppendLine();
                summary.Append("Профиль: ");
                summary.Append(profile.Name);
            }

            return summary.ToString();
        }

        private void SetRelayStatus(string text, WpfBrush brush)
        {
            RelayStatusTextBlock.Text = text;
            RelayStatusTextBlock.Foreground = brush;
            RelayStatusIndicator.Fill = brush;

            if (brush is SolidColorBrush solid)
            {
                RelayStatusBorder.BorderBrush = new SolidColorBrush(
                    Color.FromArgb(150, solid.Color.R, solid.Color.G, solid.Color.B));
            }
            else
            {
                RelayStatusBorder.BorderBrush = WpfBrushes.DimGray;
            }
        }

        private void SafeDispatcherInvoke(Action action)
        {
            if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
                return;
            try { Dispatcher.BeginInvoke(action); }
            catch (TaskCanceledException) { }
            catch (OperationCanceledException) { }
            catch (InvalidOperationException) { }
        }

    }
}





