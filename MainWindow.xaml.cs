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
using SerpiumVPN.Relay.Lifecycle;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Providers.Avo;
using SerpiumVPN.Relay.ProfileVault;
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
        private readonly DispatcherTimer _relayLifecycleTimer;
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
        private readonly SerpiumSingBoxSessionManager _serpiumSingBoxSessionManager = new();
        private readonly SerpiumXraySessionManager _serpiumXraySessionManager = new();
        private readonly SecureProfileVault _secureProfileVault = new();
        private SerpiumConnectionProfile? _validatedRelayProfile;
        private ProviderRuntimeProfile? _validatedProviderRuntimeProfile;
        private bool _suppressRelayKeyTextChanged;
        private bool _currentProviderProfileSaved;
        private IReadOnlyList<SecureProfileVaultEntry> _savedProfileEntries =
            Array.Empty<SecureProfileVaultEntry>();
        private Guid? _activeSavedProfileId;
        private int? _activeSavedProfileSocksPort;
        private bool _savedProfileOperationInProgress;
        private bool _relayLifecycleCheckInProgress;
        private Guid? _failedSavedProfileId;
        private string? _failedSavedProfileMessage;
        private DateTimeOffset _savedProfileInputBlockedUntil;
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
            _serpiumXraySessionManager.StateChanged += _ =>
                SafeDispatcherInvoke(UpdateRelayClientUi);
            _serpiumXraySessionManager.LogReceived += line => SafeDispatcherInvoke(() =>
            {
                RelayClientLogTextBox.AppendText(line + Environment.NewLine);
                RelayClientLogTextBox.ScrollToEnd();
            });
            _serpiumSingBoxSessionManager.StateChanged += _ =>
                SafeDispatcherInvoke(UpdateRelayClientUi);
            _serpiumSingBoxSessionManager.LogReceived += line => SafeDispatcherInvoke(() =>
            {
                RelayClientLogTextBox.AppendText(line + Environment.NewLine);
                RelayClientLogTextBox.ScrollToEnd();
            });
            _strategyMonitorTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMinutes(2)
            };
            _strategyMonitorTimer.Tick += StrategyMonitorTimer_TickAsync;
            _relayLifecycleTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            _relayLifecycleTimer.Tick += RelayLifecycleTimer_TickAsync;

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
            bool recoveredPreviousSession = await RecoverRelayLifecycleAtStartupAsync();
            await RefreshSecureProfileVaultStatusAsync();
            _relayLifecycleTimer.Start();

            if (recoveredPreviousSession)
            {
                SetRelayStatus(
                    "Статус: предыдущая незавершённая VPN-сессия очищена; профили готовы.",
                    WpfBrushes.Goldenrod);
            }

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
            _relayLifecycleTimer.Stop();
            _zapretManager.Stop();
            _telegramProxyManager.Stop();
            DisposeValidatedProviderRuntimeProfile();
            try
            {
                if (_serpiumSingBoxSessionManager.HasLiveProcess ||
                    _serpiumSingBoxSessionManager.State != RelayGatewayState.Stopped)
                {
                    _serpiumSingBoxSessionManager.StopAsync().GetAwaiter().GetResult();
                }
            }
            catch
            {
                // Kill-On-Close Job Object remains the final safety net.
            }
            try
            {
                if (_serpiumXraySessionManager.HasLiveProcess ||
                    _serpiumXraySessionManager.State != RelayGatewayState.Stopped)
                {
                    _serpiumXraySessionManager.StopAsync().GetAwaiter().GetResult();
                }
            }
            catch
            {
                // The owned-process cleanup below remains the final safety net.
            }
            try
            {
                RelayLifecycleRecovery.CleanupOwnedRuntimeAsync(
                    AppContext.BaseDirectory).GetAwaiter().GetResult();
            }
            catch
            {
                // Best effort during final application shutdown.
            }
            try { _serpiumSingBoxSessionManager.Dispose(); } catch { }
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
                if (_serpiumXraySessionManager.HasLiveProcess ||
                    _serpiumSingBoxSessionManager.HasLiveProcess)
                {
                    throw new InvalidOperationException(
                        "Подключение уже запущено. Сначала нажмите «Отключиться».");
                }

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

                    RelayClientLogTextBox.Clear();
                    SetRelayStatus(
                        "Статус: конфигурация принята — запускаем защищённый TUN sing-box…",
                        WpfBrushes.DeepSkyBlue);
                    RelayClientSocksStateTextBlock.Text = "TUN: запускается…";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.DeepSkyBlue;

                    await _serpiumSingBoxSessionManager.StartAsync(
                        IOPath.Combine(singBoxRelayDir, "sing-box.exe"),
                        candidateProfile);

                    string activeInterface =
                        _serpiumSingBoxSessionManager.InterfaceName ?? "Serpium TUN";
                    RelayClientSocksStateTextBlock.Text = $"TUN: активен ({activeInterface})";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.LightGreen;

                    string protocols = candidateProfile.Protocols.Count > 0
                        ? string.Join(", ", candidateProfile.Protocols.Select(
                            item => item.ToUpperInvariant()))
                        : "AVO";
                    _activeSavedProfileId = null;
                    ClearSavedProfileFailure();
                    _currentProviderProfileSaved = false;
                    ButtonSaveRelayProfile.Content = "Сохранить профиль";
                    SetRelayStatus(
                        $"Статус: подключено через AVO — {protocols}; TUN {activeInterface}.",
                        WpfBrushes.LightGreen);
                    UpdateRelayClientUi();
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

                _activeSavedProfileId = null;
                _activeSavedProfileSocksPort = socksPort;
                ClearSavedProfileFailure();
                _currentProviderProfileSaved = false;
                ButtonSaveRelayProfile.Content = "Сохранить профиль";
                RelayClientSocksStateTextBlock.Text = $"SOCKS5: активен (127.0.0.1:{socksPort})";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.LightGreen;
                SetRelayStatus(
                    $"Статус: подключено через Xray — {profile.Protocol.ToUpperInvariant()}, " +
                    $"SOCKS5 127.0.0.1:{socksPort}",
                    WpfBrushes.LightGreen);
                UpdateRelayClientUi();
            }
            catch (Exception ex)
            {
                RelayClientSocksStateTextBlock.Text = "SOCKS5: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                SetRelayStatus("Статус: ошибка подключения — " + ex.Message, WpfBrushes.OrangeRed);
                UpdateRelayClientUi();
            }
        }

        private async void StopRelayClient_ClickAsync(object sender, RoutedEventArgs e)
        {
            Exception? stopError = null;
            try
            {
                SetRelayStatus("Статус: отключение…", WpfBrushes.Goldenrod);

                bool stopSingBox =
                    _serpiumSingBoxSessionManager.HasLiveProcess ||
                    _serpiumSingBoxSessionManager.State is RelayGatewayState.Starting or
                        RelayGatewayState.Running or RelayGatewayState.Stopping or
                        RelayGatewayState.Failed;
                bool stopXray =
                    _serpiumXraySessionManager.HasLiveProcess ||
                    _serpiumXraySessionManager.State is RelayGatewayState.Starting or
                        RelayGatewayState.Running or RelayGatewayState.Stopping or
                        RelayGatewayState.Failed;

                if (stopSingBox)
                {
                    try
                    {
                        await _serpiumSingBoxSessionManager.StopAsync();
                    }
                    catch (Exception ex)
                    {
                        stopError ??= ex;
                    }
                }

                if (stopXray)
                {
                    try
                    {
                        await _serpiumXraySessionManager.StopAsync();
                    }
                    catch (Exception ex)
                    {
                        stopError ??= ex;
                    }
                }

                _validatedRelayProfile = null;
                DisposeValidatedProviderRuntimeProfile();
                _activeSavedProfileId = null;
                _activeSavedProfileSocksPort = null;
                ClearSavedProfileFailure();
                _currentProviderProfileSaved = false;
                ButtonSaveRelayProfile.Content = "Сохранить профиль";
                RelayClientSocksStateTextBlock.Text = "Транспорт: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);
                UpdateRelayClientUi();
                await RefreshSecureProfileVaultStatusAsync();

                if (stopError is not null)
                    throw stopError;

                SetRelayStatus("Статус: отключено; TUN и маршруты освобождены.", WpfBrushes.Gray);
            }
            catch (Exception ex)
            {
                SetRelayStatus("Статус: ошибка отключения — " + ex.Message, WpfBrushes.OrangeRed);
            }
        }

        private void UpdateRelayClientUi()
        {
            RelayGatewayState xrayState = _serpiumXraySessionManager.State;
            RelayGatewayState singBoxState = _serpiumSingBoxSessionManager.State;

            bool xrayBusy = xrayState is RelayGatewayState.Starting or RelayGatewayState.Stopping;
            bool singBoxBusy = singBoxState is RelayGatewayState.Starting or RelayGatewayState.Stopping;
            bool xrayRunning = xrayState == RelayGatewayState.Running ||
                               _serpiumXraySessionManager.HasLiveProcess;
            bool singBoxRunning = singBoxState == RelayGatewayState.Running ||
                                  _serpiumSingBoxSessionManager.HasLiveProcess;
            bool isBusy = xrayBusy || singBoxBusy;
            bool isRunning = xrayRunning || singBoxRunning;
            bool providerMode =
                _validatedProviderRuntimeProfile is not null ||
                singBoxState != RelayGatewayState.Stopped ||
                singBoxRunning;

            ButtonStartRelayClient.IsEnabled = !isBusy && !isRunning;
            ButtonStopRelayClient.IsEnabled = isBusy || isRunning ||
                xrayState == RelayGatewayState.Failed ||
                singBoxState == RelayGatewayState.Failed;
            ButtonValidateRelayKey.IsEnabled = !isBusy && !isRunning;
            ButtonSaveRelayProfile.IsEnabled =
                !isBusy && !_currentProviderProfileSaved &&
                ((singBoxRunning && _validatedProviderRuntimeProfile is not null) ||
                 (xrayRunning && _validatedRelayProfile is not null));
            ButtonSaveRelayProfile.Content = _currentProviderProfileSaved
                ? "Профиль сохранён"
                : "Сохранить профиль";
            RelayClientKeyTextBox.IsReadOnly = isBusy || isRunning;
            RelayClientSocksPortTextBox.IsEnabled = !providerMode && !isBusy && !isRunning;

            RelayGatewayState visibleState = providerMode ? singBoxState : xrayState;
            RelayClientStateTextBlock.Text = providerMode
                ? visibleState switch
                {
                    RelayGatewayState.Starting => "sing-box: запускается…",
                    RelayGatewayState.Running => "sing-box: работает",
                    RelayGatewayState.Stopping => "sing-box: останавливается…",
                    RelayGatewayState.Failed => "sing-box: ошибка",
                    _ => "sing-box: остановлен"
                }
                : visibleState switch
                {
                    RelayGatewayState.Starting => "Xray: запускается…",
                    RelayGatewayState.Running => "Xray: работает",
                    RelayGatewayState.Stopping => "Xray: останавливается…",
                    RelayGatewayState.Failed => "Xray: ошибка",
                    _ => "Xray: остановлен"
                };

            RelayClientStateTextBlock.Foreground = visibleState switch
            {
                RelayGatewayState.Running => WpfBrushes.LightGreen,
                RelayGatewayState.Failed => WpfBrushes.OrangeRed,
                RelayGatewayState.Starting => WpfBrushes.DeepSkyBlue,
                RelayGatewayState.Stopping => WpfBrushes.Goldenrod,
                _ => WpfBrushes.Gray
            };

            if (providerMode)
            {
                RelayClientSocksStateTextBlock.Text = visibleState switch
                {
                    RelayGatewayState.Starting => "TUN: запускается…",
                    RelayGatewayState.Running =>
                        $"TUN: активен ({_serpiumSingBoxSessionManager.InterfaceName ?? "Serpium"})",
                    RelayGatewayState.Stopping => "TUN: освобождает маршруты…",
                    _ => "TUN: остановлен"
                };
            }
            else if (!xrayRunning)
            {
                RelayClientSocksStateTextBlock.Text = "SOCKS5: остановлен";
            }

            RelayClientSocksStateTextBlock.Foreground = visibleState switch
            {
                RelayGatewayState.Running => WpfBrushes.LightGreen,
                RelayGatewayState.Failed => WpfBrushes.OrangeRed,
                RelayGatewayState.Starting => WpfBrushes.DeepSkyBlue,
                RelayGatewayState.Stopping => WpfBrushes.Goldenrod,
                _ => WpfBrushes.Gray
            };

            if (singBoxState == RelayGatewayState.Failed &&
                !string.IsNullOrWhiteSpace(_serpiumSingBoxSessionManager.LastError))
            {
                SetRelayStatus(
                    "Статус: TUN-соединение завершилось с ошибкой — " +
                    _serpiumSingBoxSessionManager.LastError,
                    WpfBrushes.OrangeRed);
            }
            else if (xrayState == RelayGatewayState.Failed &&
                     !string.IsNullOrWhiteSpace(_serpiumXraySessionManager.LastError))
            {
                SetRelayStatus(
                    "Статус: соединение завершилось с ошибкой — " +
                    _serpiumXraySessionManager.LastError,
                    WpfBrushes.OrangeRed);
            }

            RenderSavedProfileCards(_savedProfileEntries);
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

        private async void SaveRelayProfile_ClickAsync(object sender, RoutedEventArgs e)
        {
            ButtonSaveRelayProfile.IsEnabled = false;
            try
            {
                bool providerReady =
                    _validatedProviderRuntimeProfile is not null &&
                    _serpiumSingBoxSessionManager.HasLiveProcess &&
                    _serpiumSingBoxSessionManager.State == RelayGatewayState.Running;
                bool xrayReady =
                    _validatedRelayProfile is not null &&
                    _serpiumXraySessionManager.HasLiveProcess &&
                    _serpiumXraySessionManager.State == RelayGatewayState.Running;

                if (!providerReady && !xrayReady)
                {
                    throw new InvalidOperationException(
                        "Профиль можно сохранить только после успешного подключения.");
                }

                string sourceKey = RelayClientKeyTextBox.Text.Trim();
                if (string.IsNullOrWhiteSpace(sourceKey))
                {
                    throw new InvalidOperationException(
                        "Исходный ключ уже очищен или отсутствует. Повторите подключение.");
                }

                SetRelayStatus(
                    "Статус: защищаем подготовленный профиль через Windows DPAPI…",
                    WpfBrushes.DeepSkyBlue);

                SecureProfileVaultSaveResult result;
                string profileSummary;
                string sourceDescription;

                if (providerReady)
                {
                    ProviderRuntimeProfile providerProfile =
                        _validatedProviderRuntimeProfile!;
                    if (!sourceKey.StartsWith("avo://", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            "Текущий AVO-профиль не соответствует ключу в поле ввода.");
                    }

                    result = await _secureProfileVault.SaveProviderProfileAsync(
                        providerProfile,
                        sourceKey);
                    profileSummary = BuildProviderRuntimeProfileSummary(providerProfile);
                    sourceDescription = "Исходный avo:// ключ не сохранён";
                }
                else
                {
                    SerpiumConnectionProfile xrayProfile = _validatedRelayProfile!;
                    SerpiumParseResult verification = _serpiumParser.Parse(sourceKey);
                    if (!verification.Success || verification.Profile is null ||
                        verification.Envelope is not null ||
                        !string.Equals(
                            verification.Profile.Protocol,
                            xrayProfile.Protocol,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            "Текущий Xray-профиль не соответствует ключу в поле ввода.");
                    }

                    int socksPort = int.TryParse(
                        RelayClientSocksPortTextBox.Text.Trim(),
                        out int parsedPort) && parsedPort is >= 1 and <= 65535
                            ? parsedPort
                            : 10808;

                    result = await _secureProfileVault.SaveXrayProfileAsync(
                        xrayProfile,
                        socksPort,
                        sourceKey);
                    _activeSavedProfileSocksPort = socksPort;
                    profileSummary = BuildRelayProfileSummary(xrayProfile);
                    sourceDescription =
                        $"Исходный {xrayProfile.Protocol.ToLowerInvariant()}:// ключ не сохранён";
                }

                _currentProviderProfileSaved = true;
                _activeSavedProfileId = result.Entry.Id;
                _suppressRelayKeyTextChanged = true;
                try
                {
                    RelayClientKeyTextBox.Clear();
                    try
                    {
                        if (Clipboard.ContainsText() &&
                            string.Equals(
                                Clipboard.GetText().Trim(),
                                sourceKey,
                                StringComparison.Ordinal))
                        {
                            Clipboard.Clear();
                        }
                    }
                    catch
                    {
                        // Clipboard may be temporarily locked by another process.
                    }
                }
                finally
                {
                    _suppressRelayKeyTextChanged = false;
                }

                RelayDetectedProfileTextBlock.Text =
                    profileSummary +
                    Environment.NewLine + Environment.NewLine +
                    "Защищённое хранилище:" + Environment.NewLine +
                    $"• {result.Entry.SafeDisplayName}" + Environment.NewLine +
                    $"• {sourceDescription} и удалён из поля ввода." + Environment.NewLine +
                    "• Подготовленный профиль защищён DPAPI CurrentUser.";

                await RefreshSecureProfileVaultStatusAsync();
                SetRelayStatus(
                    result.UpdatedExisting
                        ? "Статус: сохранённый профиль обновлён; исходный ключ очищен."
                        : "Статус: профиль сохранён защищённо; исходный ключ очищен.",
                    WpfBrushes.LightGreen);
            }
            catch (Exception ex)
            {
                SetRelayStatus(
                    "Статус: профиль не сохранён — " + ex.Message,
                    WpfBrushes.OrangeRed);
            }
            finally
            {
                UpdateRelayClientUi();
            }
        }

        private async Task RefreshSecureProfileVaultStatusAsync()
        {
            try
            {
                _savedProfileEntries = await _secureProfileVault.ListProfilesAsync();
                RelaySavedProfilesSection.Visibility = _savedProfileEntries.Count == 0
                    ? Visibility.Collapsed
                    : Visibility.Visible;
                RelaySavedProfilesHeaderTextBlock.Text =
                    $"Профили: {_savedProfileEntries.Count}";
                RelayProfileVaultStateTextBlock.Text = _savedProfileEntries.Count == 0
                    ? "Защищённое хранилище: профилей пока нет."
                    : $"Защищённое хранилище: профилей {_savedProfileEntries.Count}.";
                RelayProfileVaultStateTextBlock.Foreground = _savedProfileEntries.Count == 0
                    ? WpfBrushes.Gray
                    : WpfBrushes.LightGreen;
                RenderSavedProfileCards(_savedProfileEntries);
            }
            catch (Exception ex)
            {
                _savedProfileEntries = Array.Empty<SecureProfileVaultEntry>();
                RelaySavedProfilesPanel.Children.Clear();
                RelaySavedProfilesSection.Visibility = Visibility.Collapsed;
                RelayProfileVaultStateTextBlock.Text =
                    "Защищённое хранилище недоступно: " + ex.Message;
                RelayProfileVaultStateTextBlock.Foreground = WpfBrushes.OrangeRed;
            }
        }

        private void RenderSavedProfileCards(
            IReadOnlyList<SecureProfileVaultEntry> profiles)
        {
            if (RelaySavedProfilesPanel is null)
                return;

            RelaySavedProfilesPanel.Children.Clear();
            bool engineRunning =
                (_serpiumSingBoxSessionManager.HasLiveProcess &&
                 _serpiumSingBoxSessionManager.State == RelayGatewayState.Running) ||
                (_serpiumXraySessionManager.HasLiveProcess &&
                 _serpiumXraySessionManager.State == RelayGatewayState.Running);
            bool hasActiveProfile = _activeSavedProfileId.HasValue && engineRunning;

            foreach (SecureProfileVaultEntry entry in profiles)
            {
                bool isActive = hasActiveProfile && _activeSavedProfileId == entry.Id;
                bool isFailed = !isActive && _failedSavedProfileId == entry.Id;
                bool blockedByAnother = hasActiveProfile && !isActive;

                System.Windows.Controls.Border card = new()
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x11, 0x11, 0x18)),
                    BorderBrush = isActive
                        ? new SolidColorBrush(Color.FromRgb(0x33, 0xD1, 0x7A))
                        : isFailed
                            ? new SolidColorBrush(Color.FromRgb(0xFF, 0x8A, 0x3D))
                            : new SolidColorBrush(Color.FromRgb(0x2D, 0x2D, 0x3A)),
                    BorderThickness = new Thickness(isActive ? 1.5 : 1),
                    CornerRadius = new CornerRadius(9),
                    Padding = new Thickness(14, 12, 12, 12),
                    Margin = new Thickness(0, 0, 0, 10),
                    Opacity = blockedByAnother ? 0.38 : 1.0,
                    IsHitTestVisible = !blockedByAnother
                };

                System.Windows.Controls.Grid layout = new();
                layout.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition
                {
                    Width = new GridLength(1, GridUnitType.Star)
                });
                layout.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition
                {
                    Width = GridLength.Auto
                });
                layout.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition
                {
                    Width = GridLength.Auto
                });

                System.Windows.Controls.StackPanel description = new();
                description.Children.Add(new System.Windows.Controls.TextBlock
                {
                    Text = entry.SafeDisplayName,
                    Foreground = WpfBrushes.White,
                    FontSize = 15,
                    FontWeight = FontWeights.SemiBold,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
                description.Children.Add(new System.Windows.Controls.TextBlock
                {
                    Text = entry.Protocols.Count == 0
                        ? entry.Engine.ToUpperInvariant()
                        : string.Join(" · ", entry.Protocols.Select(
                            protocol => protocol.ToUpperInvariant())),
                    Foreground = new SolidColorBrush(Color.FromRgb(0x9B, 0x9B, 0xA8)),
                    Margin = new Thickness(0, 4, 0, 0),
                    TextWrapping = TextWrapping.Wrap
                });
                description.Children.Add(new System.Windows.Controls.TextBlock
                {
                    Text = isActive
                        ? string.Equals(entry.Engine, "xray", StringComparison.OrdinalIgnoreCase)
                            ? $"Подключён · SOCKS5 127.0.0.1:{_activeSavedProfileSocksPort ?? 10808}"
                            : $"Подключён · TUN {_serpiumSingBoxSessionManager.InterfaceName ?? "Serpium"}"
                        : blockedByAnother
                            ? "Недоступен, пока активен другой профиль"
                            : isFailed
                                ? "Ошибка · " + (_failedSavedProfileMessage ?? "движок остановлен")
                                : "Готов к подключению",
                    Foreground = isActive
                        ? WpfBrushes.LightGreen
                        : isFailed
                            ? WpfBrushes.OrangeRed
                            : WpfBrushes.Gray,
                    Margin = new Thickness(0, 5, 0, 0),
                    FontSize = 12
                });
                layout.Children.Add(description);

                System.Windows.Controls.Primitives.ToggleButton toggle = new()
                {
                    Style = (Style)RelaySavedProfilesSection.FindResource("RelayProfileToggleStyle"),
                    IsChecked = isActive,
                    IsEnabled = !_savedProfileOperationInProgress &&
                                (!hasActiveProfile || isActive),
                    Tag = entry.Id,
                    Margin = new Thickness(16, 0, 10, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                    ToolTip = isActive ? "Отключить профиль" : "Подключить профиль"
                };
                toggle.Checked += SavedProfileToggle_CheckedAsync;
                toggle.Unchecked += SavedProfileToggle_UncheckedAsync;
                System.Windows.Controls.Grid.SetColumn(toggle, 1);
                layout.Children.Add(toggle);

                System.Windows.Controls.Button deleteButton = new()
                {
                    Style = (Style)RelaySavedProfilesSection.FindResource("RelayProfileDeleteButtonStyle"),
                    Content = "🗑",
                    Tag = entry.Id,
                    IsEnabled = !_savedProfileOperationInProgress &&
                                (!hasActiveProfile || isActive),
                    VerticalAlignment = VerticalAlignment.Center,
                    ToolTip = "Удалить профиль"
                };
                deleteButton.Click += DeleteSavedProfile_ClickAsync;
                System.Windows.Controls.Grid.SetColumn(deleteButton, 2);
                layout.Children.Add(deleteButton);

                card.Child = layout;
                RelaySavedProfilesPanel.Children.Add(card);
            }
        }

        private async void SavedProfileToggle_CheckedAsync(
            object sender,
            RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Primitives.ToggleButton toggle ||
                toggle.Tag is not Guid profileId ||
                _savedProfileOperationInProgress ||
                DateTimeOffset.UtcNow < _savedProfileInputBlockedUntil)
            {
                return;
            }

            _savedProfileInputBlockedUntil = DateTimeOffset.UtcNow.AddMilliseconds(900);

            bool anySavedEngineRunning =
                _serpiumSingBoxSessionManager.State == RelayGatewayState.Running ||
                _serpiumXraySessionManager.State == RelayGatewayState.Running;
            if (_activeSavedProfileId == profileId && anySavedEngineRunning)
                return;

            if (_serpiumXraySessionManager.HasLiveProcess ||
                _serpiumSingBoxSessionManager.HasLiveProcess)
            {
                SetRelayStatus(
                    "Статус: сначала отключите текущее соединение.",
                    WpfBrushes.Goldenrod);
                await RefreshSecureProfileVaultStatusAsync();
                return;
            }

            SecureProfileVaultEntry? entry =
                _savedProfileEntries.FirstOrDefault(item => item.Id == profileId);
            if (entry is null)
            {
                SetRelayStatus(
                    "Статус: сохранённый профиль не найден.",
                    WpfBrushes.OrangeRed);
                await RefreshSecureProfileVaultStatusAsync();
                return;
            }

            _savedProfileOperationInProgress = true;
            if (_failedSavedProfileId == profileId)
                ClearSavedProfileFailure();
            RenderSavedProfileCards(_savedProfileEntries);
            try
            {
                SetRelayStatus(
                    "Статус: открываем сохранённый профиль через Windows DPAPI…",
                    WpfBrushes.DeepSkyBlue);
                RelayClientLogTextBox.Clear();

                if (string.Equals(entry.Engine, "xray", StringComparison.OrdinalIgnoreCase))
                {
                    DisposeValidatedProviderRuntimeProfile();
                    SecureXrayVaultProfile savedXray =
                        await _secureProfileVault.OpenXrayProfileAsync(profileId);
                    _validatedRelayProfile = savedXray.Profile;
                    _activeSavedProfileSocksPort = savedXray.SocksPort;

                    string relayDir = IOPath.Combine(
                        IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                        "bin_files",
                        "relay");

                    RelayClientSocksStateTextBlock.Text = "SOCKS5: запускается…";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.DeepSkyBlue;
                    await _serpiumXraySessionManager.StartAsync(
                        IOPath.Combine(relayDir, "xray.exe"),
                        IOPath.Combine(relayDir, "configs", "key-client.json"),
                        savedXray.Profile,
                        savedXray.SocksPort);

                    _activeSavedProfileId = profileId;
                    ClearSavedProfileFailure();
                    _currentProviderProfileSaved = true;
                    RelayDetectedProfileTextBlock.Text =
                        BuildRelayProfileSummary(savedXray.Profile) +
                        Environment.NewLine + Environment.NewLine +
                        "Профиль загружен из Serpium Secure Profile Vault.";
                    RelayClientSocksStateTextBlock.Text =
                        $"SOCKS5: активен (127.0.0.1:{savedXray.SocksPort})";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.LightGreen;
                    SetRelayStatus(
                        $"Статус: сохранённый профиль подключён через Xray — " +
                        $"{savedXray.Profile.Protocol.ToUpperInvariant()}, " +
                        $"SOCKS5 127.0.0.1:{savedXray.SocksPort}.",
                        WpfBrushes.LightGreen);
                }
                else
                {
                    _validatedRelayProfile = null;
                    _activeSavedProfileSocksPort = null;
                    DisposeValidatedProviderRuntimeProfile();
                    _validatedProviderRuntimeProfile =
                        await _secureProfileVault.OpenProviderProfileAsync(profileId);

                    string singBoxRelayDir = IOPath.Combine(
                        IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                        "bin_files",
                        "relay");

                    RelayClientSocksStateTextBlock.Text = "TUN: запускается…";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.DeepSkyBlue;
                    await _serpiumSingBoxSessionManager.StartAsync(
                        IOPath.Combine(singBoxRelayDir, "sing-box.exe"),
                        _validatedProviderRuntimeProfile);

                    _activeSavedProfileId = profileId;
                    ClearSavedProfileFailure();
                    _currentProviderProfileSaved = true;
                    RelayDetectedProfileTextBlock.Text =
                        BuildProviderRuntimeProfileSummary(_validatedProviderRuntimeProfile) +
                        Environment.NewLine + Environment.NewLine +
                        "Профиль загружен из Serpium Secure Profile Vault.";

                    string protocols = _validatedProviderRuntimeProfile.Protocols.Count > 0
                        ? string.Join(", ", _validatedProviderRuntimeProfile.Protocols.Select(
                            item => item.ToUpperInvariant()))
                        : "AVO";
                    string activeInterface =
                        _serpiumSingBoxSessionManager.InterfaceName ?? "Serpium TUN";
                    SetRelayStatus(
                        $"Статус: сохранённый профиль подключён — {protocols}; " +
                        $"TUN {activeInterface}.",
                        WpfBrushes.LightGreen);
                }
            }
            catch (Exception ex)
            {
                _failedSavedProfileId = profileId;
                _failedSavedProfileMessage = NormalizeLifecycleError(ex.Message);
                _activeSavedProfileId = null;
                _activeSavedProfileSocksPort = null;
                _currentProviderProfileSaved = false;
                _validatedRelayProfile = null;
                DisposeValidatedProviderRuntimeProfile();
                RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);
                SetRelayStatus(
                    "Статус: сохранённый профиль не подключён — " + ex.Message,
                    WpfBrushes.OrangeRed);
            }
            finally
            {
                _savedProfileOperationInProgress = false;
                UpdateRelayClientUi();
                await RefreshSecureProfileVaultStatusAsync();
            }
        }

        private async void SavedProfileToggle_UncheckedAsync(
            object sender,
            RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Primitives.ToggleButton toggle ||
                toggle.Tag is not Guid profileId ||
                _activeSavedProfileId != profileId ||
                _savedProfileOperationInProgress ||
                DateTimeOffset.UtcNow < _savedProfileInputBlockedUntil)
            {
                return;
            }

            _savedProfileInputBlockedUntil = DateTimeOffset.UtcNow.AddMilliseconds(900);
            _savedProfileOperationInProgress = true;
            RenderSavedProfileCards(_savedProfileEntries);
            try
            {
                SetRelayStatus("Статус: отключение профиля…", WpfBrushes.Goldenrod);
                await StopActiveSavedProfileAsync();
                SetRelayStatus(
                    "Статус: профиль отключён; сетевой транспорт освобождён.",
                    WpfBrushes.Gray);
            }
            catch (Exception ex)
            {
                SetRelayStatus(
                    "Статус: ошибка отключения профиля — " + ex.Message,
                    WpfBrushes.OrangeRed);
            }
            finally
            {
                _savedProfileOperationInProgress = false;
                UpdateRelayClientUi();
                await RefreshSecureProfileVaultStatusAsync();
            }
        }

        private async Task StopActiveSavedProfileAsync()
        {
            Exception? stopError = null;
            try
            {
                if (_serpiumSingBoxSessionManager.HasLiveProcess ||
                    _serpiumSingBoxSessionManager.State is RelayGatewayState.Starting or
                        RelayGatewayState.Running or RelayGatewayState.Stopping or
                        RelayGatewayState.Failed)
                {
                    try
                    {
                        await _serpiumSingBoxSessionManager.StopAsync();
                    }
                    catch (Exception ex)
                    {
                        stopError ??= ex;
                    }
                }

                if (_serpiumXraySessionManager.HasLiveProcess ||
                    _serpiumXraySessionManager.State is RelayGatewayState.Starting or
                        RelayGatewayState.Running or RelayGatewayState.Stopping or
                        RelayGatewayState.Failed)
                {
                    try
                    {
                        await _serpiumXraySessionManager.StopAsync();
                    }
                    catch (Exception ex)
                    {
                        stopError ??= ex;
                    }
                }
            }
            finally
            {
                _activeSavedProfileId = null;
                _activeSavedProfileSocksPort = null;
                ClearSavedProfileFailure();
                _currentProviderProfileSaved = false;
                _validatedRelayProfile = null;
                DisposeValidatedProviderRuntimeProfile();
                RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);
                ButtonSaveRelayProfile.Content = "Сохранить профиль";
                RelayClientSocksStateTextBlock.Text = "Транспорт: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
            }

            if (stopError is not null)
                throw stopError;
        }

        private async void DeleteSavedProfile_ClickAsync(
            object sender,
            RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button button ||
                button.Tag is not Guid profileId ||
                _savedProfileOperationInProgress)
            {
                return;
            }

            SecureProfileVaultEntry? profileEntry = _savedProfileEntries
                .FirstOrDefault(entry => entry.Id == profileId);

            ProfileDeleteConfirmDialog confirmationDialog = new(
                profileEntry?.SafeDisplayName ?? "Выбранный профиль")
            {
                Owner = this
            };

            if (confirmationDialog.ShowDialog() != true)
                return;

            _savedProfileOperationInProgress = true;
            RenderSavedProfileCards(_savedProfileEntries);
            try
            {
                if (_activeSavedProfileId == profileId)
                    await StopActiveSavedProfileAsync();

                bool deleted = await _secureProfileVault.DeleteProfileAsync(profileId);
                if (_failedSavedProfileId == profileId)
                    ClearSavedProfileFailure();
                SetRelayStatus(
                    deleted
                        ? "Статус: профиль и его сохранённые данные удалены."
                        : "Статус: профиль уже отсутствует в хранилище.",
                    deleted ? WpfBrushes.LightGreen : WpfBrushes.Goldenrod);
            }
            catch (Exception ex)
            {
                SetRelayStatus(
                    "Статус: профиль не удалён — " + ex.Message,
                    WpfBrushes.OrangeRed);
            }
            finally
            {
                _savedProfileOperationInProgress = false;
                UpdateRelayClientUi();
                await RefreshSecureProfileVaultStatusAsync();
            }
        }

        private async Task<bool> RecoverRelayLifecycleAtStartupAsync()
        {
            _activeSavedProfileId = null;
            _activeSavedProfileSocksPort = null;
            ClearSavedProfileFailure();

            bool managerReportedRuntime =
                _serpiumSingBoxSessionManager.HasLiveProcess ||
                _serpiumXraySessionManager.HasLiveProcess;

            if (managerReportedRuntime)
            {
                SetRelayStatus(
                    "Статус: очищаем незавершённую предыдущую VPN-сессию…",
                    WpfBrushes.Goldenrod);
            }

            try
            {
                if (_serpiumSingBoxSessionManager.HasLiveProcess)
                {
                    try
                    {
                        await _serpiumSingBoxSessionManager.StopAsync();
                    }
                    catch
                    {
                        // The owned-process sweep below is the fallback.
                    }
                }

                if (_serpiumXraySessionManager.HasLiveProcess)
                {
                    try
                    {
                        await _serpiumXraySessionManager.StopAsync();
                    }
                    catch
                    {
                        // The owned-process sweep below is the fallback.
                    }
                }

                RelayLifecycleCleanupResult cleanup =
                    await RelayLifecycleRecovery.CleanupOwnedRuntimeAsync(
                        AppContext.BaseDirectory);

                return managerReportedRuntime ||
                       cleanup.ProcessesStopped > 0 ||
                       cleanup.FilesDeleted > 0;
            }
            finally
            {
                _validatedRelayProfile = null;
                DisposeValidatedProviderRuntimeProfile();
                _currentProviderProfileSaved = false;
                RelayClientSocksStateTextBlock.Text = "Транспорт: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                UpdateRelayClientUi();
            }
        }

        private async void RelayLifecycleTimer_TickAsync(
            object? sender,
            EventArgs e)
        {
            if (_relayLifecycleCheckInProgress ||
                _savedProfileOperationInProgress ||
                !_activeSavedProfileId.HasValue ||
                _isRealExit)
            {
                return;
            }

            _relayLifecycleCheckInProgress = true;
            try
            {
                Guid profileId = _activeSavedProfileId.Value;
                SecureProfileVaultEntry? entry =
                    _savedProfileEntries.FirstOrDefault(item => item.Id == profileId);
                if (entry is null)
                {
                    await MarkSavedProfileRuntimeFailedAsync(
                        profileId,
                        "профиль удалён или недоступен");
                    return;
                }

                bool xrayLive = _serpiumXraySessionManager.HasLiveProcess;
                bool singBoxLive = _serpiumSingBoxSessionManager.HasLiveProcess;
                bool expectsXray =
                    string.Equals(entry.Engine, "xray", StringComparison.OrdinalIgnoreCase);

                if (xrayLive && singBoxLive)
                {
                    await StopAllRelayTransportsBestEffortAsync();
                    await MarkSavedProfileRuntimeFailedAsync(
                        profileId,
                        "обнаружены два одновременно запущенных транспорта");
                    return;
                }

                RelayGatewayState expectedState = expectsXray
                    ? _serpiumXraySessionManager.State
                    : _serpiumSingBoxSessionManager.State;
                bool expectedLive = expectsXray ? xrayLive : singBoxLive;
                bool unexpectedLive = expectsXray ? singBoxLive : xrayLive;

                if (unexpectedLive)
                {
                    await StopAllRelayTransportsBestEffortAsync();
                    await MarkSavedProfileRuntimeFailedAsync(
                        profileId,
                        "запущен транспорт другого профиля");
                    return;
                }

                if (expectedState == RelayGatewayState.Failed)
                {
                    if (expectedLive)
                        await StopAllRelayTransportsBestEffortAsync();

                    string failedReason = expectsXray
                        ? _serpiumXraySessionManager.LastError ??
                          "Xray завершился с ошибкой"
                        : _serpiumSingBoxSessionManager.LastError ??
                          "sing-box завершился с ошибкой";

                    await MarkSavedProfileRuntimeFailedAsync(
                        profileId,
                        failedReason);
                    return;
                }

                if (!expectedLive &&
                    expectedState != RelayGatewayState.Starting &&
                    expectedState != RelayGatewayState.Stopping)
                {
                    string reason = expectsXray
                        ? _serpiumXraySessionManager.LastError ??
                          "Xray неожиданно завершился"
                        : _serpiumSingBoxSessionManager.LastError ??
                          "sing-box неожиданно завершился";

                    await MarkSavedProfileRuntimeFailedAsync(profileId, reason);
                }
            }
            catch (Exception ex)
            {
                SetRelayStatus(
                    "Статус: проверка состояния VPN завершилась ошибкой — " +
                    NormalizeLifecycleError(ex.Message),
                    WpfBrushes.OrangeRed);
            }
            finally
            {
                _relayLifecycleCheckInProgress = false;
            }
        }

        private async Task StopAllRelayTransportsBestEffortAsync()
        {
            try
            {
                if (_serpiumSingBoxSessionManager.HasLiveProcess ||
                    _serpiumSingBoxSessionManager.State != RelayGatewayState.Stopped)
                {
                    await _serpiumSingBoxSessionManager.StopAsync();
                }
            }
            catch
            {
                // Continue with the second manager and process sweep.
            }

            try
            {
                if (_serpiumXraySessionManager.HasLiveProcess ||
                    _serpiumXraySessionManager.State != RelayGatewayState.Stopped)
                {
                    await _serpiumXraySessionManager.StopAsync();
                }
            }
            catch
            {
                // The process sweep below is the final fallback.
            }

            await RelayLifecycleRecovery.CleanupOwnedRuntimeAsync(
                AppContext.BaseDirectory);
        }

        private async Task MarkSavedProfileRuntimeFailedAsync(
            Guid profileId,
            string reason)
        {
            _failedSavedProfileId = profileId;
            _failedSavedProfileMessage = NormalizeLifecycleError(reason);
            _activeSavedProfileId = null;
            _activeSavedProfileSocksPort = null;
            _currentProviderProfileSaved = false;
            _validatedRelayProfile = null;
            DisposeValidatedProviderRuntimeProfile();
            RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);

            RelayClientSocksStateTextBlock.Text = "Транспорт: остановлен";
            RelayClientSocksStateTextBlock.Foreground = WpfBrushes.OrangeRed;
            SetRelayStatus(
                "Статус: активный профиль аварийно остановлен — " +
                _failedSavedProfileMessage,
                WpfBrushes.OrangeRed);

            UpdateRelayClientUi();
            await RefreshSecureProfileVaultStatusAsync();
        }

        private void ClearSavedProfileFailure()
        {
            _failedSavedProfileId = null;
            _failedSavedProfileMessage = null;
        }

        private static string NormalizeLifecycleError(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "движок неожиданно завершился";

            string normalized = value
                .Replace('\r', ' ')
                .Replace('\n', ' ')
                .Trim();

            while (normalized.Contains("  ", StringComparison.Ordinal))
                normalized = normalized.Replace("  ", " ", StringComparison.Ordinal);

            return normalized.Length <= 120
                ? normalized
                : normalized[..117] + "…";
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
                UpdateRelayClientUi();
            }
        }

        private void RelayClientKeyTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (_suppressRelayKeyTextChanged)
                return;

            _currentProviderProfileSaved = false;
            _activeSavedProfileSocksPort = null;
            ButtonSaveRelayProfile.Content = "Сохранить профиль";
            _validatedRelayProfile = null;
            DisposeValidatedProviderRuntimeProfile();
            if (!IsLoaded)
                return;

            RelayDetectedProfileTextBlock.Text = string.IsNullOrWhiteSpace(RelayClientKeyTextBox.Text)
                ? "Формат ещё не определён."
                : "Ключ изменён — требуется повторная проверка.";
            UpdateRelayClientUi();
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





