using System;
using System.Collections.Generic;
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
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Components;
using SerpiumVPN.Relay.Lifecycle;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Providers.Avo;
using SerpiumVPN.Relay.ProfileVault;
using SerpiumVPN.Relay.Routing;
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
        private readonly SecureXraySessionManager _serpiumXraySessionManager = new();
        private readonly SecureProfileVault _secureProfileVault = new();
        private readonly SecureRoutingRegistry _secureRoutingRegistry = new();
        private readonly SecureRoutingRuleSetRuntime _routingRuleSetRuntime = new();
        private readonly RelayComponentManager _relayComponentManager = new();
        private RelayComponentSettingsWindow? _relayComponentSettingsWindow;
        private IReadOnlyList<RoutingRegistryEntry> _routingRegistryEntries =
            Array.Empty<RoutingRegistryEntry>();
        private bool _routingRegistryOperationInProgress;
        private SerpiumConnectionProfile? _validatedRelayProfile;
        private ProviderRuntimeProfile? _validatedProviderRuntimeProfile;
        private bool _suppressRelayKeyTextChanged;
        private string? _pendingRelaySourceKey;
        private bool _pendingRelaySourceWasDecoded;
        private bool _currentProviderProfileSaved;
        private IReadOnlyList<SecureProfileVaultEntry> _savedProfileEntries =
            Array.Empty<SecureProfileVaultEntry>();
        private Guid? _activeSavedProfileId;
        private int? _activeSavedProfileSocksPort;
        private bool _activeSavedProfileUsesRoutingTun;
        private bool _activeRoutingHotReloadEnabled;
        private int _activeSavedProfileRoutingRuleCount;
        private IReadOnlyDictionary<Guid, string> _activeSavedProfileRoutingRuleLabels =
            new Dictionary<Guid, string>();
        private IReadOnlyDictionary<Guid, long> _activeSavedProfileRoutingRuleVersions =
            new Dictionary<Guid, long>();
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
                RelayGatewayLogTextBox.AppendText(SensitiveDiagnosticRedactor.RedactText(line) + Environment.NewLine);
                RelayGatewayLogTextBox.ScrollToEnd();
            });
            _serpiumXraySessionManager.StateChanged += _ =>
                SafeDispatcherInvoke(UpdateRelayClientUi);
            _serpiumXraySessionManager.LogReceived += line => SafeDispatcherInvoke(() =>
            {
                RelayClientLogTextBox.AppendText(SensitiveDiagnosticRedactor.RedactText(line) + Environment.NewLine);
                RelayClientLogTextBox.ScrollToEnd();
            });
            _serpiumSingBoxSessionManager.StateChanged += _ =>
                SafeDispatcherInvoke(UpdateRelayClientUi);
            _serpiumSingBoxSessionManager.LogReceived += line => SafeDispatcherInvoke(() =>
            {
                RelayClientLogTextBox.AppendText(SensitiveDiagnosticRedactor.RedactText(line) + Environment.NewLine);
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

        [DllImport("gdi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteObject(IntPtr objectHandle);

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
            await RefreshRoutingRegistryAsync();
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

            if (_settings.AutoCheckRelayComponents)
                _ = CheckRelayComponentsInBackgroundAsync();

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

                    string noticeBody =
                        details + skippedDetails;

                    SerpiumNoticeDialog.Show(
                        this,
                        "Обновления Zapret",
                        summary.SkippedFiles.Count > 0
                            ? "Компоненты обновлены частично"
                            : "Компоненты Zapret обновлены",
                        summary.SkippedFiles.Count > 0
                            ? "Основные файлы обновлены, но часть занятых Windows файлов была пропущена."
                            : "Локальные компоненты успешно скачаны, проверены и заменены.",
                        noticeBody,
                        summary.SkippedFiles.Count > 0
                            ? "После перезагрузки ПК повторите проверку до запуска обхода."
                            : "Компоненты Zapret готовы к работе.",
                        summary.SkippedFiles.Count > 0
                            ? SerpiumNoticeKind.Warning
                            : SerpiumNoticeKind.Success);

                    LoadHostsList();
                }
                else
                {
                    UpdateFilesStatus("Файлы актуальны", true);

                    if (showSuccessMessage)
                    {
                        SerpiumNoticeDialog.Show(
                            this,
                            "Обновления Zapret",
                            "Компоненты уже актуальны",
                            "Новых стабильных файлов для Zapret не обнаружено.",
                            "Все установленные компоненты соответствуют последним доступным версиям.",
                            "Дополнительных действий не требуется.",
                            SerpiumNoticeKind.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                UpdateFilesStatus("Ошибка обновления файлов", false);

                if (showSuccessMessage)
                {
                    SerpiumNoticeDialog.Show(
                        this,
                        "Обновления Zapret",
                        "Не удалось обновить компоненты",
                        "Проверка или установка файлов завершилась ошибкой.",
                        ex.Message,
                        "Рабочие файлы, которые не удалось заменить, остаются без изменений.",
                        SerpiumNoticeKind.Warning);
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

        private void OpenRelayComponentSettings_Click(object sender, RoutedEventArgs e)
        {
            if (_relayComponentSettingsWindow is not null)
            {
                if (_relayComponentSettingsWindow.WindowState == WindowState.Minimized)
                    _relayComponentSettingsWindow.WindowState = WindowState.Normal;

                _relayComponentSettingsWindow.Activate();
                return;
            }

            RelayComponentSettingsWindow window = new(
                _relayComponentManager,
                _settings,
                summary => SafeDispatcherInvoke(() =>
                    RelayComponentSettingsButton.ToolTip = summary),
                StopAllRelayTransportsBestEffortAsync)
            {
                Owner = this
            };

            _relayComponentSettingsWindow = window;
            window.Closed += (_, _) => _relayComponentSettingsWindow = null;
            window.Show();
        }

        private async Task CheckRelayComponentsInBackgroundAsync()
        {
            try
            {
                if (_settings.LastRelayComponentCheckUtc is DateTimeOffset lastCheck &&
                    DateTimeOffset.UtcNow - lastCheck < TimeSpan.FromHours(12))
                {
                    return;
                }

                IReadOnlyDictionary<RelayComponentKind, RelayComponentReleaseInfo> releases =
                    await _relayComponentManager.CheckLatestStableReleasesAsync();
                IReadOnlyDictionary<RelayComponentKind, RelayComponentSnapshot> snapshots =
                    await _relayComponentManager.InspectAllAsync();

                _settings.LastRelayComponentCheckUtc = DateTimeOffset.UtcNow;
                _settings.LastKnownSingBoxRelease =
                    releases[RelayComponentKind.SingBox].TagName;
                _settings.LastKnownXrayRelease =
                    releases[RelayComponentKind.XrayCore].TagName;
                _settings.Save();

                int updateCount = snapshots.Values.Count(snapshot =>
                    releases.TryGetValue(snapshot.Kind, out RelayComponentReleaseInfo? release) &&
                    RelayComponentManager.IsUpdateAvailable(
                        snapshot.InstalledVersion,
                        release.NormalizedVersion));

                string tooltip = updateCount > 0
                    ? $"Компоненты Relay: официальных релизов новее — {updateCount}."
                    : "Компоненты Relay: новых стабильных релизов не обнаружено.";

                SafeDispatcherInvoke(() =>
                    RelayComponentSettingsButton.ToolTip = tooltip);
            }
            catch
            {
                SafeDispatcherInvoke(() =>
                    RelayComponentSettingsButton.ToolTip =
                        "Компоненты Relay: автоматическая проверка временно недоступна.");
            }
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            MainNavigationTabs.SelectedIndex = 4;
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
            ClearPendingRelaySourceKey();
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

                string sourceKey = RelayClientKeyTextBox.Text.Trim();
                EncodedKeyEnvelopeDecodeResult encodedInput =
                    EncodedKeyEnvelopeDecoder.Decode(sourceKey);
                SerpiumParseResult parseResult =
                    _serpiumParser.Parse(encodedInput.NormalizedKey);
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
                    ClearRelayKeyInputAfterSuccessfulConnection(
                        sourceKey,
                        encodedInput);
                    SetRelayStatus(
                        $"Статус: подключено через AVO — {protocols}; TUN {activeInterface}; " +
                        "ключ очищен из поля ввода.",
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
                RelayDetectedProfileTextBlock.Text =
                    encodedInput.SafeSummaryPrefix + BuildRelayProfileSummary(profile);
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
                string encodedInputStatus = encodedInput.WasDecoded
                    ? "; Base64-контейнер раскрыт локально"
                    : string.Empty;
                ClearRelayKeyInputAfterSuccessfulConnection(
                    sourceKey,
                    encodedInput);
                SetRelayStatus(
                    $"Статус: подключено через Xray — {profile.Protocol.ToUpperInvariant()}, " +
                    $"SOCKS5 127.0.0.1:{socksPort}{encodedInputStatus}; " +
                    "ключ очищен из поля ввода.",
                    WpfBrushes.LightGreen);
                UpdateRelayClientUi();
            }
            catch (Exception ex)
            {
                RelayClientSocksStateTextBlock.Text = "SOCKS5: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                SetRelayStatus("Статус: ошибка подключения — " + SensitiveDiagnosticRedactor.RedactText(ex.Message), WpfBrushes.OrangeRed);
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
                ClearPendingRelaySourceKey();
                DisposeValidatedProviderRuntimeProfile();
                _activeSavedProfileId = null;
                _activeSavedProfileSocksPort = null;
                ClearActiveRoutingSnapshot();
                ClearSavedProfileFailure();
                _currentProviderProfileSaved = false;
                ButtonSaveRelayProfile.Content = "Сохранить профиль";
                RelayClientSocksStateTextBlock.Text = "Транспорт: остановлен";
                RelayClientSocksStateTextBlock.Foreground = WpfBrushes.Gray;
                RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);
                UpdateRelayClientUi();
                UpdateRoutingSummaryStatus();
                RenderRoutingRegistryCards();
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

            if (!isBusy && !isRunning)
                ClearPendingRelaySourceKey();

            bool xrayRoutingBridgeMode =
                _activeSavedProfileUsesRoutingTun &&
                _validatedRelayProfile is not null;
            bool providerMode =
                !xrayRoutingBridgeMode &&
                (_validatedProviderRuntimeProfile is not null ||
                 singBoxState != RelayGatewayState.Stopped ||
                 singBoxRunning);

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

            RelayGatewayState visibleState = xrayRoutingBridgeMode
                ? (xrayState == RelayGatewayState.Failed ||
                   singBoxState == RelayGatewayState.Failed
                    ? RelayGatewayState.Failed
                    : xrayState == RelayGatewayState.Stopping ||
                      singBoxState == RelayGatewayState.Stopping
                        ? RelayGatewayState.Stopping
                        : xrayState == RelayGatewayState.Running &&
                          singBoxState == RelayGatewayState.Running
                            ? RelayGatewayState.Running
                            : RelayGatewayState.Starting)
                : providerMode
                    ? singBoxState
                    : xrayState;
            RelayClientStateTextBlock.Text = xrayRoutingBridgeMode
                ? visibleState switch
                {
                    RelayGatewayState.Starting => "Xray + TUN: запускаются…",
                    RelayGatewayState.Running => "Xray + TUN: работают",
                    RelayGatewayState.Stopping => "Xray + TUN: останавливаются…",
                    RelayGatewayState.Failed => "Xray + TUN: ошибка",
                    _ => "Xray + TUN: остановлены"
                }
                : providerMode
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
                string normalizedSourceKey;
                bool sourceWasDecoded;

                if (!string.IsNullOrWhiteSpace(sourceKey))
                {
                    EncodedKeyEnvelopeDecodeResult sourceEnvelope =
                        EncodedKeyEnvelopeDecoder.Decode(sourceKey);
                    normalizedSourceKey = sourceEnvelope.NormalizedKey;
                    sourceWasDecoded = sourceEnvelope.WasDecoded;
                }
                else if (!string.IsNullOrWhiteSpace(_pendingRelaySourceKey))
                {
                    normalizedSourceKey = _pendingRelaySourceKey;
                    sourceWasDecoded = _pendingRelaySourceWasDecoded;
                }
                else
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
                    if (!normalizedSourceKey.StartsWith("avo://", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            "Текущий AVO-профиль не соответствует ключу в поле ввода.");
                    }

                    result = await _secureProfileVault.SaveProviderProfileAsync(
                        providerProfile,
                        normalizedSourceKey);
                    profileSummary = BuildProviderRuntimeProfileSummary(providerProfile);
                    sourceDescription = sourceWasDecoded
                        ? "Исходный Base64-контейнер и раскрытый avo:// ключ не сохранены"
                        : "Исходный avo:// ключ не сохранён";
                }
                else
                {
                    SerpiumConnectionProfile xrayProfile = _validatedRelayProfile!;
                    SerpiumParseResult verification = _serpiumParser.Parse(normalizedSourceKey);
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
                        normalizedSourceKey);
                    _activeSavedProfileSocksPort = socksPort;
                    profileSummary = BuildRelayProfileSummary(xrayProfile);
                    sourceDescription = sourceWasDecoded
                        ? $"Исходный Base64-контейнер и раскрытый {xrayProfile.Protocol.ToLowerInvariant()}:// ключ не сохранены"
                        : $"Исходный {xrayProfile.Protocol.ToLowerInvariant()}:// ключ не сохранён";
                }

                _currentProviderProfileSaved = true;
                _activeSavedProfileId = result.Entry.Id;
                ClearRelayKeyInputAndMatchingClipboard(sourceKey);
                ClearPendingRelaySourceKey();

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
                    VerticalAlignment = System.Windows.VerticalAlignment.Center,
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
                    VerticalAlignment = System.Windows.VerticalAlignment.Center,
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

                _routingRegistryEntries = await _secureRoutingRegistry.ListAsync();
                RoutingRegistryEntry[] enabledRoutingEntries = _routingRegistryEntries
                    .Where(item => item.IsEnabled)
                    .ToArray();
                int enabledRoutingRuleCount = enabledRoutingEntries.Length;
                bool enableLiveRouting = enabledRoutingRuleCount > 0;
                if (enableLiveRouting)
                {
                    await _routingRuleSetRuntime.UpdateAsync(_routingRegistryEntries);
                }
                else
                {
                    _routingRuleSetRuntime.DeleteBestEffort();
                }
                RenderRoutingRegistryCards();

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

                    ClearActiveRoutingSnapshot();
                    if (enableLiveRouting)
                    {
                        RelayClientSocksStateTextBlock.Text =
                            "Xray готов; запускаем выборочный TUN…";

                        _validatedProviderRuntimeProfile =
                            SerpiumRoutingConfigCompiler.BuildXrayBridgeProfile(
                                profileId,
                                savedXray.SocksPort,
                                _routingRegistryEntries,
                                _routingRuleSetRuntime.RuleSetPath);

                        string singBoxPath = IOPath.Combine(relayDir, "sing-box.exe");
                        SingBoxCheckResult routingCheck =
                            await _singBoxValidationService.ValidateAsync(
                                singBoxPath,
                                _validatedProviderRuntimeProfile);
                        if (!routingCheck.Success)
                        {
                            throw new InvalidOperationException(
                                "sing-box отклонил выборочную маршрутизацию: " +
                                routingCheck.Message);
                        }

                        await _serpiumSingBoxSessionManager.StartAsync(
                            singBoxPath,
                            _validatedProviderRuntimeProfile);

                        _activeSavedProfileUsesRoutingTun = true;
                        _activeRoutingHotReloadEnabled = true;
                        CaptureActiveRoutingSnapshot(enabledRoutingEntries);
                    }
                    else
                    {
                        ClearActiveRoutingSnapshot();
                    }

                    _activeSavedProfileId = profileId;
                    ClearSavedProfileFailure();
                    _currentProviderProfileSaved = true;
                    RelayDetectedProfileTextBlock.Text =
                        BuildRelayProfileSummary(savedXray.Profile) +
                        Environment.NewLine + Environment.NewLine +
                        "Профиль загружен из Serpium Secure Profile Vault." +
                        (enableLiveRouting
                            ? Environment.NewLine +
                              $"Выборочная маршрутизация активна: правил {enabledRoutingRuleCount}; " +
                              "остальной трафик идёт напрямую."
                            : Environment.NewLine +
                              "SOCKS5 запущен без TUN: включите правила маршрутизации " +
                              "и переподключите профиль.");
                    RelayClientSocksStateTextBlock.Text = enableLiveRouting
                        ? $"TUN → SOCKS5 активны (127.0.0.1:{savedXray.SocksPort})"
                        : $"SOCKS5: активен (127.0.0.1:{savedXray.SocksPort})";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.LightGreen;
                    SetRelayStatus(
                        enableLiveRouting
                            ? $"Статус: Xray подключён; выборочный TUN применил " +
                              $"{enabledRoutingRuleCount} правил; live reload включён, " +
                              "остальной трафик direct."
                            : $"Статус: сохранённый профиль подключён через Xray — " +
                              $"{savedXray.Profile.Protocol.ToUpperInvariant()}, " +
                              $"SOCKS5 127.0.0.1:{savedXray.SocksPort}.",
                        WpfBrushes.LightGreen);
                }
                else
                {
                    _validatedRelayProfile = null;
                    _activeSavedProfileSocksPort = null;
                    DisposeValidatedProviderRuntimeProfile();
                    ProviderRuntimeProfile openedProviderProfile =
                        await _secureProfileVault.OpenProviderProfileAsync(profileId);
                    try
                    {
                        _validatedProviderRuntimeProfile = enableLiveRouting
                            ? SerpiumRoutingConfigCompiler.CompileProviderProfile(
                                openedProviderProfile,
                                _routingRegistryEntries,
                                _routingRuleSetRuntime.RuleSetPath)
                            : openedProviderProfile;

                        if (!ReferenceEquals(
                                _validatedProviderRuntimeProfile,
                                openedProviderProfile))
                        {
                            openedProviderProfile.Dispose();
                        }
                    }
                    catch
                    {
                        openedProviderProfile.Dispose();
                        throw;
                    }

                    string singBoxRelayDir = IOPath.Combine(
                        IOPath.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                        "bin_files",
                        "relay");
                    string singBoxPath =
                        IOPath.Combine(singBoxRelayDir, "sing-box.exe");

                    if (enableLiveRouting)
                    {
                        SingBoxCheckResult routingCheck =
                            await _singBoxValidationService.ValidateAsync(
                                singBoxPath,
                                _validatedProviderRuntimeProfile);
                        if (!routingCheck.Success)
                        {
                            throw new InvalidOperationException(
                                "sing-box отклонил выборочную маршрутизацию: " +
                                routingCheck.Message);
                        }
                    }

                    RelayClientSocksStateTextBlock.Text = "TUN: запускается…";
                    RelayClientSocksStateTextBlock.Foreground = WpfBrushes.DeepSkyBlue;
                    await _serpiumSingBoxSessionManager.StartAsync(
                        singBoxPath,
                        _validatedProviderRuntimeProfile);

                    if (enableLiveRouting)
                    {
                        _activeSavedProfileUsesRoutingTun = true;
                        _activeRoutingHotReloadEnabled = true;
                        CaptureActiveRoutingSnapshot(enabledRoutingEntries);
                    }
                    else
                    {
                        ClearActiveRoutingSnapshot();
                    }

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
                        enableLiveRouting
                            ? $"Статус: сохранённый профиль подключён — {protocols}; " +
                              $"выборочный TUN {activeInterface}, правил {enabledRoutingRuleCount}; " +
                              "live reload включён, остальной трафик direct."
                            : $"Статус: сохранённый профиль подключён — {protocols}; " +
                              $"полный TUN {activeInterface}.",
                        WpfBrushes.LightGreen);
                }
            }
            catch (Exception ex)
            {
                await StopAllRelayTransportsBestEffortAsync();
                _failedSavedProfileId = profileId;
                _failedSavedProfileMessage = NormalizeLifecycleError(ex.Message);
                _activeSavedProfileId = null;
                _activeSavedProfileSocksPort = null;
                ClearActiveRoutingSnapshot();
                _currentProviderProfileSaved = false;
                _validatedRelayProfile = null;
                DisposeValidatedProviderRuntimeProfile();
                _routingRuleSetRuntime.DeleteBestEffort();
                RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);
                SetRelayStatus(
                    "Статус: сохранённый профиль не подключён — " + ex.Message,
                    WpfBrushes.OrangeRed);
            }
            finally
            {
                _savedProfileOperationInProgress = false;
                UpdateRelayClientUi();
                UpdateRoutingSummaryStatus();
                RenderRoutingRegistryCards();
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
                UpdateRoutingSummaryStatus();
                RenderRoutingRegistryCards();
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
                ClearActiveRoutingSnapshot();
                ClearSavedProfileFailure();
                _currentProviderProfileSaved = false;
                _validatedRelayProfile = null;
                DisposeValidatedProviderRuntimeProfile();
                _routingRuleSetRuntime.DeleteBestEffort();
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

        private async Task RefreshRoutingRegistryAsync()
        {
            try
            {
                _routingRegistryEntries = await _secureRoutingRegistry.ListAsync();
                RenderRoutingRegistryCards();

                UpdateRoutingSummaryStatus();
            }
            catch (Exception ex)
            {
                _routingRegistryEntries = Array.Empty<RoutingRegistryEntry>();
                RenderRoutingRegistryCards();
                SetRoutingStatus(
                    "Реестр маршрутизации недоступен: " + ex.Message,
                    WpfBrushes.OrangeRed);
            }
        }

        private void CaptureActiveRoutingSnapshot(
            IEnumerable<RoutingRegistryEntry> entries)
        {
            Dictionary<Guid, string> snapshot = entries
                .Where(entry => entry.IsEnabled)
                .GroupBy(entry => entry.Id)
                .ToDictionary(
                    group => group.Key,
                    group => BuildRoutingEntryLabel(group.First()));

            _activeSavedProfileRoutingRuleLabels = snapshot;
            _activeSavedProfileRoutingRuleVersions = entries
                .Where(entry => entry.IsEnabled)
                .GroupBy(entry => entry.Id)
                .ToDictionary(
                    group => group.Key,
                    group => group.First().UpdatedUtc.UtcDateTime.Ticks);
            _activeSavedProfileRoutingRuleCount = snapshot.Count;
        }

        private void ClearActiveRoutingSnapshot()
        {
            _activeSavedProfileRoutingRuleLabels =
                new Dictionary<Guid, string>();
            _activeSavedProfileRoutingRuleVersions =
                new Dictionary<Guid, long>();
            _activeSavedProfileUsesRoutingTun = false;
            _activeRoutingHotReloadEnabled = false;
            _activeSavedProfileRoutingRuleCount = 0;
        }

        private static string BuildRoutingEntryLabel(
            RoutingRegistryEntry entry)
        {
            string name = string.IsNullOrWhiteSpace(entry.DisplayName)
                ? entry.Kind == RoutingTargetKind.Application
                    ? IOPath.GetFileNameWithoutExtension(entry.PrimaryValue)
                    : entry.PrimaryValue
                : entry.DisplayName.Trim();

            return entry.Kind == RoutingTargetKind.Application
                ? $"приложение «{name}»"
                : $"сайт «{name}»";
        }

        private static string FormatRoutingRuleCount(int count)
        {
            int absolute = Math.Abs(count);
            int lastTwoDigits = absolute % 100;
            int lastDigit = absolute % 10;

            string suffix = lastTwoDigits is >= 11 and <= 14
                ? "правил"
                : lastDigit == 1
                    ? "правило"
                    : lastDigit is >= 2 and <= 4
                        ? "правила"
                        : "правил";

            return $"{count} {suffix}";
        }

        private static string FormatRoutingRuleList(
            IEnumerable<string> labels,
            int maximumVisible = 5)
        {
            string[] ordered = labels
                .Where(label => !string.IsNullOrWhiteSpace(label))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(label => label, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();

            if (ordered.Length == 0)
                return "нет";

            string visible = string.Join(", ", ordered.Take(maximumVisible));
            int hiddenCount = ordered.Length - maximumVisible;
            return hiddenCount > 0
                ? visible + $" и ещё {hiddenCount}"
                : visible;
        }

        private async Task<bool> TryApplyLiveRoutingRulesAsync(
            string operationDescription)
        {
            if (!_activeSavedProfileId.HasValue)
            {
                UpdateRoutingSummaryStatus();
                return false;
            }

            if (!_activeRoutingHotReloadEnabled ||
                !_activeSavedProfileUsesRoutingTun ||
                !_serpiumSingBoxSessionManager.IsRunning)
            {
                UpdateRoutingSummaryStatus();
                return false;
            }

            try
            {
                RoutingRegistryEntry[] enabledEntries =
                    _routingRegistryEntries
                        .Where(entry => entry.IsEnabled)
                        .ToArray();

                if (enabledEntries.Length == 0)
                {
                    RelayClientLogTextBox.AppendText(
                        "Dynamic rule-set не очищен: пустой набор переключил бы " +
                        "весь новый трафик на direct. Переподключите профиль для " +
                        "полного VPN-туннеля." +
                        Environment.NewLine);
                    RelayClientLogTextBox.ScrollToEnd();

                    SetRoutingStatus(
                        "Все правила выключены. Последний применённый набор " +
                        "сохранён до переподключения, чтобы не допустить утечку " +
                        "трафика через direct. Переподключите профиль — он " +
                        "запустится в полном VPN-режиме.",
                        WpfBrushes.Goldenrod);
                    RenderRoutingRegistryCards();
                    return false;
                }

                RoutingRuleSetUpdateResult update =
                    await _routingRuleSetRuntime.UpdateAsync(
                        enabledEntries);

                // Local rule-sets are watched by sing-box. A short debounce keeps
                // the UI from claiming success before the filesystem event is read.
                await Task.Delay(350);
                CaptureActiveRoutingSnapshot(_routingRegistryEntries);

                RelayClientLogTextBox.AppendText(
                    $"Dynamic rule-set обновлён: правил {update.EnabledRuleCount}." +
                    Environment.NewLine);
                RelayClientLogTextBox.ScrollToEnd();

                UpdateRoutingSummaryStatus();
                RenderRoutingRegistryCards();
                return true;
            }
            catch (Exception ex)
            {
                SetRoutingStatus(
                    $"{operationDescription} сохранено в реестре, но live reload " +
                    "не подтверждён: " + NormalizeLifecycleError(ex.Message) +
                    ". Переподключите профиль.",
                    WpfBrushes.OrangeRed);
                RenderRoutingRegistryCards();
                return false;
            }
        }

        private void UpdateRoutingSummaryStatus()
        {
            if (RoutingStatusTextBlock is null || RoutingStatusIndicator is null)
                return;

            RoutingRegistryEntry[] enabled = _routingRegistryEntries
                .Where(entry => entry.IsEnabled)
                .OrderBy(entry => entry.Kind)
                .ThenBy(entry => entry.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();

            Dictionary<Guid, string> selected = enabled.ToDictionary(
                entry => entry.Id,
                BuildRoutingEntryLabel);

            string selectedCount = FormatRoutingRuleCount(selected.Count);
            string selectedList = FormatRoutingRuleList(selected.Values);
            bool savedProfileActive = _activeSavedProfileId.HasValue;

            if (savedProfileActive && _activeSavedProfileUsesRoutingTun)
            {
                if (_activeRoutingHotReloadEnabled &&
                    selected.Count == 0 &&
                    _activeSavedProfileRoutingRuleLabels.Count > 0)
                {
                    string safelyAppliedCount = FormatRoutingRuleCount(
                        _activeSavedProfileRoutingRuleLabels.Count);

                    SetRoutingStatus(
                        $"Все правила выключены, но в текущем TUN безопасно " +
                        $"сохранено {safelyAppliedCount}. Пустой live rule-set не " +
                        "применён, потому что он отправил бы весь трафик direct. " +
                        "Переподключите профиль для полного VPN-туннеля.",
                        WpfBrushes.Goldenrod);
                    return;
                }

                bool snapshotMatches =
                    selected.Count == _activeSavedProfileRoutingRuleLabels.Count &&
                    enabled.All(entry =>
                        _activeSavedProfileRoutingRuleLabels.ContainsKey(entry.Id) &&
                        _activeSavedProfileRoutingRuleVersions.TryGetValue(
                            entry.Id,
                            out long appliedTicks) &&
                        appliedTicks == entry.UpdatedUtc.UtcDateTime.Ticks);

                if (snapshotMatches)
                {
                    if (_activeRoutingHotReloadEnabled && selected.Count == 0)
                    {
                        SetRoutingStatus(
                            "Live routing активен, но все правила выключены: " +
                            "новые соединения идут напрямую. Любую карточку можно " +
                            "включить без переподключения профиля.",
                            WpfBrushes.Gray);
                        return;
                    }

                    SetRoutingStatus(
                        _activeRoutingHotReloadEnabled
                            ? $"Динамически активно {selectedCount}: {selectedList}. " +
                              "Новые соединения применяют изменения без переподключения; " +
                              "остальной трафик направляется напрямую."
                            : $"Активно {selectedCount}: {selectedList}. " +
                              "Остальной трафик направляется напрямую.",
                        WpfBrushes.LightGreen);
                    return;
                }

                string appliedCount = FormatRoutingRuleCount(
                    _activeSavedProfileRoutingRuleLabels.Count);
                string appliedList = FormatRoutingRuleList(
                    _activeSavedProfileRoutingRuleLabels.Values);

                SetRoutingStatus(
                    $"Настройки изменены: сейчас выбрано {selectedCount}: " +
                    $"{selectedList}. В текущем TUN пока применено " +
                    $"{appliedCount}: {appliedList}. " +
                    (_activeRoutingHotReloadEnabled
                        ? "Live reload не подтверждён; переподключите профиль."
                        : "Переподключите профиль."),
                    WpfBrushes.Goldenrod);
                return;
            }

            if (savedProfileActive)
            {
                if (selected.Count > 0)
                {
                    SetRoutingStatus(
                        $"Выбрано {selectedCount}: {selectedList}. " +
                        "Активный профиль запущен без выборочного TUN; " +
                        "переподключите профиль, чтобы применить правила.",
                        WpfBrushes.Goldenrod);
                }
                else
                {
                    SetRoutingStatus(
                        "Все правила выключены. Активный профиль работает " +
                        "в исходном режиме без выборочной маршрутизации.",
                        WpfBrushes.Gray);
                }

                return;
            }

            if (_routingRegistryEntries.Count == 0)
            {
                SetRoutingStatus(
                    "Реестр маршрутизации пуст. Добавьте приложение, игру или сайт.",
                    WpfBrushes.Gray);
                return;
            }

            if (selected.Count == 0)
            {
                SetRoutingStatus(
                    $"Все {_routingRegistryEntries.Count} правил выключены. " +
                    "Выборочная маршрутизация не будет применена.",
                    WpfBrushes.Gray);
                return;
            }

            SetRoutingStatus(
                $"Включено {selectedCount}: {selectedList}. " +
                "Правила будут применены при подключении профиля.",
                WpfBrushes.LightGreen);
        }

        private (string Text, WpfBrush Foreground) GetRoutingCardRuntimeStatus(
            RoutingRegistryEntry entry,
            bool fileMissing)
        {
            if (fileMissing)
                return ("Файл не найден", WpfBrushes.OrangeRed);

            bool isApplied =
                _activeSavedProfileUsesRoutingTun &&
                _activeSavedProfileRoutingRuleLabels.ContainsKey(entry.Id);

            if (_activeSavedProfileId.HasValue)
            {
                if (isApplied && entry.IsEnabled)
                    return (
                        _activeRoutingHotReloadEnabled
                            ? "Активно; live reload включён"
                            : "Активно в текущем VPN-туннеле",
                        WpfBrushes.LightGreen);

                if (isApplied)
                {
                    return (
                        "Выключено, но ещё действует до переподключения",
                        WpfBrushes.Goldenrod);
                }

                if (entry.IsEnabled)
                {
                    return (
                        "Включено; ожидает переподключения профиля",
                        WpfBrushes.Goldenrod);
                }

                return ("Исключено из VPN-маршрутизации", WpfBrushes.Gray);
            }

            return entry.IsEnabled
                ? ("Будет направлено через VPN при подключении", WpfBrushes.LightGreen)
                : ("Исключено из VPN-маршрутизации", WpfBrushes.Gray);
        }

        private void RenderRoutingRegistryCards()
        {
            if (RoutingApplicationsPanel is null || RoutingSitesPanel is null)
                return;

            RoutingApplicationsPanel.Children.Clear();
            RoutingSitesPanel.Children.Clear();

            RoutingRegistryEntry[] applications = _routingRegistryEntries
                .Where(entry => entry.Kind == RoutingTargetKind.Application)
                .ToArray();
            RoutingRegistryEntry[] websites = _routingRegistryEntries
                .Where(entry => entry.Kind == RoutingTargetKind.Website)
                .ToArray();

            RoutingApplicationsCountTextBlock.Text = applications.Length.ToString(CultureInfo.InvariantCulture);
            RoutingSitesCountTextBlock.Text = websites.Length.ToString(CultureInfo.InvariantCulture);
            RoutingEnabledCountTextBlock.Text = _routingRegistryEntries
                .Count(entry => entry.IsEnabled)
                .ToString(CultureInfo.InvariantCulture);

            RoutingApplicationsEmptyTextBlock.Visibility = applications.Length == 0
                ? Visibility.Visible
                : Visibility.Collapsed;
            RoutingSitesEmptyTextBlock.Visibility = websites.Length == 0
                ? Visibility.Visible
                : Visibility.Collapsed;
            ClearRoutingRegistryButton.IsEnabled =
                !_routingRegistryOperationInProgress && _routingRegistryEntries.Count > 0;

            foreach (RoutingRegistryEntry entry in applications)
                RoutingApplicationsPanel.Children.Add(CreateRoutingCard(entry));

            foreach (RoutingRegistryEntry entry in websites)
                RoutingSitesPanel.Children.Add(CreateRoutingCard(entry));
        }

        private System.Windows.Controls.Border CreateRoutingCard(RoutingRegistryEntry entry)
        {
            bool fileMissing = entry.Kind == RoutingTargetKind.Application &&
                               !File.Exists(entry.PrimaryValue);

            System.Windows.Controls.Border card = new()
            {
                Background = new SolidColorBrush(Color.FromRgb(0x11, 0x11, 0x18)),
                BorderBrush = entry.IsEnabled && !fileMissing
                    ? new SolidColorBrush(Color.FromRgb(0x2F, 0x72, 0x50))
                    : fileMissing
                        ? new SolidColorBrush(Color.FromRgb(0x9A, 0x5D, 0x35))
                        : new SolidColorBrush(Color.FromRgb(0x2D, 0x2D, 0x3A)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(9),
                Padding = new Thickness(14, 12, 12, 12),
                Margin = new Thickness(0, 0, 0, 10),
                Opacity = _routingRegistryOperationInProgress ? 0.58 : 1.0
            };

            System.Windows.Controls.Grid layout = new();
            layout.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition
            {
                Width = new GridLength(52)
            });
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
            layout.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition
            {
                Width = GridLength.Auto
            });

            System.Windows.FrameworkElement iconElement = CreateRoutingIcon(entry);
            iconElement.VerticalAlignment = System.Windows.VerticalAlignment.Top;
            layout.Children.Add(iconElement);

            System.Windows.Controls.StackPanel description = new()
            {
                Margin = new Thickness(0, 0, 12, 0)
            };
            description.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = entry.DisplayName,
                Foreground = WpfBrushes.White,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis,
                ToolTip = entry.DisplayName
            });

            int existingExecutableCount = entry.Kind == RoutingTargetKind.Application
                ? entry.RelatedExecutables.Count(File.Exists)
                : 0;
            string details = entry.Kind == RoutingTargetKind.Application
                ? $"{IOPath.GetFileName(entry.PrimaryValue)} · EXE в группе: {Math.Max(1, entry.RelatedExecutables.Length)} · доступно: {existingExecutableCount}"
                : entry.IncludeSubdomains
                    ? "Домен и все поддомены"
                    : "Только указанный домен";
            description.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = details,
                Foreground = new SolidColorBrush(Color.FromRgb(0x9B, 0x9B, 0xA8)),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap
            });

            string location = entry.Kind == RoutingTargetKind.Application
                ? entry.PrimaryValue
                : entry.PrimaryValue;
            description.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = location,
                Foreground = new SolidColorBrush(Color.FromRgb(0x6F, 0x6F, 0x7D)),
                FontSize = 11,
                Margin = new Thickness(0, 4, 0, 0),
                TextTrimming = TextTrimming.CharacterEllipsis,
                ToolTip = entry.Kind == RoutingTargetKind.Application
                    ? string.Join(Environment.NewLine, entry.RelatedExecutables)
                    : entry.PrimaryValue
            });

            (string runtimeStatusText, WpfBrush runtimeStatusForeground) =
                GetRoutingCardRuntimeStatus(entry, fileMissing);
            description.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = runtimeStatusText,
                Foreground = runtimeStatusForeground,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 5, 0, 0)
            });
            System.Windows.Controls.Grid.SetColumn(description, 1);
            layout.Children.Add(description);

            if (entry.Kind == RoutingTargetKind.Application)
            {
                System.Windows.Controls.Button bundleButton = new()
                {
                    Style = (Style)RoutingApplicationsPanel.FindResource("RoutingBundleButtonStyle"),
                    Content = "Состав",
                    Tag = entry.Id,
                    IsEnabled = !_routingRegistryOperationInProgress,
                    Margin = new Thickness(10, 0, 8, 0),
                    VerticalAlignment = System.Windows.VerticalAlignment.Center,
                    ToolTip = "Проверить EXE группы и запустить наблюдение за процессами"
                };
                bundleButton.Click += EditRoutingApplicationBundle_ClickAsync;
                System.Windows.Controls.Grid.SetColumn(bundleButton, 2);
                layout.Children.Add(bundleButton);
            }

            System.Windows.Controls.Primitives.ToggleButton toggle = new()
            {
                Style = (Style)RoutingApplicationsPanel.FindResource("RoutingToggleStyle"),
                IsChecked = entry.IsEnabled,
                IsEnabled = !_routingRegistryOperationInProgress,
                Tag = entry.Id,
                Margin = new Thickness(entry.Kind == RoutingTargetKind.Application ? 0 : 16, 0, 10, 0),
                VerticalAlignment = System.Windows.VerticalAlignment.Center,
                ToolTip = entry.IsEnabled
                    ? "Не направлять через VPN-шлюз"
                    : "Направлять через VPN-шлюз"
            };
            toggle.Checked += RoutingToggle_ChangedAsync;
            toggle.Unchecked += RoutingToggle_ChangedAsync;
            System.Windows.Controls.Grid.SetColumn(toggle, 3);
            layout.Children.Add(toggle);

            System.Windows.Controls.Button deleteButton = new()
            {
                Style = (Style)RoutingApplicationsPanel.FindResource("RoutingDeleteButtonStyle"),
                Content = "🗑",
                Tag = entry.Id,
                IsEnabled = !_routingRegistryOperationInProgress,
                VerticalAlignment = System.Windows.VerticalAlignment.Center,
                ToolTip = "Удалить из списка маршрутизации"
            };
            deleteButton.Click += DeleteRoutingEntry_ClickAsync;
            System.Windows.Controls.Grid.SetColumn(deleteButton, 4);
            layout.Children.Add(deleteButton);

            card.Child = layout;
            return card;
        }

        private static System.Windows.FrameworkElement CreateRoutingIcon(RoutingRegistryEntry entry)
        {
            if (entry.Kind == RoutingTargetKind.Application)
            {
                System.Windows.Media.ImageSource? imageSource = TryLoadExecutableIcon(entry.PrimaryValue);
                if (imageSource is not null)
                {
                    return new System.Windows.Controls.Image
                    {
                        Source = imageSource,
                        Width = 38,
                        Height = 38,
                        Stretch = Stretch.Uniform,
                        HorizontalAlignment = System.Windows.HorizontalAlignment.Left
                    };
                }
            }

            System.Windows.Controls.Border fallback = new()
            {
                Width = 40,
                Height = 40,
                CornerRadius = new CornerRadius(10),
                Background = entry.Kind == RoutingTargetKind.Website
                    ? new SolidColorBrush(Color.FromRgb(0x23, 0x23, 0x37))
                    : new SolidColorBrush(Color.FromRgb(0x26, 0x3D, 0x35)),
                HorizontalAlignment = System.Windows.HorizontalAlignment.Left
            };
            fallback.Child = new System.Windows.Controls.TextBlock
            {
                Text = entry.Kind == RoutingTargetKind.Website ? "🌐" : "▣",
                FontSize = 20,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = System.Windows.VerticalAlignment.Center
            };
            return fallback;
        }

        private static System.Windows.Media.ImageSource? TryLoadExecutableIcon(string executablePath)
        {
            if (!File.Exists(executablePath))
                return null;

            try
            {
                using Drawing.Icon? icon = Drawing.Icon.ExtractAssociatedIcon(executablePath);
                if (icon is null)
                    return null;

                using Drawing.Bitmap bitmap = icon.ToBitmap();
                IntPtr bitmapHandle = bitmap.GetHbitmap();
                try
                {
                    System.Windows.Media.Imaging.BitmapSource source =
                        System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                            bitmapHandle,
                            IntPtr.Zero,
                            Int32Rect.Empty,
                            System.Windows.Media.Imaging.BitmapSizeOptions.FromEmptyOptions());
                    source.Freeze();
                    return source;
                }
                finally
                {
                    DeleteObject(bitmapHandle);
                }
            }
            catch
            {
                return null;
            }
        }

        private async void AddRoutingApplication_ClickAsync(object sender, RoutedEventArgs e)
        {
            if (_routingRegistryOperationInProgress)
                return;

            OpenFileDialog fileDialog = new()
            {
                Title = "Выберите приложение, игру или лаунчер",
                Filter = "Приложения Windows (*.exe)|*.exe",
                CheckFileExists = true,
                Multiselect = false,
                DereferenceLinks = true
            };

            if (fileDialog.ShowDialog(this) != true)
                return;

            RoutingApplicationBundleDialog bundleDialog;
            try
            {
                bundleDialog = new RoutingApplicationBundleDialog(fileDialog.FileName)
                {
                    Owner = this
                };

                if (bundleDialog.ShowDialog() != true)
                {
                    SetRoutingStatus("Добавление приложения отменено.", WpfBrushes.Gray);
                    return;
                }
            }
            catch (Exception ex)
            {
                string diagnosticMessage =
                    "Редактор группы приложения не открылся: " + ex.Message;

                try
                {
                    string diagnosticsDirectory = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                        "SerpiumVPN_Diagnostics");
                    Directory.CreateDirectory(diagnosticsDirectory);

                    string diagnosticPath = Path.Combine(
                        diagnosticsDirectory,
                        "BundleDialog_" +
                        DateTime.Now.ToString("yyyyMMdd_HHmmss") +
                        ".txt");

                    File.WriteAllText(
                        diagnosticPath,
                        "SerpiumVPN v1.0.50 Bundle Dialog" +
                        Environment.NewLine +
                        "Selected EXE: " + fileDialog.FileName +
                        Environment.NewLine +
                        Environment.NewLine +
                        ex);

                    diagnosticMessage +=
                        " Диагностика сохранена: " + diagnosticPath;
                }
                catch
                {
                    // Failure to write a local diagnostic must not terminate Serpium.
                }

                SetRoutingStatus(diagnosticMessage, WpfBrushes.OrangeRed);
                return;
            }

            _routingRegistryOperationInProgress = true;
            RenderRoutingRegistryCards();
            try
            {
                SetRoutingStatus("Сохраняем проверенную группу EXE…", WpfBrushes.Goldenrod);
                await _secureRoutingRegistry.AddApplicationBundleAsync(
                    bundleDialog.DisplayName,
                    fileDialog.FileName,
                    bundleDialog.SelectedExecutables);
                await RefreshRoutingRegistryAsync();
                await TryApplyLiveRoutingRulesAsync("Добавление приложения");
            }
            catch (Exception ex)
            {
                SetRoutingStatus("Приложение не добавлено: " + ex.Message, WpfBrushes.OrangeRed);
            }
            finally
            {
                _routingRegistryOperationInProgress = false;
                RenderRoutingRegistryCards();
            }
        }

        private async void EditRoutingApplicationBundle_ClickAsync(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button button ||
                button.Tag is not Guid entryId ||
                _routingRegistryOperationInProgress)
            {
                return;
            }

            RoutingRegistryEntry? entry = _routingRegistryEntries.FirstOrDefault(item =>
                item.Id == entryId && item.Kind == RoutingTargetKind.Application);
            if (entry is null)
                return;

            if (!File.Exists(entry.PrimaryValue))
            {
                SetRoutingStatus(
                    "Основной EXE не найден. Удалите карточку и добавьте приложение заново.",
                    WpfBrushes.OrangeRed);
                return;
            }

            RoutingApplicationBundleDialog dialog = new(
                entry.PrimaryValue,
                entry.DisplayName,
                entry.RelatedExecutables)
            {
                Owner = this
            };
            if (dialog.ShowDialog() != true)
                return;

            _routingRegistryOperationInProgress = true;
            RenderRoutingRegistryCards();
            try
            {
                await _secureRoutingRegistry.UpdateApplicationBundleAsync(
                    entry.Id,
                    dialog.DisplayName,
                    entry.PrimaryValue,
                    dialog.SelectedExecutables);
                await RefreshRoutingRegistryAsync();
                await TryApplyLiveRoutingRulesAsync("Изменение состава приложения");
            }
            catch (Exception ex)
            {
                SetRoutingStatus("Состав группы не обновлён: " + ex.Message, WpfBrushes.OrangeRed);
                await RefreshRoutingRegistryAsync();
            }
            finally
            {
                _routingRegistryOperationInProgress = false;
                RenderRoutingRegistryCards();
            }
        }

        private async void AddRoutingSite_ClickAsync(object sender, RoutedEventArgs e)
        {
            if (_routingRegistryOperationInProgress)
                return;

            RoutingSiteDialog dialog = new()
            {
                Owner = this
            };
            if (dialog.ShowDialog() != true)
                return;

            _routingRegistryOperationInProgress = true;
            RenderRoutingRegistryCards();
            try
            {
                await _secureRoutingRegistry.AddWebsiteAsync(
                    dialog.Domain,
                    dialog.IncludeSubdomains);
                await RefreshRoutingRegistryAsync();
                await TryApplyLiveRoutingRulesAsync("Добавление сайта");
            }
            catch (Exception ex)
            {
                SetRoutingStatus("Сайт не добавлен: " + ex.Message, WpfBrushes.OrangeRed);
            }
            finally
            {
                _routingRegistryOperationInProgress = false;
                RenderRoutingRegistryCards();
            }
        }

        private async void RoutingToggle_ChangedAsync(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Primitives.ToggleButton toggle ||
                toggle.Tag is not Guid entryId ||
                _routingRegistryOperationInProgress)
            {
                return;
            }

            bool isEnabled = toggle.IsChecked == true;
            _routingRegistryOperationInProgress = true;
            RenderRoutingRegistryCards();
            try
            {
                bool updated = await _secureRoutingRegistry.SetEnabledAsync(entryId, isEnabled);
                if (!updated)
                    throw new InvalidOperationException("Правило уже отсутствует в реестре.");

                await RefreshRoutingRegistryAsync();
                await TryApplyLiveRoutingRulesAsync("Изменение правила");
            }
            catch (Exception ex)
            {
                SetRoutingStatus("Не удалось изменить правило: " + ex.Message, WpfBrushes.OrangeRed);
                await RefreshRoutingRegistryAsync();
            }
            finally
            {
                _routingRegistryOperationInProgress = false;
                RenderRoutingRegistryCards();
            }
        }

        private async void DeleteRoutingEntry_ClickAsync(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button button ||
                button.Tag is not Guid entryId ||
                _routingRegistryOperationInProgress)
            {
                return;
            }

            RoutingRegistryEntry? entry = _routingRegistryEntries
                .FirstOrDefault(item => item.Id == entryId);
            if (entry is null)
                return;

            bool isApplication = entry.Kind == RoutingTargetKind.Application;
            RoutingConfirmDialog dialog = new(
                "Удаление правила",
                isApplication
                    ? "Удалить приложение из VPN-маршрутизации?"
                    : "Удалить сайт из VPN-маршрутизации?",
                entry.DisplayName,
                isApplication
                    ? "Само приложение или игра останется установленным. Serpium удалит только запись и связанную группу EXE из своего реестра маршрутизации."
                    : "Serpium удалит только доменное правило из своего реестра. Сохранённые VPN-профили не изменятся.",
                "Удалить")
            {
                Owner = this
            };

            if (dialog.ShowDialog() != true)
                return;

            _routingRegistryOperationInProgress = true;
            RenderRoutingRegistryCards();
            try
            {
                await _secureRoutingRegistry.DeleteAsync(entryId);
                await RefreshRoutingRegistryAsync();
                await TryApplyLiveRoutingRulesAsync("Удаление правила");
            }
            catch (Exception ex)
            {
                SetRoutingStatus("Правило не удалено: " + ex.Message, WpfBrushes.OrangeRed);
            }
            finally
            {
                _routingRegistryOperationInProgress = false;
                RenderRoutingRegistryCards();
            }
        }

        private async void ClearRoutingRegistry_ClickAsync(object sender, RoutedEventArgs e)
        {
            if (_routingRegistryOperationInProgress || _routingRegistryEntries.Count == 0)
                return;

            RoutingConfirmDialog dialog = new(
                "Очистка маршрутизации",
                "Удалить весь список маршрутизации?",
                $"Правил: {_routingRegistryEntries.Count}",
                "Будут удалены все записи приложений, групп EXE и сайтов. Установленные программы, игры и сохранённые VPN-профили останутся без изменений.",
                "Удалить список")
            {
                Owner = this
            };

            if (dialog.ShowDialog() != true)
                return;

            _routingRegistryOperationInProgress = true;
            RenderRoutingRegistryCards();
            try
            {
                await _secureRoutingRegistry.ClearAsync();
                await RefreshRoutingRegistryAsync();
                await TryApplyLiveRoutingRulesAsync("Очистка списка");
            }
            catch (Exception ex)
            {
                SetRoutingStatus("Список не очищен: " + ex.Message, WpfBrushes.OrangeRed);
            }
            finally
            {
                _routingRegistryOperationInProgress = false;
                RenderRoutingRegistryCards();
            }
        }

        private void SetRoutingStatus(string text, WpfBrush foreground)
        {
            RoutingStatusTextBlock.Text = text;
            RoutingStatusTextBlock.Foreground = foreground;
            RoutingStatusIndicator.Fill = foreground;

            RoutingStatusBorder.BorderBrush = foreground == WpfBrushes.OrangeRed
                ? new SolidColorBrush(Color.FromRgb(0x82, 0x3F, 0x45))
                : foreground == WpfBrushes.LightGreen
                    ? new SolidColorBrush(Color.FromRgb(0x36, 0x72, 0x50))
                    : new SolidColorBrush(Color.FromRgb(0x34, 0x34, 0x42));
        }

        private async Task<bool> RecoverRelayLifecycleAtStartupAsync()
        {
            _activeSavedProfileId = null;
            _activeSavedProfileSocksPort = null;
            ClearActiveRoutingSnapshot();
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
                _routingRuleSetRuntime.DeleteBestEffort();

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

                bool expectsXrayWithRoutingTun =
                    expectsXray && _activeSavedProfileUsesRoutingTun;

                if (expectsXrayWithRoutingTun)
                {
                    RelayGatewayState xrayState = _serpiumXraySessionManager.State;
                    RelayGatewayState routingTunState =
                        _serpiumSingBoxSessionManager.State;

                    if (xrayState == RelayGatewayState.Failed ||
                        routingTunState == RelayGatewayState.Failed ||
                        !xrayLive ||
                        !singBoxLive)
                    {
                        string reason = xrayState == RelayGatewayState.Failed
                            ? _serpiumXraySessionManager.LastError ??
                              "Xray завершился с ошибкой"
                            : routingTunState == RelayGatewayState.Failed
                                ? _serpiumSingBoxSessionManager.LastError ??
                                  "выборочный TUN завершился с ошибкой"
                                : !xrayLive
                                    ? "Xray неожиданно завершился"
                                    : "выборочный TUN неожиданно завершился";

                        await StopAllRelayTransportsBestEffortAsync();
                        await MarkSavedProfileRuntimeFailedAsync(profileId, reason);
                    }

                    return;
                }

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
            _routingRuleSetRuntime.DeleteBestEffort();
        }

        private async Task MarkSavedProfileRuntimeFailedAsync(
            Guid profileId,
            string reason)
        {
            _failedSavedProfileId = profileId;
            _failedSavedProfileMessage = NormalizeLifecycleError(reason);
            _activeSavedProfileId = null;
            _activeSavedProfileSocksPort = null;
            ClearActiveRoutingSnapshot();
            _currentProviderProfileSaved = false;
            _validatedRelayProfile = null;
            DisposeValidatedProviderRuntimeProfile();
            _routingRuleSetRuntime.DeleteBestEffort();
            RelayLifecycleRecovery.DeleteGeneratedSecrets(AppContext.BaseDirectory);

            RelayClientSocksStateTextBlock.Text = "Транспорт: остановлен";
            RelayClientSocksStateTextBlock.Foreground = WpfBrushes.OrangeRed;
            SetRelayStatus(
                "Статус: активный профиль аварийно остановлен — " +
                _failedSavedProfileMessage,
                WpfBrushes.OrangeRed);

            UpdateRelayClientUi();
            UpdateRoutingSummaryStatus();
            RenderRoutingRegistryCards();
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
                EncodedKeyEnvelopeDecodeResult encodedInput =
                    EncodedKeyEnvelopeDecoder.Decode(RelayClientKeyTextBox.Text);
                SerpiumParseResult parseResult =
                    _serpiumParser.Parse(encodedInput.NormalizedKey);
                if (!parseResult.Success)
                {
                    _validatedRelayProfile = null;
                    RelayDetectedProfileTextBlock.Text = "Ключ не распознан.";
                    SetRelayStatus("Статус: ключ отклонён — " + SensitiveDiagnosticRedactor.RedactText(parseResult.Error), WpfBrushes.OrangeRed);
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
                RelayDetectedProfileTextBlock.Text =
                    encodedInput.SafeSummaryPrefix + BuildRelayProfileSummary(profile);
                SetRelayStatus(
                    encodedInput.WasDecoded
                        ? $"Статус: Base64-контейнер раскрыт локально — проверяем {profile.Protocol.ToUpperInvariant()} и Xray-конфигурацию…"
                        : $"Статус: проверяем {profile.Protocol.ToUpperInvariant()}-ключ и Xray-конфигурацию…",
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
                    string safeServer =
                        SensitiveDiagnosticRedactor.MaskHost(profile.Server);
                    SetRelayStatus(
                        $"Статус: ключ распознан — {profile.Protocol.ToUpperInvariant()}; " +
                        $"сервер {safeServer}:{profile.Port} доступен.",
                        WpfBrushes.LightGreen);
                }
                else
                {
                    string safeServer =
                        SensitiveDiagnosticRedactor.MaskHost(profile.Server);
                    SetRelayStatus(
                        $"Статус: ключ корректен, но сервер {safeServer}:{profile.Port} " +
                        "не ответил на TCP-проверку.",
                        WpfBrushes.Goldenrod);
                }
            }
            catch (Exception ex)
            {
                SetRelayStatus("Статус: ошибка проверки — " + SensitiveDiagnosticRedactor.RedactText(ex.Message), WpfBrushes.OrangeRed);
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

            ClearPendingRelaySourceKey();
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

        private void ClearRelayKeyInputAfterSuccessfulConnection(
            string sourceKey,
            EncodedKeyEnvelopeDecodeResult encodedInput)
        {
            _pendingRelaySourceKey = encodedInput.NormalizedKey;
            _pendingRelaySourceWasDecoded = encodedInput.WasDecoded;
            ClearRelayKeyInputAndMatchingClipboard(sourceKey);
        }

        private void ClearRelayKeyInputAndMatchingClipboard(
            string sourceKey)
        {
            _suppressRelayKeyTextChanged = true;
            try
            {
                RelayClientKeyTextBox.Clear();

                if (string.IsNullOrWhiteSpace(sourceKey))
                    return;

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
        }

        private void ClearPendingRelaySourceKey()
        {
            _pendingRelaySourceKey = null;
            _pendingRelaySourceWasDecoded = false;
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
            summary.Append(SensitiveDiagnosticRedactor.MaskHost(profile.Server));
            summary.Append(':');
            summary.Append(profile.Port);

            if (!string.IsNullOrWhiteSpace(profile.ServerName) &&
                !string.Equals(profile.ServerName, profile.Server, StringComparison.OrdinalIgnoreCase))
            {
                summary.AppendLine();
                summary.Append("SNI: ");
                summary.Append(SensitiveDiagnosticRedactor.MaskHost(profile.ServerName));
            }

            string safeProfileName =
                SensitiveDiagnosticRedactor.SanitizeProfileName(profile.Name);
            if (!string.IsNullOrWhiteSpace(safeProfileName))
            {
                summary.AppendLine();
                summary.Append("Профиль: ");
                summary.Append(safeProfileName);
            }

            summary.AppendLine();
            summary.Append(
                "Данные доступа: UUID, пароли, ключи Reality и полные URI скрыты.");

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





