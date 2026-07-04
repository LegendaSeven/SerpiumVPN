using System;
using System.Globalization;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
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

        // Используем IOPath вместо Path, ведем строго к файлу в bin_files
        private readonly string _listFilePath = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "bin_files", "lists", "list-general-user.txt");

        public MainWindow()
        {
            InitializeComponent();
            _zapretManager = new ZapretManager();
            _telegramProxyManager = new TelegramProxyManager();
            _vendorUpdateManager = new VendorUpdateManager();
            _appUpdateManager = new AppUpdateManager();
            _settings = UserRuntimeSettings.Load();
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
                if (!EnsureAdministratorForStrategies())
                    return;

                _zapretManager.StartStrategy(1);
                SaveCurrentStrategySettings();
                StartStrategyMonitor();
                UpdateStatus(true, "Работает (Способ 1)");
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
                if (!EnsureAdministratorForStrategies())
                    return;

                CancelStrategySelection();
                ButtonStrategy2.IsEnabled = false;

                // 1. Считываем состояние чекбоксов из UI
                bool needYoutube = CheckYouTube.IsChecked ?? false;
                bool needDiscord = CheckDiscord.IsChecked ?? false;
                SaveServiceSelectionSettings();

                _strategySelectionCts = new CancellationTokenSource();

                System.Diagnostics.Debug.WriteLine($"[UI] Запуск автоподбора. YouTube: {needYoutube}, Discord: {needDiscord}");

                // 2. Передаем флаги в ZapretManager
                bool isStrategyFound = await _zapretManager.AutoSelectStrategyAsync(
                    needYoutube,
                    needDiscord,
                    preferFirstAcceptable: !_settings.AutoSwitchStrategies,
                    cancellationToken: _strategySelectionCts.Token
                );

                if (isStrategyFound)
                {
                    SaveCurrentStrategySettings();
                    StartStrategyMonitor();
                    UpdateStatus(true, $"Статус: Работает ({_zapretManager.CurrentStrategyName})");
                }
                else
                {
                    UpdateStatus(false, "Статус: Ошибка автоподбора");
                }
            }
            catch (OperationCanceledException)
            {
                _zapretManager.Stop();
                UpdateStatus(false, "Статус: Отключен");
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
                UpdateStatus(true, "Статус: Запускаем Telegram WS-прокси...");

                TelegramProxyStartResult result = await _telegramProxyManager.StartAsync();

                UpdateStatus(true, "Статус: Telegram WS-прокси активен");

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
                UpdateStatus(false, "Статус: TgWsProxy не найден");
                MessageBox.Show(
                    ex.Message + Environment.NewLine + Environment.NewLine + @"Положите TgWsProxy_windows.exe в папку bin_files\tgws и нажмите кнопку ещё раз.",
                    "Telegram WS-прогон",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }
            catch (Exception ex)
            {
                UpdateStatus(false, "Статус: Ошибка Telegram WS-прокси");
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
                UpdateStatus(true, "Статус: Проверяем обновления файлов...");

                _zapretManager.Stop();
                _telegramProxyManager.Stop();

                Progress<string> progress = new Progress<string>(message =>
                {
                    UpdateStatus(true, "Статус: " + message);
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

                    UpdateStatus(false, "Статус: Файлы обновлены");
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
                    UpdateStatus(false, "Статус: Файлы актуальны");

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
                UpdateStatus(false, "Статус: Ошибка обновления");

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
                // SettingsWindow disables its own button while this task runs.
            }
        }

        private async Task CheckAppUpdatesAsync(bool showSuccessMessage)
        {
            try
            {
                UpdateStatus(true, "Статус: Проверяем обновление программы...");

                Progress<int> progress = new Progress<int>(percent =>
                {
                    UpdateStatus(true, $"Статус: Скачиваем обновление программы... {percent}%");
                });

                AppUpdateCheckResult result = await _appUpdateManager.CheckDownloadAndApplyAsync(progress);

                switch (result.Status)
                {
                    case AppUpdateCheckStatus.NoUpdates:
                        UpdateStatus(false, "Статус: Программа актуальна");

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
                        UpdateStatus(false, "Статус: Обновление готово");

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
                UpdateStatus(false, "Статус: Ошибка обновления программы");
                MessageBox.Show(
                    $"Не удалось проверить или установить обновление программы: {ex.Message}",
                    "Обновление программы",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }
            finally
            {
                // SettingsWindow disables its own button while this task runs.
            }
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            SettingsWindow settingsWindow = new SettingsWindow(_settings, CheckAppUpdatesAsync, CheckVendorUpdatesAsync)
            {
                Owner = this
            };

            settingsWindow.ShowDialog();

            if (_settings.AutoSwitchStrategies && _zapretManager.IsRunning)
                StartStrategyMonitor();
            else
                StopStrategyMonitor();
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
                UpdateStatus(false, "Статус: Отключен");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при остановке: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Обновление UI-индикатора (зеленый/красный кружок)
        private void UpdateStatus(bool isRunning, string text)
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
            _trayIcon?.Dispose();
        }

        private void MainWindow_StateChanged(object? sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
                Hide();
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
                UpdateStatus(false, "Статус: Отключен");
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

        private void ShowFromTray()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        }

        private void ExitApplication()
        {
            _isRealExit = true;
            Close();
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

        private bool EnsureAdministratorForStrategies(bool showMessage = true)
        {
            if (IsRunningAsAdministrator())
                return true;

            if (showMessage)
            {
                MessageBoxResult restart = MessageBox.Show(
                    "Для запуска стратегий обхода нужны права администратора.\n\nПерезапустить SerpiumVPN от имени администратора?",
                    "Нужны права администратора",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information
                );

                if (restart != MessageBoxResult.Yes)
                    return false;
            }

            try
            {
                string? exePath = Environment.ProcessPath;
                if (string.IsNullOrWhiteSpace(exePath))
                    return false;

                _isRealExit = true;

                Process.Start(new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true,
                    Verb = "runas"
                });

                Close();
                return false;
            }
            catch (Exception ex)
            {
                if (showMessage)
                    MessageBox.Show($"Не удалось перезапустить с правами администратора: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);

                return false;
            }
        }

        private static bool IsRunningAsAdministrator()
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void LoadRuntimeSettingsIntoUi()
        {
            CheckYouTube.IsChecked = _settings.CheckYouTube;
            CheckDiscord.IsChecked = _settings.CheckDiscord;
        }

        private async Task RestoreSavedStrategyAsync()
        {
            if (!_settings.AutoStartLastStrategy || string.IsNullOrWhiteSpace(_settings.LastStrategyName))
                return;

            try
            {
                if (!EnsureAdministratorForStrategies(showMessage: false))
                {
                    UpdateStatus(false, "Статус: Для автозапуска стратегии нужны права администратора");
                    return;
                }

                UpdateStatus(true, $"Статус: Запускаем сохранённую стратегию ({_settings.LastStrategyName})...");
                _zapretManager.StartStrategy(_settings.LastStrategyName);
                await Task.Delay(2500);

                bool ok = await _zapretManager.CheckConnectionAsync(_settings.CheckYouTube, _settings.CheckDiscord);
                if (ok)
                {
                    StartStrategyMonitor();
                    UpdateStatus(true, $"Статус: Работает ({_settings.LastStrategyName})");
                    return;
                }

                UpdateStatus(true, "Статус: Сохранённая стратегия просела, подбираем новую...");
                bool selected = await _zapretManager.AutoSelectStrategyAsync(_settings.CheckYouTube, _settings.CheckDiscord, showMessages: false);
                if (selected)
                {
                    SaveCurrentStrategySettings();
                    StartStrategyMonitor();
                    UpdateStatus(true, $"Статус: Работает ({_zapretManager.CurrentStrategyName})");
                }
                else
                {
                    UpdateStatus(false, "Статус: Нет подходящей стратегии");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RESTORE WARN] {ex}");
                UpdateStatus(false, "Статус: Сохранённая стратегия не запущена");
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
                    UpdateStatus(true, $"Статус: Работает ({_zapretManager.CurrentStrategyName})");
                    return;
                }

                UpdateStatus(true, "Статус: Качество просело, меняем стратегию...");

                bool switched = await _zapretManager.AutoSelectStrategyAsync(
                    needYoutube,
                    needDiscord,
                    showMessages: false,
                    cancellationToken: _strategySelectionCts.Token
                );
                if (switched)
                {
                    SaveCurrentStrategySettings();
                    UpdateStatus(true, $"Статус: Автосмена: {_zapretManager.CurrentStrategyName}");
                }
                else
                {
                    UpdateStatus(false, "Статус: Нет стратегии с подходящей скоростью");
                }
            }
            catch (OperationCanceledException)
            {
                _zapretManager.Stop();
                UpdateStatus(false, "Статус: Отключен");
            }
            finally
            {
                _strategySelectionCts?.Dispose();
                _strategySelectionCts = null;
                _isMonitoringStrategy = false;
            }
        }

      
    }
}
