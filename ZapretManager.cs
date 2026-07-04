using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace SerpiumVPN
{
    public class ZapretManager
    {
        private Process? _zapretProcess;

        private readonly string _basePath = AppDomain.CurrentDomain.BaseDirectory;
        private readonly string _binFilesPath;
        private readonly string _batsPath;
        private readonly string _binPath;
        private readonly string _listsPath;
        private readonly string _logsPath;
        private readonly string _winwsExePath;

        public string? CurrentStrategyName { get; private set; }
        public string LastQualitySummary { get; private set; } = "";

        public ZapretManager()
        {
            _binFilesPath = Path.Combine(_basePath, "bin_files");
            _batsPath = Path.Combine(_binFilesPath, "bats");
            _binPath = Path.Combine(_binFilesPath, "bin");
            _listsPath = Path.Combine(_binFilesPath, "lists");
            _logsPath = Path.Combine(_binFilesPath, "logs");
            _winwsExePath = Path.Combine(_binPath, "winws.exe");

            Directory.CreateDirectory(_logsPath);
        }

        /// <summary>
        /// Проверяет, запущен ли winws.exe именно из папки этого приложения.
        /// </summary>
        public bool IsRunning => FindManagedWinwsProcesses().Any();

        /// <summary>
        /// Способ 1 — general.bat.
        /// Способ 2 лучше запускать через AutoSelectStrategyAsync из MainWindow.
        /// </summary>
        public void StartStrategy(int strategyNum)
        {
            if (strategyNum == 1)
            {
                StartStrategy("general.bat");
                return;
            }

            if (strategyNum == 2)
            {
                _ = AutoSelectStrategyAsync(checkYoutube: false, checkDiscord: true);
                return;
            }

            throw new ArgumentOutOfRangeException(nameof(strategyNum), "Неизвестный номер стратегии.");
        }

        /// <summary>
        /// Запуск конкретной стратегии по имени bat-файла.
        /// Реально запускает winws.exe напрямую с аргументами, извлечёнными из bat.
        /// </summary>
        public void StartStrategy(string batFileName)
        {
            string batPath = ResolveBatPath(batFileName);
            StartStrategyFromBatPath(batPath);
        }

        /// <summary>
        /// Способ 2 — автоподбор.
        /// Перебирает все general*.bat, извлекает из каждого стратегию winws.exe,
        /// запускает её напрямую и оставляет первую рабочую.
        /// </summary>
        public async Task<bool> AutoSelectStrategyAsync(
            bool checkYoutube,
            bool checkDiscord,
            bool showMessages = true,
            bool preferFirstAcceptable = false)
        {
            List<string> batFiles = GetStrategyBatFiles();
            string? bestBatPath = null;
            ConnectionQualityResult? bestQuality = null;

            Debug.WriteLine("==================================================");
            Debug.WriteLine($"[AUTO] Старт автоподбора. YouTube: {checkYoutube}, Discord: {checkDiscord}");
            Debug.WriteLine($"[AUTO] Найдено стратегий: {batFiles.Count}");
            Debug.WriteLine("==================================================");

            foreach (string batPath in batFiles)
            {
                StrategyProbeResult result = await TryStartAndCheckStrategyAsync(batPath, checkYoutube, checkDiscord);

                if (result.IsAcceptable && IsBetterQuality(result.Quality, bestQuality))
                {
                    bestBatPath = batPath;
                    bestQuality = result.Quality;

                    if (preferFirstAcceptable)
                        break;
                }

                Stop();
            }

            if (bestBatPath == null)
            {
                string generatedBatPath = CreateFallbackStrategyBatFile();

                Debug.WriteLine("");
                Debug.WriteLine($"[AUTO GENERATE] Все готовые стратегии не подошли. Создана новая: {Path.GetFileName(generatedBatPath)}");

                StrategyProbeResult generatedResult = await TryStartAndCheckStrategyAsync(generatedBatPath, checkYoutube, checkDiscord);

                if (generatedResult.IsAcceptable)
                {
                    bestBatPath = generatedBatPath;
                    bestQuality = generatedResult.Quality;
                }

                Stop();
            }

            if (bestBatPath != null)
            {
                StartStrategyFromBatPath(bestBatPath);
                CurrentStrategyName = Path.GetFileName(bestBatPath);
                LastQualitySummary = bestQuality?.Summary ?? "";

                if (showMessages)
                {
                    MessageBox.Show(
                        $"Подобран лучший рабочий конфиг:\n{CurrentStrategyName}\n\n{LastQualitySummary}",
                        "Автоподбор",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }

                return true;
            }

            Stop();

            if (showMessages)
            {
                MessageBox.Show(
                    "Ни одна стратегия не подошла по доступности или скорости.\n\n" +
                    "Проверьте запуск от имени администратора, антивирус/WinDivert и актуальность файлов zapret.",
                    "Автоподбор",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }

            return false;
        }

        private async Task<StrategyProbeResult> TryStartAndCheckStrategyAsync(string batPath, bool checkYoutube, bool checkDiscord)
        {
            string batFileName = Path.GetFileName(batPath);

            try
            {
                Debug.WriteLine("");
                Debug.WriteLine($"[AUTO TEST] Пробуем: {batFileName}");

                StartStrategyFromBatPath(batPath);

                Debug.WriteLine("[AUTO WAIT] Ждём 2.5 сек для запуска winws/WinDivert...");
                await Task.Delay(2500);

                if (!IsRunning)
                {
                    Debug.WriteLine($"[AUTO FAIL] winws.exe не остался висеть после запуска {batFileName}");
                    return StrategyProbeResult.Fail();
                }

                ConnectionQualityResult quality = await CheckConnectionQualityAsync(checkYoutube, checkDiscord);

                if (quality.IsAcceptable)
                {
                    Debug.WriteLine("--------------------------------------------------");
                    Debug.WriteLine($"[AUTO SUCCESS] Рабочая стратегия: {batFileName}. {quality.Summary}");
                    Debug.WriteLine("--------------------------------------------------");

                    CurrentStrategyName = batFileName;
                    LastQualitySummary = quality.Summary;
                    return StrategyProbeResult.Success(quality);
                }

                Debug.WriteLine($"[AUTO FAIL] Проверка сервисов/скорости не прошла: {batFileName}. {quality.Summary}");
                return StrategyProbeResult.Fail(quality);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AUTO ERR] {batFileName}: {ex.Message}");
            }

            return StrategyProbeResult.Fail();
        }

        private string CreateFallbackStrategyBatFile()
        {
            Directory.CreateDirectory(_batsPath);

            int generatedCount = Directory
                .GetFiles(_batsPath, "general (AUTO GENERATED*.bat")
                .Length;

            string[] splitPositions = { "2,sniext+1", "1", "2" };
            int[] splitOverlaps = { 679, 664, 720, 652, 681 };
            string[] tcpFoolings = { "badseq", "ts" };

            string splitPosition = splitPositions[generatedCount % splitPositions.Length];
            int splitOverlap = splitOverlaps[generatedCount % splitOverlaps.Length];
            string tcpFooling = tcpFoolings[generatedCount % tcpFoolings.Length];
            int repeats = 8 + (generatedCount % 3);
            int udpRepeats = 10 + (generatedCount % 4);

            string fileName = $"general (AUTO GENERATED {DateTime.Now:yyyyMMdd-HHmmss}).bat";
            string batPath = Path.Combine(_batsPath, fileName);

            string content =
                "@echo off\r\n" +
                "chcp 65001 > nul\r\n" +
                ":: 65001 - UTF-8\r\n" +
                "\r\n" +
                "cd /d \"%~dp0\"\r\n" +
                "call service.bat status_zapret\r\n" +
                "call service.bat check_updates\r\n" +
                "call service.bat load_game_filter\r\n" +
                "call service.bat load_user_lists\r\n" +
                "echo:\r\n" +
                "\r\n" +
                "set \"BIN=%~dp0bin\\\"\r\n" +
                "set \"LISTS=%~dp0lists\\\"\r\n" +
                "cd /d %BIN%\r\n" +
                "\r\n" +
                "start \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilterTCP% --wf-udp=443,19294-19344,50000-50100,%GameFilterUDP% ^\r\n" +
                "--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" --hostlist-exclude=\"%LISTS%list-exclude-user.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"%BIN%quic_initial_www_google_com.bin\" --new ^\r\n" +
                "--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desync-fake-stun=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desync-repeats=6 --new ^\r\n" +
                $"--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake,multisplit --dpi-desync-split-seqovl={splitOverlap} --dpi-desync-split-pos={splitPosition} --dpi-desync-fooling={tcpFooling} --dpi-desync-repeats={repeats} --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls=\"%BIN%tls_clienthello_www_google_com.bin\" --new ^\r\n" +
                $"--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --ip-id=zero --dpi-desync=fake,multisplit --dpi-desync-split-seqovl={splitOverlap} --dpi-desync-split-pos={splitPosition} --dpi-desync-fooling={tcpFooling} --dpi-desync-repeats={repeats} --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_www_google_com.bin\" --dpi-desync-fake-tls=\"%BIN%tls_clienthello_www_google_com.bin\" --new ^\r\n" +
                $"--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" --hostlist-exclude=\"%LISTS%list-exclude-user.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl={splitOverlap} --dpi-desync-split-pos={splitPosition} --dpi-desync-fooling={tcpFooling} --dpi-desync-repeats={repeats} --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_max_ru.bin\" --dpi-desync-fake-tls=\"%BIN%stun.bin\" --dpi-desync-fake-tls=\"%BIN%tls_clienthello_max_ru.bin\" --dpi-desync-fake-http=\"%BIN%tls_clienthello_max_ru.bin\" --new ^\r\n" +
                "--filter-udp=443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" --hostlist-exclude=\"%LISTS%list-exclude-user.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"%BIN%quic_initial_www_google_com.bin\" --new ^\r\n" +
                $"--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" --hostlist-exclude=\"%LISTS%list-exclude-user.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl={splitOverlap} --dpi-desync-split-pos={splitPosition} --dpi-desync-fooling={tcpFooling} --dpi-desync-repeats={repeats} --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_max_ru.bin\" --dpi-desync-fake-tls=\"%BIN%stun.bin\" --dpi-desync-fake-tls=\"%BIN%tls_clienthello_max_ru.bin\" --dpi-desync-fake-http=\"%BIN%tls_clienthello_max_ru.bin\" --new ^\r\n" +
                $"--filter-tcp=%GameFilterTCP% --ipset=\"%LISTS%ipset-all.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" --dpi-desync=fake,multisplit --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n4 --dpi-desync-split-seqovl={splitOverlap} --dpi-desync-split-pos={splitPosition} --dpi-desync-fooling={tcpFooling} --dpi-desync-repeats={repeats} --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_max_ru.bin\" --dpi-desync-fake-tls=\"%BIN%stun.bin\" --dpi-desync-fake-tls=\"%BIN%tls_clienthello_max_ru.bin\" --dpi-desync-fake-http=\"%BIN%tls_clienthello_max_ru.bin\" --new ^\r\n" +
                $"--filter-udp=%GameFilterUDP% --ipset=\"%LISTS%ipset-all.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --ipset-exclude=\"%LISTS%ipset-exclude-user.txt\" --dpi-desync=fake --dpi-desync-repeats={udpRepeats} --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desync-cutoff=n3\r\n";

            File.WriteAllText(batPath, content, Encoding.UTF8);
            return batPath;
        }

        /// <summary>
        /// Проверка доступности выбранных сервисов.
        /// </summary>
        public async Task<bool> CheckConnectionAsync(bool checkYoutube, bool checkDiscord, int timeoutMs = 3000)
        {
            ConnectionQualityResult quality = await CheckConnectionQualityAsync(checkYoutube, checkDiscord, timeoutMs);
            LastQualitySummary = quality.Summary;
            return quality.IsAcceptable;
        }

        public async Task<ConnectionQualityResult> CheckConnectionQualityAsync(bool checkYoutube, bool checkDiscord, int timeoutMs = 5000)
        {
            if (!checkYoutube && !checkDiscord)
            {
                Debug.WriteLine("[CHECK] Сервисы не выбраны. Проверяем сеть через Cloudflare...");
                return await QuickMeasureUrlAsync("https://1.1.1.1", "Cloudflare", timeoutMs);
            }

            List<ConnectionQualityResult> results = new List<ConnectionQualityResult>();

            if (checkYoutube)
            {
                Debug.WriteLine("[CHECK] Тестируем YouTube...");
                results.Add(await QuickMeasureUrlAsync("https://www.youtube.com", "YouTube", timeoutMs));
            }

            if (checkDiscord)
            {
                Debug.WriteLine("[CHECK] Тестируем Discord...");
                results.Add(await QuickMeasureUrlAsync("https://discord.com", "Discord", timeoutMs));
            }

            if (results.Count == 0)
                return ConnectionQualityResult.Fail("Сервисы не выбраны");

            bool isAcceptable = results.All(result => result.IsAcceptable);
            int latency = results.Max(result => result.LatencyMs);
            double speed = results.Min(result => result.KilobytesPerSecond);
            string summary = string.Join("; ", results.Select(result => result.Summary));

            return new ConnectionQualityResult(isAcceptable, latency, speed, summary);
        }

        private async Task<ConnectionQualityResult> QuickMeasureUrlAsync(string url, string name, int timeoutMs)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            try
            {
                using HttpClient client = new HttpClient
                {
                    Timeout = TimeSpan.FromMilliseconds(timeoutMs)
                };

                using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
                using HttpResponseMessage response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead
                );

                bool reachable = response.IsSuccessStatusCode || (int)response.StatusCode < 500;
                if (!reachable)
                    return ConnectionQualityResult.Fail($"{name}: HTTP {(int)response.StatusCode}");

                int bytesRead = 0;
                byte[] buffer = new byte[8192];

                await using Stream stream = await response.Content.ReadAsStreamAsync();

                while (bytesRead < 192 * 1024)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, 192 * 1024 - bytesRead)));
                    if (read == 0)
                        break;

                    bytesRead += read;
                }

                stopwatch.Stop();

                int elapsedMs = Math.Max(1, (int)stopwatch.ElapsedMilliseconds);
                double kbps = bytesRead > 0 ? bytesRead / 1024.0 / (elapsedMs / 1000.0) : 0;
                bool enoughLatency = elapsedMs <= 5000;
                bool enoughSpeed = bytesRead < 16 * 1024 || kbps >= 32;
                bool acceptable = enoughLatency && enoughSpeed;

                return new ConnectionQualityResult(
                    acceptable,
                    elapsedMs,
                    kbps,
                    $"{name}: {elapsedMs} мс, {kbps:F0} КБ/с"
                );
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                Debug.WriteLine($"[HTTP ERR] {url}: {ex.Message}");
                return ConnectionQualityResult.Fail($"{name}: недоступен");
            }
        }

        private async Task<bool> QuickTestUrlAsync(string url, int timeoutMs)
        {
            try
            {
                using HttpClient client = new HttpClient
                {
                    Timeout = TimeSpan.FromMilliseconds(timeoutMs)
                };

                using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);
                using HttpResponseMessage response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead
                );

                return response.IsSuccessStatusCode || (int)response.StatusCode < 500;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HTTP ERR] {url}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Запускает winws.exe напрямую, без вызова general.bat/service.bat.
        /// Это убирает ошибку с путём вида bin_files\D:\...\winws.exe.
        /// </summary>
        private void StartStrategyFromBatPath(string batPath)
        {
            Stop();

            if (!File.Exists(_winwsExePath))
                throw new FileNotFoundException($"winws.exe не найден: {_winwsExePath}");

            if (!File.Exists(batPath))
                throw new FileNotFoundException($"Bat-файл не найден: {batPath}");

            string arguments = ExtractWinwsArgumentsFromBat(batPath);

            if (string.IsNullOrWhiteSpace(arguments))
                throw new InvalidOperationException($"Не удалось извлечь аргументы winws.exe из {Path.GetFileName(batPath)}");

            CurrentStrategyName = Path.GetFileName(batPath);

            string logPath = Path.Combine(
                _logsPath,
                $"winws_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}_{MakeSafeFileName(Path.GetFileNameWithoutExtension(batPath))}.log"
            );

            File.WriteAllText(
                logPath,
                $"Strategy: {CurrentStrategyName}{Environment.NewLine}" +
                $"Exe: {_winwsExePath}{Environment.NewLine}" +
                $"Args: {arguments}{Environment.NewLine}" +
                $"WorkDir: {_binPath}{Environment.NewLine}",
                Encoding.UTF8
            );

            _zapretProcess = new Process();
            _zapretProcess.StartInfo.FileName = _winwsExePath;
            _zapretProcess.StartInfo.Arguments = arguments;
            _zapretProcess.StartInfo.WorkingDirectory = _binPath;
            _zapretProcess.StartInfo.CreateNoWindow = true;
            _zapretProcess.StartInfo.UseShellExecute = false;
            Process startedProcess = _zapretProcess;

            Debug.WriteLine("==================================================");
            Debug.WriteLine($"[LAUNCH DIRECT] Strategy: {CurrentStrategyName}");
            Debug.WriteLine($"[LAUNCH DIRECT] Exe: {_winwsExePath}");
            Debug.WriteLine($"[LAUNCH DIRECT] Args: {arguments}");
            Debug.WriteLine($"[LAUNCH DIRECT] Log: {logPath}");
            Debug.WriteLine("==================================================");

            startedProcess.Start();

            _ = Task.Run(async () =>
            {
                await Task.Delay(1200);

                try
                {
                    if (startedProcess.HasExited)
                    {
                        Debug.WriteLine($"[LAUNCH WARN] winws.exe сразу завершился. ExitCode: {startedProcess.ExitCode}");
                        File.AppendAllText(
                            logPath,
                            $"{Environment.NewLine}winws.exe exited quickly. ExitCode: {startedProcess.ExitCode}{Environment.NewLine}",
                            Encoding.UTF8
                        );
                    }
                }
                catch
                {
                    // ignore
                }
            });
        }

        /// <summary>
        /// Достаёт полную команду winws.exe из general*.bat.
        /// Поддерживает:
        /// - многострочные команды с ^
        /// - однострочные bat-файлы
        /// - start "title" /min "%BIN%winws.exe" ...
        /// - переменные %BIN%, %LISTS%, %GameFilterTCP%, %GameFilterUDP%
        /// </summary>
        private string ExtractWinwsArgumentsFromBat(string batPath)
        {
            string[] lines = File.ReadAllLines(batPath, Encoding.UTF8);

            StringBuilder commandBuilder = new StringBuilder();
            bool capturing = false;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();

                if (string.IsNullOrWhiteSpace(line))
                    continue;

                if (IsCommentLine(line))
                    continue;

                if (!capturing)
                {
                    if (!line.Contains("winws.exe", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // В general*.bat нас интересует именно запуск, а не tasklist/findstr.
                    if (!line.Contains("start", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("%BIN%winws.exe", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("bin\\winws.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    capturing = true;
                }

                bool hasContinuation = line.EndsWith("^", StringComparison.Ordinal);

                if (hasContinuation)
                    line = line.Substring(0, line.Length - 1).Trim();

                commandBuilder.Append(line);
                commandBuilder.Append(' ');

                if (capturing && !hasContinuation)
                {
                    // Если команда была однострочной — сразу выходим.
                    // Если многострочная — выйдем после последней строки без ^.
                    break;
                }
            }

            string fullCommand = commandBuilder.ToString().Trim();

            if (string.IsNullOrWhiteSpace(fullCommand))
                return "";

            int winwsIndex = fullCommand.IndexOf("winws.exe", StringComparison.OrdinalIgnoreCase);

            if (winwsIndex < 0)
                return "";

            string args = fullCommand.Substring(winwsIndex + "winws.exe".Length).Trim();

            // После "%BIN%winws.exe" остаётся закрывающая кавычка.
            if (args.StartsWith("\"", StringComparison.Ordinal))
                args = args.Substring(1).TrimStart();

            args = ExpandKnownBatVariables(args);
            args = NormalizeArgs(args);

            Debug.WriteLine($"[EXTRACT OK] {Path.GetFileName(batPath)}");
            Debug.WriteLine($"[EXTRACT ARGS] {args}");

            return args;
        }

        private string ExpandKnownBatVariables(string args)
        {
            string bin = EnsureTrailingSlash(_binPath);
            string lists = EnsureTrailingSlash(_listsPath);
            string root = EnsureTrailingSlash(_binFilesPath);

            string result = args;

            result = result.Replace("%BIN%", bin, StringComparison.OrdinalIgnoreCase);
            result = result.Replace("%LISTS%", lists, StringComparison.OrdinalIgnoreCase);
            result = result.Replace("%~dp0bin\\", bin, StringComparison.OrdinalIgnoreCase);
            result = result.Replace("%~dp0lists\\", lists, StringComparison.OrdinalIgnoreCase);
            result = result.Replace("%~dp0", root, StringComparison.OrdinalIgnoreCase);

            // В service.bat при отключённом game filter выставляется порт 12.
            // Так оригинальные стратегии Flowseal не ломаются на пустом значении.
            result = result.Replace("%GameFilterTCP%", "12", StringComparison.OrdinalIgnoreCase);
            result = result.Replace("%GameFilterUDP%", "12", StringComparison.OrdinalIgnoreCase);
            result = result.Replace("%GameFilter%", "12", StringComparison.OrdinalIgnoreCase);

            return result;
        }

        private string NormalizeArgs(string args)
        {
            string result = args;

            result = result.Replace("^", " ");
            result = result.Replace("\r", " ");
            result = result.Replace("\n", " ");
            result = result.Replace("\t", " ");

            while (result.Contains("  ", StringComparison.Ordinal))
                result = result.Replace("  ", " ");

            return result.Trim();
        }

        public void Stop()
        {
            try
            {
                KillProcess(_zapretProcess, "текущий winws");
                _zapretProcess = null;

                foreach (Process process in FindManagedWinwsProcesses())
                    KillProcess(process, $"winws PID {process.Id}");

                CurrentStrategyName = null;
                Debug.WriteLine("[STOP] winws.exe из папки приложения остановлен.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[STOP ERR] Ошибка при остановке: {ex.Message}");
            }
        }

        private string ResolveBatPath(string batFileName)
        {
            string pathInBats = Path.Combine(_batsPath, batFileName);
            if (File.Exists(pathInBats))
                return pathInBats;

            string pathInBinFiles = Path.Combine(_binFilesPath, batFileName);
            if (File.Exists(pathInBinFiles))
                return pathInBinFiles;

            throw new FileNotFoundException($"Bat-файл не найден: {batFileName}");
        }

        private List<string> GetStrategyBatFiles()
        {
            List<string> files = new List<string>();

            if (Directory.Exists(_batsPath))
                files.AddRange(Directory.GetFiles(_batsPath, "general*.bat"));

            if (Directory.Exists(_binFilesPath))
                files.AddRange(Directory.GetFiles(_binFilesPath, "general*.bat"));

            return files
                .Where(path => Path.GetFileName(path).StartsWith("general", StringComparison.OrdinalIgnoreCase))
                .GroupBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
                .Select(group =>
                {
                    // Предпочитаем исходники из bin_files\bats.
                    string? inBats = group.FirstOrDefault(path =>
                        string.Equals(Path.GetDirectoryName(path), _batsPath, StringComparison.OrdinalIgnoreCase)
                    );

                    return inBats ?? group.First();
                })
                .OrderBy(GetStrategySortIndex)
                .ToList();
        }

        private int GetStrategySortIndex(string path)
        {
            string name = Path.GetFileNameWithoutExtension(path);

            if (name.Equals("general", StringComparison.OrdinalIgnoreCase))
                return 0;

            if (name.Equals("general (ALT)", StringComparison.OrdinalIgnoreCase))
                return 1;

            int altIndex = name.IndexOf("ALT", StringComparison.OrdinalIgnoreCase);

            if (altIndex >= 0)
            {
                string digits = new string(name.Skip(altIndex + 3).Where(char.IsDigit).ToArray());

                if (int.TryParse(digits, out int number))
                    return number + 1;
            }

            return 999;
        }

        private bool IsCommentLine(string line)
        {
            return line.StartsWith("rem ", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("::", StringComparison.OrdinalIgnoreCase);
        }

        private IEnumerable<Process> FindManagedWinwsProcesses()
        {
            foreach (Process process in Process.GetProcessesByName("winws"))
            {
                string? processPath = TryGetProcessPath(process);

                if (processPath != null && IsSamePath(processPath, _winwsExePath))
                    yield return process;
            }
        }

        private static string? TryGetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                return null;
            }
        }

        private static void KillProcess(Process? process, string description)
        {
            if (process == null)
                return;

            try
            {
                if (process.HasExited)
                    return;

                process.Kill();
                process.WaitForExit(3000);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[STOP WARN] Не удалось завершить {description}: {ex.Message}");
            }
        }

        private static bool IsSamePath(string left, string right)
        {
            try
            {
                return string.Equals(
                    Path.GetFullPath(left).TrimEnd('\\', '/'),
                    Path.GetFullPath(right).TrimEnd('\\', '/'),
                    StringComparison.OrdinalIgnoreCase
                );
            }
            catch
            {
                return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
            }
        }

        private string EnsureTrailingSlash(string path)
        {
            if (path.EndsWith("\\", StringComparison.Ordinal) || path.EndsWith("/", StringComparison.Ordinal))
                return path;

            return path + "\\";
        }

        private static string MakeSafeFileName(string name)
        {
            foreach (char invalidChar in Path.GetInvalidFileNameChars())
                name = name.Replace(invalidChar, '_');

            return name;
        }

        private static bool IsBetterQuality(ConnectionQualityResult? candidate, ConnectionQualityResult? currentBest)
        {
            if (candidate == null)
                return false;

            if (currentBest == null)
                return true;

            double candidateScore = candidate.KilobytesPerSecond - candidate.LatencyMs / 25.0;
            double currentScore = currentBest.KilobytesPerSecond - currentBest.LatencyMs / 25.0;

            return candidateScore > currentScore;
        }

        private sealed class StrategyProbeResult
        {
            private StrategyProbeResult(bool isAcceptable, ConnectionQualityResult? quality)
            {
                IsAcceptable = isAcceptable;
                Quality = quality;
            }

            public bool IsAcceptable { get; }
            public ConnectionQualityResult? Quality { get; }

            public static StrategyProbeResult Success(ConnectionQualityResult quality) => new StrategyProbeResult(true, quality);
            public static StrategyProbeResult Fail(ConnectionQualityResult? quality = null) => new StrategyProbeResult(false, quality);
        }
    }

    public sealed class ConnectionQualityResult
    {
        public ConnectionQualityResult(bool isAcceptable, int latencyMs, double kilobytesPerSecond, string summary)
        {
            IsAcceptable = isAcceptable;
            LatencyMs = latencyMs;
            KilobytesPerSecond = kilobytesPerSecond;
            Summary = summary;
        }

        public bool IsAcceptable { get; }
        public int LatencyMs { get; }
        public double KilobytesPerSecond { get; }
        public string Summary { get; }

        public static ConnectionQualityResult Fail(string summary) => new ConnectionQualityResult(false, int.MaxValue, 0, summary);
    }
}
