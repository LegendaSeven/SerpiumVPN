using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN
{
    public enum TelegramProxyStartResult
    {
        Started,
        AlreadyRunning
    }

    /// <summary>
    /// Управляет отдельным TG WS Proxy от Flowseal.
    /// Это не winws-стратегия и не системный VPN: Telegram Desktop подключается
    /// к локальному MTProto-прокси 127.0.0.1:1443, а прокси уже гонит трафик через WS/TLS.
    /// </summary>
    public sealed class TelegramProxyManager
    {
        private const string Host = "127.0.0.1";
        private const int Port = 1443;

        private Process? _process;

        private readonly string _basePath = AppDomain.CurrentDomain.BaseDirectory;
        private readonly string _tgwsPath;
        private readonly string _dataPath;
        private readonly string _configPath;
        private readonly string _linkPath;
        private readonly string _logsPath;

        private readonly string[] _exeCandidates =
        {
            "TgWsProxy_windows.exe",
            "TgWsProxy_windows_arm64.exe",
            "TgWsProxy_windows_7_64bit.exe",
            "TgWsProxy_windows_7_32bit.exe",
            "TgWsProxy_core.exe",
            "tg-ws-proxy.exe"
        };

        public TelegramProxyManager()
        {
            _tgwsPath = Path.Combine(_basePath, "bin_files", "tgws");
            _dataPath = Path.Combine(_tgwsPath, "TgWsProxy_data");
            _configPath = Path.Combine(_dataPath, "config.json");
            _linkPath = Path.Combine(_tgwsPath, "telegram_proxy_link.txt");
            _logsPath = Path.Combine(_basePath, "bin_files", "logs");

            Directory.CreateDirectory(_tgwsPath);
            Directory.CreateDirectory(_dataPath);
            Directory.CreateDirectory(_logsPath);
        }

        public async Task<TelegramProxyStartResult> StartAsync()
        {
            string exePath = ResolveExecutablePath();
            TelegramProxyConfig config = EnsurePortableConfig();
            string proxyLink = BuildTelegramProxyLink(config.Secret);
            File.WriteAllText(_linkPath, proxyLink);

            Process? running = FindRunningManagedProcess();
            if (running != null)
            {
                _process = running;
                OpenTelegramProxyLink(proxyLink);
                return TelegramProxyStartResult.AlreadyRunning;
            }

            bool useTrayApp = IsTrayExecutable(exePath);

            string arguments = useTrayApp
                ? "--portable"
                : BuildCoreArguments(config.Secret);

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? _tgwsPath,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            _process = Process.Start(startInfo);

            if (_process == null)
                throw new InvalidOperationException("Не удалось запустить TG WS Proxy.");

            bool isPortReady = await WaitForPortAsync(Host, Port, TimeSpan.FromSeconds(10));

            if (!isPortReady)
                throw new TimeoutException("TG WS Proxy запущен, но локальный порт 127.0.0.1:1443 не открылся.");

            OpenTelegramProxyLink(proxyLink);
            return TelegramProxyStartResult.Started;
        }

        public void Stop()
        {
            try
            {
                KillProcess(_process);
                _process = null;

                foreach (Process process in FindManagedProcesses())
                {
                    KillProcess(process);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TG STOP ERR] {ex.Message}");
            }
        }

        private string ResolveExecutablePath()
        {
            foreach (string candidate in _exeCandidates)
            {
                string path = Path.Combine(_tgwsPath, candidate);
                if (File.Exists(path))
                    return path;
            }

            throw new FileNotFoundException(
                $"Не найден TG WS Proxy. Ожидаемый путь: {Path.Combine(_tgwsPath, "TgWsProxy_windows.exe")}."
            );
        }

        private TelegramProxyConfig EnsurePortableConfig()
        {
            Directory.CreateDirectory(_dataPath);

            TelegramProxyConfig config = LoadConfigOrDefault();

            if (string.IsNullOrWhiteSpace(config.Secret) || !IsValidHexSecret(config.Secret))
                config.Secret = GenerateSecret();

            config.Host = Host;
            config.Port = Port;

            if (config.DcIp == null || config.DcIp.Count == 0)
                config.DcIp = new List<string> { "2:149.154.167.220", "4:149.154.167.220" };

            JsonSerializerOptions options = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };

            File.WriteAllText(_configPath, JsonSerializer.Serialize(config, options));
            return config;
        }

        private TelegramProxyConfig LoadConfigOrDefault()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    TelegramProxyConfig? config = JsonSerializer.Deserialize<TelegramProxyConfig>(
                        File.ReadAllText(_configPath)
                    );

                    if (config != null)
                        return config;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TG CONFIG WARN] Не удалось прочитать config.json: {ex.Message}");
            }

            return new TelegramProxyConfig
            {
                Host = Host,
                Port = Port,
                Secret = GenerateSecret(),
                DcIp = new List<string> { "2:149.154.167.220", "4:149.154.167.220" },
                Verbose = false,
                CheckUpdates = false,
                LogMaxMb = 5,
                BufKb = 256,
                PoolSize = 4,
                CfProxy = true,
                CfProxyUserDomain = new List<string>(),
                CfProxyWorkerDomain = new List<string>(),
                WsKeepaliveInterval = 30,
                Language = "ru",
                Autostart = false
            };
        }

        private string BuildCoreArguments(string secret)
        {
            string logFile = Path.Combine(_logsPath, "telegram_ws_proxy.log");

            return
                $"--host {Host} " +
                $"--port {Port} " +
                $"--secret {secret} " +
                "--dc-ip 2:149.154.167.220 " +
                "--dc-ip 4:149.154.167.220 " +
                $"--log-file \"{logFile}\"";
        }

        private static bool IsTrayExecutable(string path)
        {
            string fileName = Path.GetFileName(path);
            return fileName.StartsWith("TgWsProxy_windows", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildTelegramProxyLink(string secret)
        {
            return $"tg://proxy?server={Host}&port={Port}&secret=dd{secret}";
        }

        private static void OpenTelegramProxyLink(string link)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = link,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TG OPEN WARN] Не удалось открыть tg://proxy ссылку: {ex.Message}");
            }
        }

        private async Task<bool> WaitForPortAsync(string host, int port, TimeSpan timeout)
        {
            using CancellationTokenSource cts = new CancellationTokenSource(timeout);

            while (!cts.IsCancellationRequested)
            {
                try
                {
                    using TcpClient client = new TcpClient();
                    await client.ConnectAsync(host, port, cts.Token);
                    return true;
                }
                catch
                {
                    await Task.Delay(250);
                }
            }

            return false;
        }

        private Process? FindRunningManagedProcess()
        {
            return FindManagedProcesses().FirstOrDefault();
        }

        private IEnumerable<Process> FindManagedProcesses()
        {
            foreach (Process process in Process.GetProcesses())
            {
                string name = process.ProcessName;

                if (!name.Contains("TgWsProxy", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("tg-ws-proxy", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string? processPath = TryGetProcessPath(process);

                if (processPath != null && processPath.StartsWith(_tgwsPath, StringComparison.OrdinalIgnoreCase))
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

        private static void KillProcess(Process? process)
        {
            if (process == null || process.HasExited)
                return;

            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TG KILL WARN] PID {process.Id}: {ex.Message}");
            }
        }

        private static string GenerateSecret()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        }

        private static bool IsValidHexSecret(string secret)
        {
            if (secret.Length != 32)
                return false;

            return secret.All(c =>
                c is >= '0' and <= '9' ||
                c is >= 'a' and <= 'f' ||
                c is >= 'A' and <= 'F'
            );
        }
    }

    public sealed class TelegramProxyConfig
    {
        [JsonPropertyName("port")]
        public int Port { get; set; } = 1443;

        [JsonPropertyName("host")]
        public string Host { get; set; } = "127.0.0.1";

        [JsonPropertyName("dc_ip")]
        public List<string> DcIp { get; set; } = new List<string> { "2:149.154.167.220", "4:149.154.167.220" };

        [JsonPropertyName("verbose")]
        public bool Verbose { get; set; }

        [JsonPropertyName("check_updates")]
        public bool CheckUpdates { get; set; } = false;

        [JsonPropertyName("log_max_mb")]
        public int LogMaxMb { get; set; } = 5;

        [JsonPropertyName("buf_kb")]
        public int BufKb { get; set; } = 256;

        [JsonPropertyName("pool_size")]
        public int PoolSize { get; set; } = 4;

        [JsonPropertyName("cfproxy")]
        public bool CfProxy { get; set; } = true;

        [JsonPropertyName("cfproxy_user_domain")]
        public List<string> CfProxyUserDomain { get; set; } = new List<string>();

        [JsonPropertyName("cfproxy_worker_domain")]
        public List<string> CfProxyWorkerDomain { get; set; } = new List<string>();

        [JsonPropertyName("ws_keepalive_interval")]
        public int WsKeepaliveInterval { get; set; } = 30;

        [JsonPropertyName("secret")]
        public string Secret { get; set; } = string.Empty;

        [JsonPropertyName("language")]
        public string Language { get; set; } = "ru";

        [JsonPropertyName("autostart")]
        public bool Autostart { get; set; }
    }
}
