using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay;

public sealed class XrayClientManager : IDisposable
{
    private Process? _process;
    private Process? _bridgeProcess;
    private string? _statePath;
    private string? _clientExePath;
    private string? _configPath;
    private string? _legacyConfigPath;
    private TaskCompletionSource<int>? _bridgeReady;

    private static readonly string PrivateRuntimeDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SerpiumVPN",
        "Runtime",
        "Xray");

    private static readonly string PrivateRuntimeConfigPath = Path.Combine(
        PrivateRuntimeDirectory,
        "key-client.json");

    public XrayClientManager()
    {
        CleanupKnownStaleConfigFiles();
    }

    public RelayGatewayState State { get; private set; } =
        RelayGatewayState.Stopped;

    public string? LastError { get; private set; }
    public bool IsRunning => _process is { HasExited: false };
    public bool HasLiveProcess =>
        IsRunning ||
        _bridgeProcess is { HasExited: false } ||
        TryGetStoredOwnedProcess(out _) ||
        SerpiumNetClientConfig.HasLiveBridgeProcess();

    public event Action<string>? LogReceived;
    public event Action<RelayGatewayState>? StateChanged;

    public async Task StartAsync(
        string sourceXrayPath,
        string configPath,
        RelayKey key,
        int socksPort,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (HasLiveProcess)
            throw new InvalidOperationException("Relay-клиент уже подключён.");

        if (!File.Exists(sourceXrayPath))
        {
            throw new FileNotFoundException(
                "xray.exe не найден. Положите его в bin_files\\relay\\xray.exe.",
                sourceXrayPath);
        }

        _legacyConfigPath = Path.GetFullPath(configPath);
        _configPath = PrivateRuntimeConfigPath;
        EnsurePrivateRuntimeDirectory();
        CleanupKnownStaleConfigFiles(_legacyConfigPath);

        string relayDirectory =
            Directory.GetParent(Path.GetDirectoryName(configPath)!)?.FullName
            ?? throw new InvalidOperationException("Не удалось определить папку Relay.");

        string clientDirectory = Path.Combine(relayDirectory, "client");
        Directory.CreateDirectory(clientDirectory);

        _clientExePath = Path.Combine(clientDirectory, "xray-client.exe");
        _statePath = Path.Combine(relayDirectory, "state", "client-process.json");

        SetState(RelayGatewayState.Starting);
        LastError = null;

        try
        {
            await StopStoredOwnedProcessAsync(cancellationToken);
            await StopStoredBridgeProcessAsync(cancellationToken);
            await StopOrphanedClientAsync(_clientExePath, cancellationToken);

            if (IsPortListening(socksPort))
            {
                throw new InvalidOperationException(
                    $"SOCKS-порт {socksPort} уже занят. Выберите другой локальный порт.");
            }

            RelayKey effectiveKey = key;
            if (UsesSerpiumNetTransport(key.Transport))
            {
                int bridgePort = await StartSerpiumNetBridgeAsync(key, cancellationToken);
                effectiveKey = CloneForLocalBridge(key, bridgePort);
                LogReceived?.Invoke(
                    $"SerpiumNet headless: {key.Host}:{key.Port} → 127.0.0.1:{bridgePort}");
            }

            File.Copy(sourceXrayPath, _clientExePath, overwrite: true);

            string configDirectory = Path.GetDirectoryName(_configPath)!;
            string logDirectory = Path.Combine(relayDirectory, "logs", "client");

            Directory.CreateDirectory(configDirectory);
            Directory.CreateDirectory(logDirectory);
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);

            string json = XrayClientConfigBuilder.Build(
                effectiveKey,
                socksPort,
                logDirectory);

            await WriteSensitiveConfigAsync(
                _configPath,
                json,
                cancellationToken);

            ProcessStartInfo startInfo = new()
            {
                FileName = _clientExePath,
                WorkingDirectory = clientDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("-config");
            startInfo.ArgumentList.Add(_configPath);

            _process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            _process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    LogReceived?.Invoke(e.Data);
            };
            _process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    LogReceived?.Invoke(e.Data);
            };
            _process.Exited += (_, _) =>
            {
                DeleteStateFile();
                DeleteRuntimeConfig();

                if (State is RelayGatewayState.Stopping or RelayGatewayState.Stopped)
                    return;

                LastError = $"Xray-клиент завершился. Код: {_process?.ExitCode}";
                SetState(RelayGatewayState.Failed);
                _ = StopBridgeOnlyAsync(CancellationToken.None);
            };

            if (!_process.Start())
                throw new InvalidOperationException("Не удалось запустить Xray-клиент.");

            SaveState(_process.Id, socksPort, _clientExePath);
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();

            await WaitForPortAsync(
                "127.0.0.1",
                socksPort,
                TimeSpan.FromSeconds(8),
                cancellationToken);

            if (_process.HasExited)
            {
                throw new InvalidOperationException(
                    $"Xray-клиент завершился с кодом {_process.ExitCode} " +
                    "до открытия SOCKS-порта.");
            }

            // Xray reads its configuration during startup. Remove the plaintext
            // file as soon as the local SOCKS listener proves that startup
            // completed. The in-memory process keeps the parsed configuration.
            DeleteRuntimeConfig();

            SetState(RelayGatewayState.Running);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            TryKillProcess();
            await StopBridgeOnlyAsync(CancellationToken.None);
            DeleteStateFile();
            DeleteRuntimeConfig();
            SetState(RelayGatewayState.Failed);
            throw;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        SetState(RelayGatewayState.Stopping);

        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync(cancellationToken);
            }
            else
            {
                await StopStoredOwnedProcessAsync(cancellationToken);
            }

            await StopBridgeOnlyAsync(cancellationToken);
        }
        finally
        {
            _process?.Dispose();
            _process = null;
            DeleteStateFile();
            DeleteRuntimeConfig();
            SerpiumNetClientConfig.DeleteBridgeRuntime();
            SetState(RelayGatewayState.Stopped);
        }
    }

    private async Task<int> StartSerpiumNetBridgeAsync(
        RelayKey key,
        CancellationToken cancellationToken)
    {
        SerpiumNetClientEnrollment enrollment =
            SerpiumNetClientConfig.ResolveEnrollment();

        string remote = FormatHostPort(key.Host, key.Port);
        string hostname = "serpium-client-" + SanitizeHostname(Environment.MachineName);

        _bridgeReady = new TaskCompletionSource<int>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        ProcessStartInfo info = new()
        {
            FileName = enrollment.BinaryPath,
            WorkingDirectory = Path.GetDirectoryName(enrollment.BinaryPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        info.ArgumentList.Add("client");
        info.ArgumentList.Add("-hostname");
        info.ArgumentList.Add(hostname);
        info.ArgumentList.Add("-state-dir");
        info.ArgumentList.Add(enrollment.StateDirectory);
        info.ArgumentList.Add("-listen");
        info.ArgumentList.Add("127.0.0.1:0");
        info.ArgumentList.Add("-remote");
        info.ArgumentList.Add(remote);
        info.ArgumentList.Add("-control-url");
        info.ArgumentList.Add(enrollment.ControlUrl);

        if (!string.IsNullOrWhiteSpace(enrollment.AuthKey))
        {
            info.ArgumentList.Add("-auth-key");
            info.ArgumentList.Add(enrollment.AuthKey);
        }

        _bridgeProcess = new Process
        {
            StartInfo = info,
            EnableRaisingEvents = true
        };

        _bridgeProcess.OutputDataReceived += (_, e) =>
        {
            if (string.IsNullOrWhiteSpace(e.Data))
                return;

            HandleBridgeOutput(e.Data);
        };

        _bridgeProcess.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
                LogReceived?.Invoke("[SerpiumNet] " + RedactSensitiveLine(e.Data));
        };

        _bridgeProcess.Exited += (_, _) =>
        {
            if (_bridgeReady is { Task.IsCompleted: false })
            {
                int code = -1;
                try { code = _bridgeProcess?.ExitCode ?? -1; } catch { }
                _bridgeReady.TrySetException(
                    new InvalidOperationException(
                        $"SerpiumNet client bridge завершился до готовности. Код: {code}."));
            }
        };

        if (!_bridgeProcess.Start())
            throw new InvalidOperationException("Не удалось запустить встроенный SerpiumNet client bridge.");

        _bridgeProcess.BeginOutputReadLine();
        _bridgeProcess.BeginErrorReadLine();

        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));

        int localPort;
        try
        {
            localPort = await _bridgeReady.Task.WaitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "SerpiumNet не подключился к Headscale и не открыл локальный bridge за 45 секунд.");
        }

        SerpiumNetClientConfig.WriteBridgeRuntime(new SerpiumNetBridgeRuntime
        {
            ProcessId = _bridgeProcess.Id,
            ExecutablePath = enrollment.BinaryPath,
            RemoteHost = key.Host,
            RemotePort = key.Port,
            LocalPort = localPort,
            StartedAtUtc = DateTime.UtcNow
        });

        if (!enrollment.HasPersistentState && !string.IsNullOrWhiteSpace(enrollment.AuthKey))
            SerpiumNetClientConfig.DeleteConsumedAuthKeyFile();

        return localPort;
    }

    private void HandleBridgeOutput(string line)
    {
        string safeLine = RedactSensitiveLine(line);
        LogReceived?.Invoke("[SerpiumNet] " + safeLine);

        const string readyPrefix = "CLIENT_BRIDGE_READY=";
        if (!line.StartsWith(readyPrefix, StringComparison.Ordinal))
            return;

        string endpointText = line[readyPrefix.Length..].Trim();
        if (!TryParsePort(endpointText, out int port))
        {
            _bridgeReady?.TrySetException(
                new InvalidOperationException(
                    "SerpiumNet вернул некорректный адрес локального bridge: " + endpointText));
            return;
        }

        _bridgeReady?.TrySetResult(port);
    }

    private async Task StopBridgeOnlyAsync(CancellationToken cancellationToken)
    {
        Process? process = _bridgeProcess;
        _bridgeProcess = null;

        try
        {
            if (process is { HasExited: false })
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(cancellationToken);
            }
            else
            {
                await StopStoredBridgeProcessAsync(cancellationToken);
            }
        }
        catch (InvalidOperationException)
        {
            // The process exited between checks.
        }
        finally
        {
            process?.Dispose();
            _bridgeReady = null;
            SerpiumNetClientConfig.DeleteBridgeRuntime();
        }
    }

    private static async Task StopStoredBridgeProcessAsync(
        CancellationToken cancellationToken)
    {
        if (!SerpiumNetClientConfig.TryReadBridgeRuntime(
                out SerpiumNetBridgeRuntime? state) || state is null)
        {
            SerpiumNetClientConfig.DeleteBridgeRuntime();
            return;
        }

        try
        {
            using Process process = Process.GetProcessById(state.ProcessId);
            if (process.HasExited)
                return;

            string? actualPath = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(actualPath) ||
                !Path.GetFullPath(actualPath).Equals(
                    Path.GetFullPath(state.ExecutablePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (ArgumentException)
        {
            // Process no longer exists.
        }
        catch (InvalidOperationException)
        {
            // Process already exited.
        }
        finally
        {
            SerpiumNetClientConfig.DeleteBridgeRuntime();
        }
    }

    private static bool UsesSerpiumNetTransport(string? transport) =>
        string.Equals(transport, "tailscale", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(transport, "headscale", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(transport, "serpiumnet", StringComparison.OrdinalIgnoreCase);

    private static RelayKey CloneForLocalBridge(RelayKey source, int localPort) => new()
    {
        Schema = source.Schema,
        Name = source.Name,
        Transport = "serpiumnet-headless",
        Protocol = source.Protocol,
        Host = "127.0.0.1",
        Port = localPort,
        Uuid = source.Uuid,
        Network = source.Network
    };

    private static string FormatHostPort(string host, int port)
    {
        if (IPAddress.TryParse(host, out IPAddress? address) &&
            address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return $"[{host}]:{port}";
        }

        return $"{host}:{port}";
    }

    private static string SanitizeHostname(string value)
    {
        string result = new(value
            .ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) || c == '-' ? c : '-')
            .ToArray());

        result = result.Trim('-');
        return string.IsNullOrWhiteSpace(result) ? "windows" : result;
    }

    private static bool TryParsePort(string endpoint, out int port)
    {
        port = 0;
        int separator = endpoint.LastIndexOf(':');
        return separator >= 0 &&
               int.TryParse(endpoint[(separator + 1)..], out port) &&
               port is > 0 and <= 65535;
    }

    private static string RedactSensitiveLine(string line)
    {
        int index = line.IndexOf("https://login.tailscale.com/", StringComparison.OrdinalIgnoreCase);
        return index < 0
            ? line
            : line[..index] + "<interactive-login-url-blocked>";
    }

    private static async Task StopOrphanedClientAsync(
        string expectedExecutablePath,
        CancellationToken cancellationToken)
    {
        string expectedFullPath = Path.GetFullPath(expectedExecutablePath);
        string processName = Path.GetFileNameWithoutExtension(expectedFullPath);

        foreach (Process candidate in Process.GetProcessesByName(processName))
        {
            using (candidate)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    if (candidate.HasExited)
                        continue;

                    string? actualPath = candidate.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(actualPath))
                        continue;

                    if (!Path.GetFullPath(actualPath).Equals(
                            expectedFullPath,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    candidate.Kill(entireProcessTree: true);
                    await candidate.WaitForExitAsync(cancellationToken);
                }
                catch (InvalidOperationException)
                {
                    // Process exited independently.
                }
            }
        }
    }

    private async Task<bool> StopStoredOwnedProcessAsync(
        CancellationToken cancellationToken)
    {
        if (!TryGetStoredOwnedProcess(out Process? process) || process is null)
        {
            DeleteStateFile();
            return false;
        }

        using (process)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(cancellationToken);
                return true;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            finally
            {
                DeleteStateFile();
            }
        }
    }

    private bool TryGetStoredOwnedProcess(out Process? process)
    {
        process = null;

        if (string.IsNullOrWhiteSpace(_statePath) || !File.Exists(_statePath))
            return false;

        try
        {
            ClientProcessState? state =
                JsonSerializer.Deserialize<ClientProcessState>(
                    File.ReadAllText(_statePath));

            if (state is null || state.Pid <= 0)
                return false;

            Process candidate = Process.GetProcessById(state.Pid);
            if (candidate.HasExited)
            {
                candidate.Dispose();
                return false;
            }

            string? actualPath = candidate.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(actualPath) ||
                !Path.GetFullPath(actualPath).Equals(
                    Path.GetFullPath(state.ExecutablePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                candidate.Dispose();
                return false;
            }

            process = candidate;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void EnsurePrivateRuntimeDirectory()
    {
        Directory.CreateDirectory(PrivateRuntimeDirectory);

        try
        {
            File.SetAttributes(
                PrivateRuntimeDirectory,
                File.GetAttributes(PrivateRuntimeDirectory) |
                FileAttributes.Hidden |
                FileAttributes.NotContentIndexed);
        }
        catch
        {
            // LocalAppData already inherits the current user's private ACL.
            // Attributes are only additional hygiene and must not block startup.
        }
    }

    private static async Task WriteSensitiveConfigAsync(
        string path,
        string content,
        CancellationToken cancellationToken)
    {
        EnsurePrivateRuntimeDirectory();
        BestEffortDeleteSensitiveFile(path);

        await File.WriteAllTextAsync(
            path,
            content,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            cancellationToken);

        try
        {
            File.SetAttributes(
                path,
                File.GetAttributes(path) |
                FileAttributes.Hidden |
                FileAttributes.NotContentIndexed);
        }
        catch
        {
            // File attributes are not a cryptographic boundary.
        }
    }

    private void DeleteRuntimeConfig()
    {
        CleanupKnownStaleConfigFiles(_configPath);
        CleanupKnownStaleConfigFiles(_legacyConfigPath);
    }

    private static void CleanupKnownStaleConfigFiles(
        string? additionalPath = null)
    {
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase)
        {
            PrivateRuntimeConfigPath,
            Path.Combine(
                AppContext.BaseDirectory,
                "bin_files",
                "relay",
                "configs",
                "key-client.json"),
            Path.Combine(
                AppContext.BaseDirectory,
                "bin_files",
                "relay",
                "configs",
                "client.json")
        };

        if (!string.IsNullOrWhiteSpace(additionalPath))
        {
            try
            {
                paths.Add(Path.GetFullPath(additionalPath));
            }
            catch
            {
                // Ignore malformed stale paths; normal validation handles the
                // active path before it is used.
            }
        }

        foreach (string path in paths)
            BestEffortDeleteSensitiveFile(path);
    }

    private static void BestEffortDeleteSensitiveFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        try
        {
            if (!File.Exists(path))
                return;

            try
            {
                using FileStream stream = new(
                    path,
                    FileMode.Open,
                    FileAccess.Write,
                    FileShare.None);

                long remaining = stream.Length;
                byte[] zeroBuffer = new byte[16 * 1024];
                stream.Position = 0;

                while (remaining > 0)
                {
                    int count = (int)Math.Min(zeroBuffer.Length, remaining);
                    stream.Write(zeroBuffer, 0, count);
                    remaining -= count;
                }

                stream.Flush(flushToDisk: true);
                Array.Clear(zeroBuffer, 0, zeroBuffer.Length);
            }
            catch
            {
                // Secure overwrite is best-effort. Deletion is still required.
            }

            File.Delete(path);
        }
        catch
        {
            // Runtime cleanup must not block disconnect or application exit.
        }
    }

    private void SaveState(int pid, int socksPort, string executablePath)
    {
        if (string.IsNullOrWhiteSpace(_statePath))
            return;

        ClientProcessState state = new()
        {
            Pid = pid,
            SocksPort = socksPort,
            ExecutablePath = executablePath,
            StartedAtUtc = DateTime.UtcNow
        };

        File.WriteAllText(
            _statePath,
            JsonSerializer.Serialize(
                state,
                new JsonSerializerOptions { WriteIndented = true }));
    }

    private void DeleteStateFile()
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(_statePath) && File.Exists(_statePath))
                File.Delete(_statePath);
        }
        catch
        {
            // Service metadata must not block disconnect.
        }
    }

    private static bool IsPortListening(int port) =>
        IPGlobalProperties.GetIPGlobalProperties()
            .GetActiveTcpListeners()
            .Any(endpoint => endpoint.Port == port);

    private static async Task WaitForPortAsync(
        string host,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        Exception? last = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using TcpClient client = new();
                using CancellationTokenSource attempt =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                attempt.CancelAfter(TimeSpan.FromMilliseconds(700));

                await client.ConnectAsync(host, port, attempt.Token);
                return;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                last = ex;
                await Task.Delay(250, cancellationToken);
            }
        }

        throw new TimeoutException(
            $"Xray-клиент запущен, но SOCKS-порт {host}:{port} " +
            $"не открылся за {timeout.TotalSeconds:0} с.",
            last);
    }

    private void TryKillProcess()
    {
        try
        {
            if (_process is { HasExited: false })
                _process.Kill(entireProcessTree: true);
        }
        catch
        {
        }
        finally
        {
            _process?.Dispose();
            _process = null;
        }
    }

    private void SetState(RelayGatewayState state)
    {
        State = state;
        StateChanged?.Invoke(state);
    }

    public void Dispose()
    {
        TryKillProcess();

        try
        {
            if (_bridgeProcess is { HasExited: false })
                _bridgeProcess.Kill(entireProcessTree: true);
        }
        catch
        {
        }
        finally
        {
            _bridgeProcess?.Dispose();
            _bridgeProcess = null;
        }

        DeleteStateFile();
        DeleteRuntimeConfig();
        SerpiumNetClientConfig.DeleteBridgeRuntime();
        GC.SuppressFinalize(this);
    }

    private sealed class ClientProcessState
    {
        public int Pid { get; set; }
        public int SocksPort { get; set; }
        public string ExecutablePath { get; set; } = string.Empty;
        public DateTime StartedAtUtc { get; set; }
    }
}
