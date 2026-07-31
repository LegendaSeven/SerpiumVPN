using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.IO;

namespace SerpiumVPN.Relay;

public sealed class XrayGatewayManager : IDisposable
{
    private Process? _process;
    private string? _statePath;
    private string? _xrayExePath;

    public RelayGatewayState State { get; private set; } = RelayGatewayState.Stopped;
    public string? LastError { get; private set; }
    public bool IsRunning => _process is { HasExited: false };
    public bool HasLiveProcess => IsRunning || TryGetStoredOwnedProcess(out _);


    public bool TryRecoverStoredProcess(out int port, out string address)
    {
        port = 0;
        address = string.Empty;

        if (string.IsNullOrWhiteSpace(_statePath))
        {
            string baseDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
            string relayDir = Path.Combine(baseDir, "bin_files", "relay");
            _statePath = Path.Combine(relayDir, "state", "gateway-process.json");
        }

        GatewayProcessState? state = ReadStoredState();
        if (state is null)
            return false;

        if (!TryGetStoredOwnedProcess(out Process? process) || process is null)
            return false;

        process.Dispose();
        port = state.Port;
        address = state.Address;
        SetState(RelayGatewayState.Running);
        return true;
    }

    public event Action<string>? LogReceived;
    public event Action<RelayGatewayState>? StateChanged;

    public async Task StartAsync(
        string xrayExePath,
        string configPath,
        string listenAddress,
        int port,
        string uuid,
        CancellationToken cancellationToken = default)
    {
        if (IsRunning)
            throw new InvalidOperationException("Xray-шлюз уже запущен.");
        if (!File.Exists(xrayExePath))
            throw new FileNotFoundException(
                "xray.exe не найден. Положите его в bin_files\\relay\\xray.exe.", xrayExePath);

        _xrayExePath = Path.GetFullPath(xrayExePath);
        string configDirectory = Path.GetDirectoryName(configPath)
            ?? throw new InvalidOperationException("Не удалось определить папку конфигурации.");
        string relayDirectory = Directory.GetParent(configDirectory)?.FullName ?? configDirectory;
        _statePath = Path.Combine(relayDirectory, "state", "gateway-process.json");

        SetState(RelayGatewayState.Starting);
        LastError = null;

        try
        {
            // Clean/Rebuild может удалить PID-файл, оставив встроенный xray.exe живым.
            bool orphanStopped = await StopOrphanedEmbeddedXrayAsync(_xrayExePath, cancellationToken);
            if (orphanStopped)
            {
                await WaitForPortReleaseAsync(port, TimeSpan.FromSeconds(5), cancellationToken);
                LogReceived?.Invoke($"Зависший встроенный Xray остановлен; порт {port} освобождён.");
            }

            // После аварийного закрытия Serpium старый Xray может остаться жить.
            // Завершаем только процесс, PID и путь которого ранее сохранил сам Serpium.
            bool staleProcessStopped = await StopStoredOwnedProcessAsync(cancellationToken);
            if (staleProcessStopped)
            {
                await WaitForPortReleaseAsync(port, TimeSpan.FromSeconds(5), cancellationToken);
                LogReceived?.Invoke($"Старый экземпляр Xray остановлен; порт {port} освобождён.");
            }

            if (IsPortListening(port))
            {
                throw new InvalidOperationException(
                    $"Порт {port} уже занят другим процессом.\n\n" +
                    "Выберите другой порт либо закройте программу, которая его использует.");
            }

            string logDirectory = Path.Combine(relayDirectory, "logs");
            Directory.CreateDirectory(configDirectory);
            Directory.CreateDirectory(logDirectory);
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);

            string json = XrayGatewayConfigBuilder.Build(listenAddress, port, uuid, logDirectory);
            await File.WriteAllTextAsync(configPath, json, cancellationToken);

            ProcessStartInfo startInfo = new()
            {
                FileName = _xrayExePath,
                WorkingDirectory = Path.GetDirectoryName(_xrayExePath)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("-config");
            startInfo.ArgumentList.Add(configPath);

            _process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
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
                if (State is RelayGatewayState.Stopping or RelayGatewayState.Stopped)
                    return;

                LastError = $"Xray завершился. Код: {_process?.ExitCode}";
                SetState(RelayGatewayState.Failed);
            };

            if (!_process.Start())
                throw new InvalidOperationException("Не удалось запустить xray.exe.");

            SaveProcessState(_process.Id, port, listenAddress, _xrayExePath);
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();

            await WaitForPortAsync("127.0.0.1", port, TimeSpan.FromSeconds(8), cancellationToken);

            if (_process.HasExited)
                throw new InvalidOperationException($"Xray завершился с кодом {_process.ExitCode} до открытия порта.");

            SetState(RelayGatewayState.Running);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            TryKillProcess();
            DeleteStateFile();
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
        }
        finally
        {
            _process?.Dispose();
            _process = null;
            DeleteStateFile();
            SetState(RelayGatewayState.Stopped);
        }
    }


    private static async Task<bool> StopOrphanedEmbeddedXrayAsync(
        string expectedExecutablePath,
        CancellationToken cancellationToken)
    {
        string expectedFullPath = Path.GetFullPath(expectedExecutablePath);
        bool stoppedAny = false;

        foreach (Process candidate in Process.GetProcessesByName("xray"))
        {
            using (candidate)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    if (candidate.HasExited)
                        continue;

                    string? actualPath = TryGetProcessPath(candidate);
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
                    stoppedAny = true;
                }
                catch (InvalidOperationException)
                {
                    // Process exited on its own.
                }
            }
        }

        return stoppedAny;
    }

    private async Task<bool> StopStoredOwnedProcessAsync(CancellationToken cancellationToken)
    {
        if (!TryGetStoredOwnedProcess(out Process? storedProcess) || storedProcess is null)
        {
            DeleteStateFile();
            return false;
        }

        using (storedProcess)
        {
            try
            {
                storedProcess.Kill(entireProcessTree: true);
                await storedProcess.WaitForExitAsync(cancellationToken);
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
            GatewayProcessState? state = JsonSerializer.Deserialize<GatewayProcessState>(
                File.ReadAllText(_statePath));
            if (state is null || state.Pid <= 0)
                return false;

            Process candidate = Process.GetProcessById(state.Pid);
            if (candidate.HasExited || !candidate.ProcessName.Equals("xray", StringComparison.OrdinalIgnoreCase))
            {
                candidate.Dispose();
                return false;
            }

            string? actualPath = TryGetProcessPath(candidate);
            if (!string.IsNullOrWhiteSpace(actualPath) &&
                !Path.GetFullPath(actualPath).Equals(Path.GetFullPath(state.ExecutablePath), StringComparison.OrdinalIgnoreCase))
            {
                candidate.Dispose();
                return false;
            }

            process = candidate;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or JsonException)
        {
            return false;
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


    private GatewayProcessState? ReadStoredState()
    {
        if (string.IsNullOrWhiteSpace(_statePath) || !File.Exists(_statePath))
            return null;

        try
        {
            return JsonSerializer.Deserialize<GatewayProcessState>(
                File.ReadAllText(_statePath));
        }
        catch
        {
            return null;
        }
    }

    private void SaveProcessState(int pid, int port, string address, string executablePath)
    {
        if (string.IsNullOrWhiteSpace(_statePath))
            return;

        GatewayProcessState state = new()
        {
            Pid = pid,
            Port = port,
            Address = address,
            ExecutablePath = executablePath,
            StartedAtUtc = DateTime.UtcNow
        };

        File.WriteAllText(_statePath, JsonSerializer.Serialize(state, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
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
            // Сбой удаления служебного файла не должен ломать остановку шлюза.
        }
    }

    private static bool IsPortListening(int port)
    {
        return IPGlobalProperties.GetIPGlobalProperties()
            .GetActiveTcpListeners()
            .Any(endpoint => endpoint.Port == port);
    }

    private static async Task WaitForPortReleaseAsync(
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsPortListening(port))
                return;

            await Task.Delay(150, cancellationToken);
        }

        throw new TimeoutException($"Порт {port} не освободился за {timeout.TotalSeconds:0} с.");
    }

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
                using CancellationTokenSource attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
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

        throw new TimeoutException($"Xray запущен, но порт {host}:{port} не открылся за {timeout.TotalSeconds:0} с.", last);
    }

    private void TryKillProcess()
    {
        try
        {
            if (_process is { HasExited: false })
                _process.Kill(entireProcessTree: true);
        }
        catch { }
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
        DeleteStateFile();
        GC.SuppressFinalize(this);
    }

    private sealed class GatewayProcessState
    {
        public int Pid { get; set; }
        public int Port { get; set; }
        public string Address { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public DateTime StartedAtUtc { get; set; }
    }
}
