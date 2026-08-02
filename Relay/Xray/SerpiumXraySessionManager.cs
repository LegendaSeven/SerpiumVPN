using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using SerpiumVPN.Relay.Parser;
using System.IO;

namespace SerpiumVPN.Relay.Xray;

public sealed class SerpiumXraySessionManager : IDisposable
{
    private Process? _process;
    private string? _sessionExePath;
    private string? _configPath;
    private string? _statePath;
    private bool _disposed;

    public RelayGatewayState State { get; private set; } = RelayGatewayState.Stopped;
    public bool IsRunning => _process is { HasExited: false };
    public bool HasLiveProcess => IsRunning || TryGetStoredOwnedProcess(out _);
    public string? LastError { get; private set; }

    public event Action<string>? LogReceived;
    public event Action<RelayGatewayState>? StateChanged;

    public async Task StartAsync(
        string sourceXrayPath,
        string configPath,
        SerpiumConnectionProfile profile,
        int socksPort,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(profile);

        if (HasLiveProcess)
            throw new InvalidOperationException("Подключение по ключу уже запущено.");
        if (!File.Exists(sourceXrayPath))
        {
            throw new FileNotFoundException(
                "xray.exe не найден. Положите его в bin_files\\relay\\xray.exe.",
                sourceXrayPath);
        }
        if (socksPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(socksPort));

        string relayDirectory =
            Directory.GetParent(Path.GetDirectoryName(configPath)!)?.FullName
            ?? throw new InvalidOperationException("Не удалось определить папку Relay.");
        string sessionDirectory = Path.Combine(relayDirectory, "key-client");
        string logDirectory = Path.Combine(relayDirectory, "logs", "key-client");

        _sessionExePath = Path.Combine(sessionDirectory, "xray-key-client.exe");
        _configPath = configPath;
        _statePath = Path.Combine(relayDirectory, "state", "key-client-process.json");

        Directory.CreateDirectory(sessionDirectory);
        Directory.CreateDirectory(logDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);

        SetState(RelayGatewayState.Starting);
        LastError = null;

        try
        {
            await StopStoredOwnedProcessAsync(cancellationToken);
            await StopOrphanByPathAsync(_sessionExePath, cancellationToken);

            if (IsPortListening(socksPort))
            {
                throw new InvalidOperationException(
                    $"SOCKS5-порт {socksPort} уже занят. Остановите процесс, использующий этот порт.");
            }

            File.Copy(sourceXrayPath, _sessionExePath, overwrite: true);
            string json = SerpiumXrayConfigBuilder.Build(profile, socksPort, logDirectory);
            await File.WriteAllTextAsync(configPath, json, cancellationToken);

            ProcessStartInfo startInfo = new()
            {
                FileName = _sessionExePath,
                WorkingDirectory = sessionDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("-config");
            startInfo.ArgumentList.Add(configPath);

            _process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };
            _process.OutputDataReceived += (_, e) => ForwardLog(e.Data);
            _process.ErrorDataReceived += (_, e) => ForwardLog(e.Data);
            _process.Exited += (_, _) => HandleUnexpectedExit();

            if (!_process.Start())
                throw new InvalidOperationException("Не удалось запустить Xray.");

            SaveState(_process);
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();

            await WaitForPortAsync(
                IPAddress.Loopback,
                socksPort,
                TimeSpan.FromSeconds(10),
                cancellationToken);

            if (_process.HasExited)
            {
                throw new InvalidOperationException(
                    $"Xray завершился с кодом {_process.ExitCode} до открытия SOCKS5-порта.");
            }

            await VerifySocksTunnelAsync(socksPort, cancellationToken);

            LogReceived?.Invoke(
                $"Serpium Parser: {profile.Protocol.ToUpperInvariant()} · " +
                $"{profile.Transport.ToUpperInvariant()} · {profile.Security.ToUpperInvariant()}");
            LogReceived?.Invoke($"SOCKS5 готов: 127.0.0.1:{socksPort}");
            SetState(RelayGatewayState.Running);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            TryKillCurrentProcess();
            DeleteSensitiveRuntimeFiles();
            SetState(RelayGatewayState.Failed);
            throw;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
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
            DeleteSensitiveRuntimeFiles();
            SetState(RelayGatewayState.Stopped);
        }
    }

    private void ForwardLog(string? line)
    {
        if (!string.IsNullOrWhiteSpace(line))
            LogReceived?.Invoke(line);
    }

    private void HandleUnexpectedExit()
    {
        DeleteStateFile();
        DeleteConfigFile();

        if (State is RelayGatewayState.Stopping or RelayGatewayState.Stopped)
            return;

        try
        {
            LastError = $"Xray неожиданно завершился. Код: {_process?.ExitCode}.";
        }
        catch
        {
            LastError = "Xray неожиданно завершился.";
        }

        SetState(RelayGatewayState.Failed);
    }

    private void SaveState(Process process)
    {
        if (string.IsNullOrWhiteSpace(_statePath) || string.IsNullOrWhiteSpace(_sessionExePath))
            return;

        SessionProcessState state = new()
        {
            ProcessId = process.Id,
            ExecutablePath = _sessionExePath,
            StartedAtUtc = process.StartTime.ToUniversalTime()
        };

        File.WriteAllText(
            _statePath,
            JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
    }

    private bool TryGetStoredOwnedProcess(out Process? process)
    {
        process = null;
        if (string.IsNullOrWhiteSpace(_statePath) || !File.Exists(_statePath))
            return false;

        try
        {
            SessionProcessState? state = JsonSerializer.Deserialize<SessionProcessState>(
                File.ReadAllText(_statePath));
            if (state is null || state.ProcessId <= 0 || string.IsNullOrWhiteSpace(state.ExecutablePath))
                return false;

            Process candidate = Process.GetProcessById(state.ProcessId);
            if (candidate.HasExited || !IsSameProcess(candidate, state))
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

    private async Task StopStoredOwnedProcessAsync(CancellationToken cancellationToken)
    {
        if (!TryGetStoredOwnedProcess(out Process? process) || process is null)
        {
            DeleteStateFile();
            return;
        }

        using (process)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(cancellationToken);
            }
            catch { }
        }

        DeleteStateFile();
    }

    private static async Task StopOrphanByPathAsync(
        string executablePath,
        CancellationToken cancellationToken)
    {
        string processName = Path.GetFileNameWithoutExtension(executablePath);
        foreach (Process process in Process.GetProcessesByName(processName))
        {
            using (process)
            {
                try
                {
                    string? actualPath = process.MainModule?.FileName;
                    if (!string.Equals(
                            Path.GetFullPath(actualPath ?? string.Empty),
                            Path.GetFullPath(executablePath),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync(cancellationToken);
                }
                catch { }
            }
        }
    }

    private static bool IsSameProcess(Process process, SessionProcessState state)
    {
        try
        {
            string? actualPath = process.MainModule?.FileName;
            bool pathMatches = string.Equals(
                Path.GetFullPath(actualPath ?? string.Empty),
                Path.GetFullPath(state.ExecutablePath),
                StringComparison.OrdinalIgnoreCase);
            bool startMatches = Math.Abs(
                (process.StartTime.ToUniversalTime() - state.StartedAtUtc).TotalSeconds) < 3;
            return pathMatches && startMatches;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsPortListening(int port)
    {
        try
        {
            TcpListener listener = new(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return false;
        }
        catch (SocketException)
        {
            return true;
        }
    }

    private static async Task VerifySocksTunnelAsync(
        int socksPort,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));

        using TcpClient client = new();
        await client.ConnectAsync(IPAddress.Loopback, socksPort, timeout.Token);
        await using NetworkStream stream = client.GetStream();

        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }.AsMemory(), timeout.Token);
        byte[] hello = new byte[2];
        await ReadExactlyAsync(stream, hello, timeout.Token);
        if (hello[0] != 0x05 || hello[1] != 0x00)
            throw new InvalidOperationException("Локальный SOCKS5 отклонил соединение без авторизации.");

        const string probeHost = "www.cloudflare.com";
        byte[] hostBytes = System.Text.Encoding.ASCII.GetBytes(probeHost);
        byte[] request = new byte[7 + hostBytes.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x03;
        request[4] = (byte)hostBytes.Length;
        Buffer.BlockCopy(hostBytes, 0, request, 5, hostBytes.Length);
        request[^2] = 0x01;
        request[^1] = 0xBB; // 443

        await stream.WriteAsync(request.AsMemory(), timeout.Token);
        byte[] responseHead = new byte[4];
        await ReadExactlyAsync(stream, responseHead, timeout.Token);
        if (responseHead[0] != 0x05 || responseHead[1] != 0x00)
        {
            throw new InvalidOperationException(
                $"VPN-ключ не прошёл тестовый запрос через SOCKS5 (код {responseHead[1]}).");
        }

        int addressLength = responseHead[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => await ReadDomainLengthAsync(stream, timeout.Token),
            _ => throw new InvalidOperationException("SOCKS5 вернул неизвестный тип адреса.")
        };

        byte[] tail = new byte[addressLength + 2];
        await ReadExactlyAsync(stream, tail, timeout.Token);
    }

    private static async Task<int> ReadDomainLengthAsync(
        NetworkStream stream,
        CancellationToken cancellationToken)
    {
        byte[] length = new byte[1];
        await ReadExactlyAsync(stream, length, cancellationToken);
        return length[0];
    }

    private static async Task ReadExactlyAsync(
        NetworkStream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(
                buffer.AsMemory(offset, buffer.Length - offset),
                cancellationToken);
            if (read == 0)
                throw new IOException("SOCKS5 закрыл соединение во время проверки.");
            offset += read;
        }
    }

    private static async Task WaitForPortAsync(
        IPAddress address,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using TcpClient client = new();
            try
            {
                await client.ConnectAsync(address, port, cancellationToken);
                return;
            }
            catch (SocketException)
            {
                await Task.Delay(150, cancellationToken);
            }
        }

        throw new TimeoutException(
            $"Xray не открыл локальный SOCKS5-порт {port} за {timeout.TotalSeconds:0} секунд.");
    }

    private void TryKillCurrentProcess()
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

    private void DeleteSensitiveRuntimeFiles()
    {
        DeleteStateFile();
        DeleteConfigFile();
    }

    private void DeleteStateFile()
    {
        DeleteFileWithRetry(_statePath);
    }

    private void DeleteConfigFile()
    {
        DeleteFileWithRetry(_configPath);
    }

    private static void DeleteFileWithRetry(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        for (int attempt = 0; attempt < 6; attempt++)
        {
            try
            {
                if (!File.Exists(path))
                    return;

                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);

                if (!File.Exists(path))
                    return;
            }
            catch (IOException)
            {
                // Exited/stop handlers may briefly race on the same file.
            }
            catch (UnauthorizedAccessException)
            {
                // Retry after the process releases its final handles.
            }

            if (attempt < 5)
                Thread.Sleep(80);
        }
    }

    private void SetState(RelayGatewayState state)
    {
        State = state;
        StateChanged?.Invoke(state);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        try
        {
            if (HasLiveProcess)
                StopAsync().GetAwaiter().GetResult();
        }
        catch { }

        _disposed = true;
        _process?.Dispose();
        _process = null;
    }

    private sealed class SessionProcessState
    {
        public int ProcessId { get; init; }
        public string ExecutablePath { get; init; } = string.Empty;
        public DateTime StartedAtUtc { get; init; }
    }
}
