using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using SerpiumVPN.Core;
using SerpiumVPN.Core.Interfaces;

namespace Serpium.SerpiumNet.Engine;

/// <summary>
/// External Serpium engine wrapper for the native SerpiumNet process.
/// MVP6.1.2 enforces headless Headscale enrollment and never opens a browser.
/// </summary>
public sealed class SerpiumNetEngine : IRelayGatewayEngine, IAsyncDisposable
{
    private const string DefaultControlUrl = "http://127.0.0.1:8080";
    private const string ControlUrlEnvironmentVariable = "SERPIUM_CONTROL_URL";
    private const string AuthKeyEnvironmentVariable = "SERPIUM_AUTH_KEY";
    private const string ControlUrlFileName = "headscale-control-url.txt";
    private const string AuthKeyFileName = "headscale-auth.key";
    private const string StateFileName = "tailscaled.state";

    private static readonly TimeSpan VersionProbeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ConnectionOutcomeTimeout = TimeSpan.FromSeconds(45);
    private static readonly Regex TailscaleLoginUrlRegex = new(
        @"https://login\.tailscale\.com/a/[A-Za-z0-9_-]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex KeyUriRegex = new(
        @"(?i)\b(vless|vmess|trojan|avo)://[^\s""'<>]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex UuidRegex = new(
        @"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex LongEncodedTokenRegex = new(
        @"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{80,}={0,2}(?![A-Za-z0-9+/_-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SensitiveAssignmentRegex = new(
        @"(?i)\b(auth[-_]?key|preauth[-_]?key|password|passwd|token|secret|private[-_]?key|pbk|sid|shortid|uuid)\s*[:=]\s*([^\s,;""']+|""[^""]*"")",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly object LogSync = new();
    private static bool _existingLogSanitized;

    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);
    private Process? _process;
    private volatile Process? _intentionalStopProcess;
    private ProcessMode _processMode;
    private TaskCompletionSource<bool>? _onlineSignal;
    private TaskCompletionSource<RelayGatewayStartResult>? _gatewayReadySignal;
    private IProgress<RelayGatewayEvent>? _gatewayProgress;
    private string? _reportedAddress;
    private string? _expectedControlUrl;
    private string? _oneTimeKeyFile;
    private int _gatewayPort;
    private bool _disposed;

    public ComponentInfo Info { get; } = new()
    {
        Name = "SerpiumNet",
        Version = "0.5.2",
        Type = ComponentType.Engine
    };

    public ComponentState State { get; private set; } = ComponentState.Disabled;

    public bool IsConnected { get; private set; }

    public bool HasLiveGatewayProcess =>
        _processMode == ProcessMode.Gateway && _process is { HasExited: false };

    public async Task InitializeAsync()
    {
        ThrowIfDisposed();
        await _lifecycleLock.WaitAsync().ConfigureAwait(false);

        try
        {
            if (State == ComponentState.Enabled)
            {
                return;
            }

            string executablePath = GetExecutablePath();

            if (!File.Exists(executablePath))
            {
                throw new FileNotFoundException(
                    "The packaged SerpiumNet executable was not found.",
                    executablePath);
            }

            string versionOutput = await ProbeVersionAsync(executablePath).ConfigureAwait(false);
            State = ComponentState.Enabled;
            WriteLog($"Initialized. Binary={versionOutput}; Mode=HeadscaleHeadless");
        }
        catch (Exception exception)
        {
            State = ComponentState.Error;
            WriteLog($"Initialization failed: {exception.GetType().Name}: {exception.Message}");
            throw;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task ConnectAsync()
    {
        ThrowIfDisposed();
        await DisconnectAsync().ConfigureAwait(false);

        Task<bool> onlineTask;

        await _lifecycleLock.WaitAsync().ConfigureAwait(false);

        try
        {
            EnsureInitialized();
            HeadscaleLaunchSettings settings = ResolveHeadscaleSettings();

            StartProcess(
                ProcessMode.Node,
                "node -hostname serpium-node",
                gatewayPort: 0,
                progress: null,
                settings: settings);

            onlineTask = _onlineSignal!.Task;
        }
        finally
        {
            _lifecycleLock.Release();
        }

        try
        {
            await onlineTask.WaitAsync(ConnectionOutcomeTimeout).ConfigureAwait(false);
        }
        catch
        {
            await DisconnectAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<RelayGatewayStartResult> StartGatewayAsync(
        int port,
        IProgress<RelayGatewayEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(
                nameof(port),
                port,
                "Relay gateway port must be in range 1..65535.");
        }

        await DisconnectAsync().ConfigureAwait(false);

        Task<RelayGatewayStartResult> readyTask;

        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            EnsureInitialized();
            HeadscaleLaunchSettings settings = ResolveHeadscaleSettings();

            string target = $"127.0.0.1:{port}";
            StartProcess(
                ProcessMode.Gateway,
                $"gateway -hostname serpium-gateway -port {port} -target {target}",
                port,
                progress,
                settings);

            readyTask = _gatewayReadySignal!.Task;
        }
        finally
        {
            _lifecycleLock.Release();
        }

        try
        {
            RelayGatewayStartResult result = await readyTask
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);

            WriteLog($"Gateway ready. Address={result.VirtualAddress}; Port={result.Port}.");
            return result;
        }
        catch
        {
            await StopGatewayAsync().ConfigureAwait(false);
            throw;
        }
    }

    public Task StopGatewayAsync()
    {
        return DisconnectAsync();
    }

    public async Task DisconnectAsync()
    {
        ThrowIfDisposed();

        Process? process;
        ProcessMode processMode;
        TaskCompletionSource<bool>? onlineSignal;
        TaskCompletionSource<RelayGatewayStartResult>? gatewayReadySignal;
        IProgress<RelayGatewayEvent>? gatewayProgress;

        await _lifecycleLock.WaitAsync().ConfigureAwait(false);

        try
        {
            process = _process;
            _intentionalStopProcess = process;
            processMode = _processMode;
            onlineSignal = _onlineSignal;
            gatewayReadySignal = _gatewayReadySignal;
            gatewayProgress = _gatewayProgress;

            _process = null;
            _processMode = ProcessMode.None;
            _onlineSignal = null;
            _gatewayReadySignal = null;
            _gatewayProgress = null;
            _reportedAddress = null;
            _expectedControlUrl = null;
            _oneTimeKeyFile = null;
            _gatewayPort = 0;
            IsConnected = false;
        }
        finally
        {
            _lifecycleLock.Release();
        }

        onlineSignal?.TrySetCanceled();
        gatewayReadySignal?.TrySetCanceled();

        if (process is not null)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync().ConfigureAwait(false);
                }

                if (!process.HasExited)
                {
                    throw new InvalidOperationException(
                        "SerpiumNet process did not exit after the stop request.");
                }
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                // The process exited between the state check and the stop request.
            }
            finally
            {
                process.Dispose();

                if (ReferenceEquals(_intentionalStopProcess, process))
                {
                    _intentionalStopProcess = null;
                }
            }
        }

        if (processMode == ProcessMode.Gateway)
        {
            gatewayProgress?.Report(new RelayGatewayEvent
            {
                Kind = RelayGatewayEventKind.Status,
                Message = "SerpiumNet Relay gateway stopped."
            });
            WriteLog("Gateway stopped. ProcessVerifiedExited=true");
        }
        else if (processMode == ProcessMode.Node)
        {
            WriteLog("Node disconnected. ProcessVerifiedExited=true");
        }
    }

    public async Task ShutdownAsync()
    {
        ThrowIfDisposed();
        await DisconnectAsync().ConfigureAwait(false);
        State = ComponentState.Disabled;
        WriteLog("Shutdown completed.");
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await ShutdownAsync().ConfigureAwait(false);
        _disposed = true;
        _lifecycleLock.Dispose();
        GC.SuppressFinalize(this);
    }

    private void StartProcess(
        ProcessMode mode,
        string arguments,
        int gatewayPort,
        IProgress<RelayGatewayEvent>? progress,
        HeadscaleLaunchSettings settings)
    {
        string executablePath = GetExecutablePath();
        string workingDirectory = Path.GetDirectoryName(executablePath)
            ?? throw new InvalidOperationException(
                "SerpiumNet package directory could not be resolved.");

        var onlineSignal = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var gatewayReadySignal = new TaskCompletionSource<RelayGatewayStartResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        _onlineSignal = onlineSignal;
        _gatewayReadySignal = gatewayReadySignal;
        _gatewayProgress = progress;
        _reportedAddress = null;
        _expectedControlUrl = settings.ControlUrl;
        _oneTimeKeyFile = settings.AuthKeyFile;
        _gatewayPort = gatewayPort;
        IsConnected = false;
        _processMode = mode;

        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        // Never inherit a cloud-Tailscale enrollment key. SerpiumNet receives only
        // the explicit Headscale settings resolved by this engine.
        startInfo.Environment.Remove("TS_AUTHKEY");
        startInfo.Environment[ControlUrlEnvironmentVariable] = settings.ControlUrl;

        if (!string.IsNullOrWhiteSpace(settings.AuthKey))
        {
            startInfo.Environment[AuthKeyEnvironmentVariable] = settings.AuthKey;
        }
        else
        {
            startInfo.Environment.Remove(AuthKeyEnvironmentVariable);
        }

        var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };

        process.OutputDataReceived += (_, eventArgs) =>
        {
            if (!string.IsNullOrWhiteSpace(eventArgs.Data))
            {
                HandleProcessLine(
                    eventArgs.Data,
                    "stdout",
                    mode,
                    onlineSignal,
                    gatewayReadySignal,
                    progress);
            }
        };

        process.ErrorDataReceived += (_, eventArgs) =>
        {
            if (!string.IsNullOrWhiteSpace(eventArgs.Data))
            {
                HandleProcessLine(
                    eventArgs.Data,
                    "stderr",
                    mode,
                    onlineSignal,
                    gatewayReadySignal,
                    progress);
            }
        };

        process.Exited += (_, _) =>
        {
            IsConnected = false;
            int exitCode = SafeExitCode(process);
            bool intentionalStop = ReferenceEquals(_intentionalStopProcess, process);

            if (!intentionalStop)
            {
                var exception = new InvalidOperationException(
                    $"SerpiumNet process exited unexpectedly. Mode={mode}; ExitCode={exitCode}.");

                if (mode == ProcessMode.Node)
                {
                    onlineSignal.TrySetException(exception);
                }
                else if (mode == ProcessMode.Gateway)
                {
                    gatewayReadySignal.TrySetException(exception);
                    progress?.Report(new RelayGatewayEvent
                    {
                        Kind = RelayGatewayEventKind.Error,
                        Message = exception.Message
                    });
                }
            }

            WriteLog($"Process exited. Mode={mode}; ExitCode={exitCode}; Intentional={intentionalStop}.");
        };

        _process = process;

        if (!process.Start())
        {
            _process = null;
            _processMode = ProcessMode.None;
            process.Dispose();
            throw new InvalidOperationException("SerpiumNet process could not be started.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        string authMode = settings.HasPersistentState
            ? "persistent-state"
            : settings.HasAuthKey ? "one-time-key" : "missing";

        if (mode == ProcessMode.Gateway)
        {
            progress?.Report(new RelayGatewayEvent
            {
                Kind = RelayGatewayEventKind.Status,
                Message = $"SerpiumNet Headscale gateway process started on port {gatewayPort}."
            });
            WriteLog(
                $"Gateway process started. Port={gatewayPort}; ControlURL={settings.ControlUrl}; Enrollment={authMode}.");
        }
        else
        {
            WriteLog(
                $"Node process started. ControlURL={settings.ControlUrl}; Enrollment={authMode}.");
        }
    }

    private void HandleProcessLine(
        string line,
        string streamName,
        ProcessMode mode,
        TaskCompletionSource<bool> onlineSignal,
        TaskCompletionSource<RelayGatewayStartResult> gatewayReadySignal,
        IProgress<RelayGatewayEvent>? progress)
    {
        WriteLog($"{streamName}: {RedactSensitiveUrls(line)}");

        if (line.Equals("CONTROL_MODE=tailscale-default", StringComparison.OrdinalIgnoreCase))
        {
            FailHeadlessStartup(
                "SerpiumNet attempted to use the public Tailscale control plane. " +
                "Headless Headscale mode forbids cloud fallback.",
                mode,
                onlineSignal,
                gatewayReadySignal,
                progress);
            return;
        }

        if (line.StartsWith("CONTROL_URL=", StringComparison.OrdinalIgnoreCase))
        {
            string reportedControlUrl = line["CONTROL_URL=".Length..].Trim().TrimEnd('/');
            string expectedControlUrl = (_expectedControlUrl ?? string.Empty).TrimEnd('/');

            if (!string.Equals(
                    reportedControlUrl,
                    expectedControlUrl,
                    StringComparison.OrdinalIgnoreCase))
            {
                FailHeadlessStartup(
                    $"SerpiumNet reported an unexpected control URL: '{reportedControlUrl}'.",
                    mode,
                    onlineSignal,
                    gatewayReadySignal,
                    progress);
            }

            return;
        }

        if (TailscaleLoginUrlRegex.IsMatch(line) ||
            line.StartsWith("LOGIN_URL=", StringComparison.OrdinalIgnoreCase))
        {
            FailHeadlessStartup(
                "Headscale registration was not accepted. Browser authorization is disabled. " +
                $"For a fresh node, place a valid one-time key in '{GetAuthKeyFilePath()}' and start the gateway again.",
                mode,
                onlineSignal,
                gatewayReadySignal,
                progress);
            return;
        }

        if (line.StartsWith("TAILSCALE_IP=", StringComparison.Ordinal))
        {
            string address = line["TAILSCALE_IP=".Length..].Trim();
            _reportedAddress = address;

            if (mode == ProcessMode.Gateway)
            {
                progress?.Report(new RelayGatewayEvent
                {
                    Kind = RelayGatewayEventKind.AddressAssigned,
                    Message = $"SerpiumNet virtual address assigned: {address}",
                    Value = address
                });
            }

            return;
        }

        if (line.Equals("NODE_ONLINE", StringComparison.Ordinal))
        {
            IsConnected = true;
            TryDeleteOneTimeKeyFile();
            onlineSignal.TrySetResult(true);
            return;
        }

        if (line.StartsWith("GATEWAY_READY=", StringComparison.Ordinal))
        {
            if (mode != ProcessMode.Gateway)
            {
                return;
            }

            string portText = line["GATEWAY_READY=".Length..].Trim();
            int readyPort = int.TryParse(portText, out int parsedPort)
                ? parsedPort
                : _gatewayPort;

            string? reportedAddress = _reportedAddress;

            if (string.IsNullOrWhiteSpace(reportedAddress))
            {
                FailHeadlessStartup(
                    "SerpiumNet reported gateway readiness without a virtual network address.",
                    mode,
                    onlineSignal,
                    gatewayReadySignal,
                    progress);
                return;
            }

            var result = new RelayGatewayStartResult
            {
                VirtualAddress = reportedAddress,
                Port = readyPort
            };

            IsConnected = true;
            TryDeleteOneTimeKeyFile();
            gatewayReadySignal.TrySetResult(result);
            progress?.Report(new RelayGatewayEvent
            {
                Kind = RelayGatewayEventKind.Ready,
                Message = $"SerpiumNet Relay gateway is ready at {reportedAddress}:{readyPort}.",
                Value = reportedAddress
            });
        }
    }

    private static void FailHeadlessStartup(
        string message,
        ProcessMode mode,
        TaskCompletionSource<bool> onlineSignal,
        TaskCompletionSource<RelayGatewayStartResult> gatewayReadySignal,
        IProgress<RelayGatewayEvent>? progress)
    {
        var exception = new InvalidOperationException(message);

        if (mode == ProcessMode.Node)
        {
            onlineSignal.TrySetException(exception);
        }
        else if (mode == ProcessMode.Gateway)
        {
            gatewayReadySignal.TrySetException(exception);
            progress?.Report(new RelayGatewayEvent
            {
                Kind = RelayGatewayEventKind.Error,
                Message = message
            });
        }
    }

    private static HeadscaleLaunchSettings ResolveHeadscaleSettings()
    {
        string stateDirectory = GetStateDirectory();
        Directory.CreateDirectory(stateDirectory);

        string controlUrl = FirstNonEmpty(
            Environment.GetEnvironmentVariable(ControlUrlEnvironmentVariable),
            ReadTrimmedTextFile(Path.Combine(stateDirectory, ControlUrlFileName)),
            DefaultControlUrl);

        if (!Uri.TryCreate(controlUrl, UriKind.Absolute, out Uri? controlUri) ||
            (controlUri.Scheme != Uri.UriSchemeHttp &&
             controlUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidDataException(
                $"Invalid Headscale control URL '{controlUrl}'. " +
                $"Set {ControlUrlEnvironmentVariable} or update '{Path.Combine(stateDirectory, ControlUrlFileName)}'.");
        }

        string normalizedControlUrl = controlUri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        string stateFile = Path.Combine(stateDirectory, StateFileName);
        bool hasPersistentState = File.Exists(stateFile) && new FileInfo(stateFile).Length > 0;

        string authKeyFile = Path.Combine(stateDirectory, AuthKeyFileName);
        string environmentAuthKey = Environment.GetEnvironmentVariable(AuthKeyEnvironmentVariable)?.Trim()
            ?? string.Empty;
        string fileAuthKey = ReadTrimmedTextFile(authKeyFile);
        string authKey = FirstNonEmpty(environmentAuthKey, fileAuthKey);
        string? usedAuthKeyFile = string.IsNullOrWhiteSpace(environmentAuthKey) &&
                                  !string.IsNullOrWhiteSpace(fileAuthKey)
            ? authKeyFile
            : null;

        if (!hasPersistentState && string.IsNullOrWhiteSpace(authKey))
        {
            throw new InvalidOperationException(
                "SerpiumNet has no registered Headscale state and no one-time enrollment key. " +
                $"Put a Headscale preauth key on one line in '{authKeyFile}', then start the gateway again. " +
                "The key file will be deleted automatically after successful enrollment.");
        }

        return new HeadscaleLaunchSettings(
            normalizedControlUrl,
            authKey,
            usedAuthKeyFile,
            hasPersistentState);
    }

    private void TryDeleteOneTimeKeyFile()
    {
        string? keyFile = _oneTimeKeyFile;
        _oneTimeKeyFile = null;

        if (string.IsNullOrWhiteSpace(keyFile))
        {
            return;
        }

        try
        {
            if (File.Exists(keyFile))
            {
                File.Delete(keyFile);
                WriteLog("One-time Headscale auth-key file deleted after successful enrollment.");
            }
        }
        catch (Exception exception)
        {
            WriteLog(
                $"Warning: one-time auth-key file could not be deleted: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static string GetStateDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SerpiumVPN",
            "SerpiumNet");
    }

    private static string GetAuthKeyFilePath()
    {
        return Path.Combine(GetStateDirectory(), AuthKeyFileName);
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    private static string ReadTrimmedTextFile(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path).Trim() : string.Empty;
        }
        catch (Exception exception)
        {
            throw new IOException($"Could not read SerpiumNet configuration file '{path}'.", exception);
        }
    }

    private static string RedactSensitiveUrls(string line) =>
        RedactSensitiveText(line);

    private static string RedactSensitiveText(string value)
    {
        string redacted = TailscaleLoginUrlRegex.Replace(
            value,
            "<tailscale-login-url-redacted>");

        redacted = KeyUriRegex.Replace(
            redacted,
            match => match.Groups[1].Value.ToUpperInvariant() + "://[REDACTED]");

        redacted = UuidRegex.Replace(redacted, "[UUID REDACTED]");
        redacted = LongEncodedTokenRegex.Replace(
            redacted,
            "[ENCODED TOKEN REDACTED]");

        redacted = SensitiveAssignmentRegex.Replace(
            redacted,
            match => match.Groups[1].Value + "=[REDACTED]");

        return redacted;
    }

    private static void SanitizeExistingLog(string path)
    {
        if (_existingLogSanitized)
            return;

        _existingLogSanitized = true;

        try
        {
            if (!File.Exists(path))
                return;

            FileInfo info = new(path);
            if (info.Length > 8 * 1024 * 1024)
            {
                File.Delete(path);
                return;
            }

            string original = File.ReadAllText(path);
            string sanitized = RedactSensitiveText(original);

            if (!string.Equals(
                    original,
                    sanitized,
                    StringComparison.Ordinal))
            {
                File.WriteAllText(path, sanitized);
            }
        }
        catch
        {
            // Existing diagnostic history is optional.
        }
    }

    private static async Task<string> ProbeVersionAsync(string executablePath)
    {
        string workingDirectory = Path.GetDirectoryName(executablePath)
            ?? throw new InvalidOperationException(
                "SerpiumNet package directory could not be resolved.");

        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            Arguments = "version",
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = new Process { StartInfo = startInfo };

        if (!process.Start())
        {
            throw new InvalidOperationException(
                "SerpiumNet version probe could not be started.");
        }

        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync();
        Task<string> standardError = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(VersionProbeTimeout);

        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            TryKill(process);
            throw new TimeoutException(
                "SerpiumNet version probe timed out.",
                exception);
        }

        string output = (await standardOutput.ConfigureAwait(false)).Trim();
        string error = (await standardError.ConfigureAwait(false)).Trim();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"SerpiumNet version probe failed with exit code {process.ExitCode}: {error}");
        }

        if (!output.StartsWith("SerpiumNet ", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Unexpected SerpiumNet version response: '{output}'.");
        }

        return output;
    }

    private void EnsureInitialized()
    {
        if (State != ComponentState.Enabled)
        {
            throw new InvalidOperationException(
                "SerpiumNet must be initialized before starting a connection.");
        }
    }

    private static string GetExecutablePath()
    {
        string assemblyPath = Assembly.GetExecutingAssembly().Location;
        string directory = Path.GetDirectoryName(assemblyPath)
            ?? throw new InvalidOperationException(
                "SerpiumNet engine assembly directory could not be resolved.");

        return Path.Combine(directory, "SerpiumNet.exe");
    }

    private static int SafeExitCode(Process process)
    {
        try
        {
            return process.ExitCode;
        }
        catch
        {
            return -1;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best-effort cleanup after a failed probe.
        }
    }

    private static void WriteLog(string message)
    {
        try
        {
            string logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SerpiumVPN",
                "Logs");
            Directory.CreateDirectory(logDirectory);

            string logPath = Path.Combine(
                logDirectory,
                "serpium-net-engine.log");

            lock (LogSync)
            {
                SanitizeExistingLog(logPath);

                string safeMessage = RedactSensitiveText(message);
                string line =
                    $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} " +
                    $"[SerpiumNetEngine] {safeMessage}" +
                    Environment.NewLine;

                File.AppendAllText(logPath, line);
            }
        }
        catch
        {
            // Engine logging must never break the host process.
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed record HeadscaleLaunchSettings(
        string ControlUrl,
        string AuthKey,
        string? AuthKeyFile,
        bool HasPersistentState)
    {
        public bool HasAuthKey => !string.IsNullOrWhiteSpace(AuthKey);
    }

    private enum ProcessMode
    {
        None,
        Node,
        Gateway
    }
}

