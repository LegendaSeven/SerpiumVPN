using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Routing;

using SerpiumVPN.Relay.Diagnostics;

namespace SerpiumVPN.Relay.SingBox;

/// <summary>
/// Owns a single Serpium sing-box TUN session.
/// The provider configuration is supplied through stdin and is never written to disk.
/// Only process identity and the non-sensitive interface name are persisted for recovery.
/// </summary>
public enum SingBoxObservedRoute
{
    Direct = 0,
    Vpn = 1
}

public sealed record SingBoxFlowRouteObservation(
    string ProcessPath,
    SingBoxObservedRoute Route,
    DateTimeOffset ObservedAt);

public sealed record SingBoxActiveConnection(
    string Id,
    string ProcessPath,
    SingBoxObservedRoute Route,
    bool UsesInternet = false);

public sealed record SingBoxActiveConnectionsSnapshot(
    DateTimeOffset ObservedAt,
    IReadOnlyList<SingBoxActiveConnection> Connections,
    bool ApiAvailable);

public sealed class SerpiumSingBoxSessionManager : IDisposable
{
    private static readonly TimeSpan InterfaceStartTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan ConnectivityTimeout = TimeSpan.FromSeconds(35);
    private static readonly TimeSpan InterfaceStopTimeout = TimeSpan.FromSeconds(30);
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private static readonly Uri ConnectivityProbeUri =
        new("https://www.gstatic.com/generate_204", UriKind.Absolute);

    private static readonly Regex SensitiveAssignmentRegex = new(
        "(?i)\\b(password|uuid|server|server_name|sni|secret|token|key)\\s*[:=]\\s*(?:\\\"[^\\\"]*\\\"|'[^']*'|\\S+)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex UuidRegex = new(
        @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex Ipv4Regex = new(
        @"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex HostNameRegex = new(
        @"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LongBase64Regex = new(
        @"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{28,}(?![A-Za-z0-9+/=_-])",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    // sing-box INFO flow prefix is typically "[123456789 4ms]".
    // Correlate router process discovery with the later outbound decision.
    private static readonly Regex FlowIdRegex = new(
        @"\[(?<id>[0-9]{1,20})(?:\s+[^\]]+)?\]",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex ProcessPathLogRegex = new(
        @"(?i)\brouter:\s+found process path:\s*(?<path>.+?)\s*$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex OutboundRouteLogRegex = new(
        @"(?i)\boutbound/[^\[]+\[(?<tag>[^\]]+)\]:\s+" +
        @"outbound(?:\s+packet)?\s+connection\s+to\s+(?<destination>.+?)\s*$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex DestinationPortRegex = new(
        @":(?<port>[0-9]{1,5})\s*$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private readonly string _relayDirectory;
    private readonly string _statePath;
    private Process? _process;
    private SafeFileHandle? _killOnCloseJob;
    private string? _interfaceName;
    private readonly object _flowObservationGate = new();
    private readonly Dictionary<string, string> _flowProcessPaths =
        new(StringComparer.Ordinal);
    private readonly HttpClient _clashApiClient = new(
        new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(2)
    };
    private CancellationTokenSource? _connectionMonitorCts;
    private Task? _connectionMonitorTask;
    private int _clashApiPort;
    private string _clashApiSecret = string.Empty;
    private string? _connectivityProbeOutboundTag;
    private string _lastActiveConnectionFingerprint = string.Empty;
    private bool _disposed;

    public SerpiumSingBoxSessionManager()
    {
        _relayDirectory = Path.Combine(
            Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
            "bin_files",
            "relay");
        _statePath = Path.Combine(
            _relayDirectory,
            "state",
            "sing-box-tun-process.json");
    }

    public RelayGatewayState State { get; private set; } = RelayGatewayState.Stopped;
    public bool IsRunning => _process is { HasExited: false };
    public string? LastError { get; private set; }
    public string? InterfaceName => _interfaceName;
    public int? ProcessId => _process is { HasExited: false } ? _process.Id : null;

    public bool HasLiveProcess
    {
        get
        {
            if (IsRunning)
                return true;

            if (!TryGetStoredOwnedProcess(out Process? process, out _))
                return false;

            process?.Dispose();
            return true;
        }
    }

    public event Action<string>? LogReceived;
    public event Action<RelayGatewayState>? StateChanged;

    /// <summary>
    /// Actual data-plane observation from sing-box TUN routing.
    /// Destination addresses are intentionally not exposed to the UI.
    /// </summary>
    public event Action<SingBoxFlowRouteObservation>? FlowRouteObserved;
    public event Action<SingBoxActiveConnectionsSnapshot>?
        ActiveConnectionsChanged;

    public async Task StartAsync(
        string singBoxExecutablePath,
        ProviderRuntimeProfile runtimeProfile,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(runtimeProfile);

        if (HasLiveProcess)
            throw new InvalidOperationException("TUN-подключение sing-box уже запущено.");
        if (!IsCurrentProcessAdministrator())
        {
            throw new InvalidOperationException(
                "Для создания TUN и системных маршрутов перезапустите SerpiumVPN от имени администратора.");
        }

        string executablePath = Path.GetFullPath(singBoxExecutablePath);
        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException(
                "sing-box.exe не найден в bin_files\\relay.",
                executablePath);
        }

        byte[] configurationUtf8 = runtimeProfile.CopyConfiguration();
        string? interfaceName = null;
        _clashApiPort = runtimeProfile.ClashApiPort;
        _clashApiSecret = runtimeProfile.ClashApiSecret;
        _connectivityProbeOutboundTag = null;
        SetState(RelayGatewayState.Starting);
        LastError = null;

        try
        {
            interfaceName = ReadAndValidateTunInterface(configurationUtf8);
            if (_clashApiPort > 0)
                _connectivityProbeOutboundTag = VpnOutboundProbe.ReadOutboundTag(configurationUtf8);
            _interfaceName = interfaceName;
            ClearFlowObservations();

            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            await StopStoredOwnedProcessAsync(cancellationToken);
            await WaitForInterfaceToDisappearAsync(
                interfaceName,
                InterfaceStopTimeout,
                cancellationToken);

            ProcessStartInfo startInfo = new()
            {
                FileName = executablePath,
                WorkingDirectory = Path.GetDirectoryName(executablePath) ?? _relayDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("--disable-color");
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add("stdin");

            _process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };
            _process.OutputDataReceived += (_, eventArgs) => ForwardLog(eventArgs.Data);
            _process.ErrorDataReceived += (_, eventArgs) => ForwardLog(eventArgs.Data);
            _process.Exited += (_, _) => HandleUnexpectedExit();

            if (!_process.Start())
                throw new InvalidOperationException("Не удалось запустить sing-box.");

            AttachProcessToKillOnCloseJob(_process);
            SaveState(_process, executablePath, interfaceName);
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();

            try
            {
                await _process.StandardInput.BaseStream.WriteAsync(
                    configurationUtf8.AsMemory(),
                    cancellationToken);
                await _process.StandardInput.BaseStream.FlushAsync(cancellationToken);
            }
            finally
            {
                _process.StandardInput.Close();
            }

            await WaitForInterfaceAsync(
                interfaceName,
                InterfaceStartTimeout,
                cancellationToken);

            ThrowIfProcessExited("sing-box завершился до создания рабочего TUN-интерфейса");

            await VerifyTunnelConnectivityAsync(
                ConnectivityTimeout,
                cancellationToken);

            ThrowIfProcessExited("sing-box завершился во время проверки подключения");

            LogReceived?.Invoke($"TUN готов: {interfaceName}");
            LogReceived?.Invoke("Контрольный HTTPS-запрос через VPN выполнен успешно.");
            StartActiveConnectionMonitor();
            SetState(RelayGatewayState.Running);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            await KillCurrentProcessAsync(CancellationToken.None);
            DeleteStateFile();

            if (!string.IsNullOrWhiteSpace(interfaceName))
            {
                await WaitForInterfaceToDisappearAsync(
                    interfaceName,
                    InterfaceStopTimeout,
                    CancellationToken.None);
            }

            SetState(RelayGatewayState.Failed);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(configurationUtf8);
        }
    }


    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        string? interfaceName = _interfaceName;
        if (string.IsNullOrWhiteSpace(interfaceName))
            interfaceName = ReadState()?.InterfaceName;

        SetState(RelayGatewayState.Stopping);
        LastError = null;
        StopActiveConnectionMonitor();

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
            CloseKillOnCloseJob();
            DeleteStateFile();

            if (!string.IsNullOrWhiteSpace(interfaceName))
            {
                await WaitForInterfaceToDisappearAsync(
                    interfaceName,
                    InterfaceStopTimeout,
                    CancellationToken.None);
            }

            _interfaceName = null;
            _clashApiPort = 0;
            _clashApiSecret = string.Empty;
            ClearFlowObservations();
            SetState(RelayGatewayState.Stopped);
        }
    }


    private static string ReadAndValidateTunInterface(byte[] configurationUtf8)
    {
        using JsonDocument document = JsonDocument.Parse(configurationUtf8);
        JsonElement root = document.RootElement;
        if (!root.TryGetProperty("inbounds", out JsonElement inbounds) ||
            inbounds.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("Конфигурация sing-box не содержит массив inbounds.");
        }

        foreach (JsonElement inbound in inbounds.EnumerateArray())
        {
            if (inbound.ValueKind != JsonValueKind.Object ||
                !inbound.TryGetProperty("type", out JsonElement typeValue) ||
                typeValue.ValueKind != JsonValueKind.String ||
                !string.Equals(typeValue.GetString(), "tun", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!inbound.TryGetProperty("auto_route", out JsonElement autoRouteValue) ||
                autoRouteValue.ValueKind is not JsonValueKind.True)
            {
                throw new FormatException("TUN-вход sing-box не включает auto_route.");
            }

            if (!inbound.TryGetProperty("interface_name", out JsonElement nameValue) ||
                nameValue.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(nameValue.GetString()))
            {
                throw new FormatException("TUN-вход sing-box не содержит interface_name.");
            }

            string interfaceName = nameValue.GetString()!.Trim();
            if (interfaceName.Length is < 3 or > 64 ||
                interfaceName.Any(character =>
                    !(char.IsLetterOrDigit(character) || character is '-' or '_')))
            {
                throw new FormatException("Имя TUN-интерфейса содержит недопустимые символы.");
            }

            return interfaceName;
        }

        throw new FormatException("В конфигурации sing-box не найден TUN-вход.");
    }

    private async Task VerifyTunnelConnectivityAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        string lastFailure = "контрольный запрос ещё не выполнялся";
        Exception? lastError = null;

        using HttpClientHandler handler = new()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None
        };
        using HttpClient client = new(handler);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SerpiumVPN/1.0.42");

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfProcessExited("sing-box завершился до проверки доступа в интернет");

            using CancellationTokenSource attemptTimeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            attemptTimeout.CancelAfter(TimeSpan.FromSeconds(8));

            try
            {
                if (_clashApiPort > 0)
                {
                    await VpnOutboundProbe.CheckAsync(client,_clashApiPort,_clashApiSecret,
                        _connectivityProbeOutboundTag ?? throw new InvalidOperationException("VPN probe is unavailable"),attemptTimeout.Token);
                    return;
                }
                using HttpRequestMessage request = new(HttpMethod.Get, ConnectivityProbeUri);
                using HttpResponseMessage response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    attemptTimeout.Token);

                if (response.StatusCode == HttpStatusCode.NoContent || response.IsSuccessStatusCode)
                    return;

                lastFailure = $"HTTP {(int)response.StatusCode}";
            }
            catch (SerpiumVPN.Relay.Diagnostics.ConnectionCheckException ex)
            {
                lastError = ex;
                lastFailure = ex.Message;
                if (ex.Kind is SerpiumVPN.Relay.Diagnostics.ConnectionFailureKind.AuthenticationRejected or
                    SerpiumVPN.Relay.Diagnostics.ConnectionFailureKind.ProbeUnavailable) throw;
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
                lastFailure = "таймаут контрольного HTTPS-запроса";
            }
            catch (HttpRequestException ex)
            {
                lastError = ex;
                lastFailure = SanitizeLogLine(ex.Message);
            }
            catch (Exception ex) when (ex is InvalidDataException or JsonException)
            {
                lastError = new SerpiumVPN.Relay.Diagnostics.ConnectionCheckException(SerpiumVPN.Relay.Diagnostics.ConnectionFailureKind.ProbeFailed, ex);
                lastFailure = "движок не подтвердил VPN-соединение";
            }

            await Task.Delay(TimeSpan.FromMilliseconds(900), cancellationToken);
        }

        throw new TimeoutException(
            "TUN-интерфейс создан, но доступ через VPN не подтвердился за " +
            $"{timeout.TotalSeconds:0} секунд: {lastFailure}.", lastError);
    }

    private static async Task WaitForInterfaceAsync(
        string interfaceName,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsInterfacePresent(interfaceName))
                return;

            await Task.Delay(200, cancellationToken);
        }

        throw new TimeoutException(
            $"sing-box не создал TUN-интерфейс {interfaceName} за {timeout.TotalSeconds:0} секунд.");
    }

    private static async Task WaitForInterfaceToDisappearAsync(
        string interfaceName,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (!IsInterfacePresent(interfaceName))
                return;

            try
            {
                await Task.Delay(200, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private static bool IsInterfacePresent(string interfaceName)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(networkInterface =>
                string.Equals(
                    networkInterface.Name,
                    interfaceName,
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    networkInterface.Description,
                    interfaceName,
                    StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    private void ThrowIfProcessExited(string prefix)
    {
        if (_process is not { HasExited: true })
            return;

        throw new InvalidOperationException($"{prefix}. Код: {_process.ExitCode}.");
    }

    private void ForwardLog(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        // Parse the raw line before privacy redaction. The UI only receives
        // process identity + route class; destination is never forwarded.
        TryForwardFlowRouteObservation(line);

        string safeLine = SanitizeLogLine(line);
        if (!string.IsNullOrWhiteSpace(safeLine))
            LogReceived?.Invoke(safeLine);
    }

    private void TryForwardFlowRouteObservation(string rawLine)
    {
        Match idMatch = FlowIdRegex.Match(rawLine);
        if (!idMatch.Success)
            return;

        string flowId = idMatch.Groups["id"].Value;

        Match processMatch = ProcessPathLogRegex.Match(rawLine);
        if (processMatch.Success)
        {
            string processPath = NormalizeObservedProcessPath(
                processMatch.Groups["path"].Value);

            if (string.IsNullOrWhiteSpace(processPath) ||
                processPath.StartsWith(
                    ":",
                    StringComparison.Ordinal))
            {
                return;
            }

            lock (_flowObservationGate)
            {
                _flowProcessPaths[flowId] = processPath;

                // Defensive bound for malformed/unmatched log sequences.
                if (_flowProcessPaths.Count > 2048)
                    _flowProcessPaths.Clear();
            }

            return;
        }

        Match outboundMatch = OutboundRouteLogRegex.Match(rawLine);
        if (!outboundMatch.Success)
            return;

        string? processPathForFlow;
        lock (_flowObservationGate)
        {
            if (!_flowProcessPaths.Remove(
                    flowId,
                    out processPathForFlow))
            {
                return;
            }
        }

        if (string.IsNullOrWhiteSpace(processPathForFlow))
            return;

        string destination =
            outboundMatch.Groups["destination"].Value.Trim();

        Match portMatch =
            DestinationPortRegex.Match(destination);

        if (portMatch.Success &&
            int.TryParse(
                portMatch.Groups["port"].Value,
                out int destinationPort) &&
            destinationPort == 53)
        {
            // DNS alone is not proof that the application's actual traffic
            // has switched route.
            return;
        }

        string outboundTag =
            outboundMatch.Groups["tag"].Value.Trim();

        SingBoxObservedRoute route =
            string.Equals(
                outboundTag,
                "direct",
                StringComparison.OrdinalIgnoreCase)
                ? SingBoxObservedRoute.Direct
                : SingBoxObservedRoute.Vpn;

        FlowRouteObserved?.Invoke(
            new SingBoxFlowRouteObservation(
                processPathForFlow,
                route,
                DateTimeOffset.Now));
    }

    private static string NormalizeObservedProcessPath(
        string value)
    {
        string path = value.Trim().Trim('"');

        if (path.StartsWith(
                @"\\?\",
                StringComparison.Ordinal))
        {
            path = path[4..];
        }
        else if (path.StartsWith(
                     @"\??\",
                     StringComparison.Ordinal))
        {
            path = path[4..];
        }

        return path;
    }

    private void StartActiveConnectionMonitor()
    {
        StopActiveConnectionMonitor();

        if (_clashApiPort is < 1 or > 65535 ||
            string.IsNullOrWhiteSpace(_clashApiSecret))
            return;

        _lastActiveConnectionFingerprint = string.Empty;
        _connectionMonitorCts = new CancellationTokenSource();
        CancellationToken token = _connectionMonitorCts.Token;
        _connectionMonitorTask = Task.Run(
            () => MonitorActiveConnectionsAsync(token),
            CancellationToken.None);
    }

    private void StopActiveConnectionMonitor()
    {
        CancellationTokenSource? cts =
            Interlocked.Exchange(ref _connectionMonitorCts, null);
        if (cts is not null)
        {
            try { cts.Cancel(); } catch { }
            cts.Dispose();
        }

        _connectionMonitorTask = null;
        _lastActiveConnectionFingerprint = string.Empty;
    }

    private async Task MonitorActiveConnectionsAsync(
        CancellationToken cancellationToken)
    {
        int consecutiveFailures = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                SingBoxActiveConnectionsSnapshot snapshot =
                    await QueryActiveConnectionsAsync(cancellationToken);

                consecutiveFailures = 0;
                string fingerprint =
                    BuildConnectionFingerprint(snapshot.Connections);

                if (!string.Equals(
                        fingerprint,
                        _lastActiveConnectionFingerprint,
                        StringComparison.Ordinal))
                {
                    _lastActiveConnectionFingerprint = fingerprint;
                    ActiveConnectionsChanged?.Invoke(snapshot);
                }
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                consecutiveFailures++;
                if (consecutiveFailures == 6)
                {
                    ActiveConnectionsChanged?.Invoke(
                        new SingBoxActiveConnectionsSnapshot(
                            DateTimeOffset.Now,
                            Array.Empty<SingBoxActiveConnection>(),
                            false));
                }
            }

            try
            {
                await Task.Delay(500, cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    public async Task WaitForRoutingPolicyAsync(string activationProbe, CancellationToken cancellationToken = default)
    {
        if (!IsRunning)
            throw new InvalidOperationException("Live TUN routing is unavailable.");
        var client = new SfpLiveRoutingClient(_clashApiClient, _clashApiPort, _clashApiSecret);
        await client.WaitForPolicyAsync(activationProbe, cancellationToken);
    }

    public async Task<int> ApplySfpLivePolicyAsync(string activationProbe, IEnumerable<string> processPaths,
        bool desiredVpn, CancellationToken cancellationToken = default)
    {
        if (!IsRunning)
            throw new InvalidOperationException("Live TUN routing is unavailable.");
        int? processId = ProcessId;
        var client = new SfpLiveRoutingClient(_clashApiClient, _clashApiPort, _clashApiSecret);
        await client.WaitForPolicyAsync(activationProbe, cancellationToken);
        int closed = await client.CloseStaleConnectionsAsync(processPaths, desiredVpn, cancellationToken);
        if (!IsRunning || ProcessId != processId)
            throw new InvalidOperationException("TUN session changed during the application switch.");
        _lastActiveConnectionFingerprint = string.Empty;
        LogReceived?.Invoke($"SFP live policy confirmed; closed old application connections: {closed}.");
        return closed;
    }

    public async Task<int> ApplySfpLivePolicyAsync(string activationProbe, SfpRoutingPolicy policy,
        CancellationToken cancellationToken = default)
    {
        if (!IsRunning) throw new InvalidOperationException("Live TUN routing is unavailable.");
        int? processId = ProcessId;
        var client = new SfpLiveRoutingClient(_clashApiClient, _clashApiPort, _clashApiSecret);
        await client.WaitForPolicyAsync(activationProbe, cancellationToken);
        int closed = await client.CloseStaleConnectionsAsync(policy, cancellationToken);
        if (!IsRunning || ProcessId != processId) throw new InvalidOperationException("TUN session changed during the route switch.");
        _lastActiveConnectionFingerprint = string.Empty;
        return closed;
    }

    public async Task<int> CloseOppositeRouteConnectionsAsync(
        IEnumerable<string> processPaths,
        SingBoxObservedRoute desiredRoute,
        CancellationToken cancellationToken = default)
    {
        if (_clashApiPort is < 1 or > 65535 ||
            string.IsNullOrWhiteSpace(_clashApiSecret))
        {
            return 0;
        }

        HashSet<string> normalizedPaths = new(
            processPaths
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(NormalizeObservedProcessPath),
            StringComparer.OrdinalIgnoreCase);

        if (normalizedPaths.Count == 0)
            return 0;

        int closed = 0;

        for (int pass = 0; pass < 2; pass++)
        {
            SingBoxActiveConnectionsSnapshot snapshot =
                await QueryActiveConnectionsAsync(cancellationToken);

            List<SingBoxActiveConnection> stale =
                snapshot.Connections
                    .Where(connection =>
                        connection.Route != desiredRoute &&
                        normalizedPaths.Contains(
                            NormalizeObservedProcessPath(connection.ProcessPath)))
                    .ToList();

            if (stale.Count == 0)
                break;

            foreach (SingBoxActiveConnection connection in stale)
            {
                await CloseActiveConnectionAsync(
                    connection.Id,
                    cancellationToken);
                closed++;
            }

            if (pass == 0)
                await Task.Delay(120, cancellationToken);
        }

        _lastActiveConnectionFingerprint = string.Empty;
        return closed;
    }

    private async Task CloseActiveConnectionAsync(
        string connectionId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connectionId))
            return;

        using HttpRequestMessage request = new(
            HttpMethod.Delete,
            $"http://127.0.0.1:{_clashApiPort}/connections/" +
            Uri.EscapeDataString(connectionId));

        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer",
                _clashApiSecret);

        using HttpResponseMessage response =
            await _clashApiClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

        response.EnsureSuccessStatusCode();
    }

    private async Task<SingBoxActiveConnectionsSnapshot>
        QueryActiveConnectionsAsync(
            CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            $"http://127.0.0.1:{_clashApiPort}/connections");

        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer",
                _clashApiSecret);

        using HttpResponseMessage response =
            await _clashApiClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

        response.EnsureSuccessStatusCode();

        await using Stream stream =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        using JsonDocument document =
            await JsonDocument.ParseAsync(
                stream,
                cancellationToken: cancellationToken);

        List<SingBoxActiveConnection> result = new();

        if (!document.RootElement.TryGetProperty(
                "connections",
                out JsonElement array) ||
            array.ValueKind != JsonValueKind.Array)
        {
            return new SingBoxActiveConnectionsSnapshot(
                DateTimeOffset.Now,
                result,
                true);
        }

        foreach (JsonElement item in array.EnumerateArray())
        {
            string id =
                item.TryGetProperty("id", out JsonElement idElement)
                    ? idElement.GetString() ?? string.Empty
                    : string.Empty;

            if (string.IsNullOrWhiteSpace(id) ||
                !item.TryGetProperty(
                    "metadata",
                    out JsonElement metadata) ||
                metadata.ValueKind != JsonValueKind.Object)
                continue;

            string processPath =
                metadata.TryGetProperty(
                    "processPath",
                    out JsonElement processElement)
                    ? processElement.GetString() ?? string.Empty
                    : string.Empty;

            processPath = NormalizeObservedProcessPath(processPath);
            if (string.IsNullOrWhiteSpace(processPath) ||
                processPath.StartsWith(":", StringComparison.Ordinal))
                continue;

            int destinationPort = 0;
            if (metadata.TryGetProperty(
                    "destinationPort",
                    out JsonElement portElement))
            {
                if (portElement.ValueKind == JsonValueKind.String)
                    int.TryParse(portElement.GetString(), out destinationPort);
                else if (portElement.ValueKind == JsonValueKind.Number)
                    portElement.TryGetInt32(out destinationPort);
            }

            if (destinationPort == 53)
                continue;

            result.Add(new SingBoxActiveConnection(
                id,
                processPath,
                ResolveConnectionRoute(item),
                SerpiumVPN.Relay.Routing.UserApplicationPolicy.IsInternetFlow(metadata)));
        }

        return new SingBoxActiveConnectionsSnapshot(
            DateTimeOffset.Now,
            result,
            true);
    }

    private static SingBoxObservedRoute ResolveConnectionRoute(
        JsonElement connection)
    {
        if (connection.TryGetProperty(
                "chains",
                out JsonElement chains) &&
            chains.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement chain in chains.EnumerateArray())
            {
                if (string.Equals(
                        chain.GetString(),
                        "direct",
                        StringComparison.OrdinalIgnoreCase))
                    return SingBoxObservedRoute.Direct;
            }
        }

        return SingBoxObservedRoute.Vpn;
    }

    private static string BuildConnectionFingerprint(
        IReadOnlyList<SingBoxActiveConnection> connections) =>
        string.Join(
            "|",
            connections
                .OrderBy(item => item.Id, StringComparer.Ordinal)
                .Select(item =>
                    item.Id + ":" + item.Route + ":" + item.ProcessPath + ":" + item.UsesInternet));

    private void ClearFlowObservations()
    {
        lock (_flowObservationGate)
        {
            _flowProcessPaths.Clear();
        }
    }

    private static string SanitizeLogLine(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "безопасное описание отсутствует";

        string sanitized = SensitiveAssignmentRegex.Replace(SensitiveDiagnosticRedactor.RedactText(value), "$1=<hidden>");
        sanitized = UuidRegex.Replace(sanitized, "<uuid>");
        sanitized = Ipv4Regex.Replace(sanitized, "<ip>");
        sanitized = HostNameRegex.Replace(sanitized, "<host>");
        sanitized = LongBase64Regex.Replace(sanitized, "<encoded>");
        sanitized = sanitized.Trim();

        if (sanitized.Length == 0)
            return "безопасное описание отсутствует";

        return sanitized.Length <= 600
            ? sanitized
            : sanitized[..600] + "…";
    }

    private void HandleUnexpectedExit()
    {
        CloseKillOnCloseJob();
        DeleteStateFile();
        StopActiveConnectionMonitor();
        ClearFlowObservations();

        if (State is RelayGatewayState.Stopping or RelayGatewayState.Stopped)
            return;

        try
        {
            LastError = $"sing-box неожиданно завершился. Код: {_process?.ExitCode}.";
        }
        catch
        {
            LastError = "sing-box неожиданно завершился.";
        }

        SetState(RelayGatewayState.Failed);
    }

    private void SaveState(
        Process process,
        string executablePath,
        string interfaceName)
    {
        SessionProcessState state = new()
        {
            ProcessId = process.Id,
            ExecutablePath = executablePath,
            InterfaceName = interfaceName,
            StartedAtUtc = process.StartTime.ToUniversalTime()
        };

        File.WriteAllText(
            _statePath,
            JsonSerializer.Serialize(
                state,
                new JsonSerializerOptions { WriteIndented = true }));
    }

    private SessionProcessState? ReadState()
    {
        if (!File.Exists(_statePath))
            return null;

        try
        {
            return JsonSerializer.Deserialize<SessionProcessState>(
                File.ReadAllText(_statePath));
        }
        catch
        {
            return null;
        }
    }

    private bool TryGetStoredOwnedProcess(
        out Process? process,
        out SessionProcessState? state)
    {
        process = null;
        state = ReadState();
        if (state is null ||
            state.ProcessId <= 0 ||
            string.IsNullOrWhiteSpace(state.ExecutablePath))
        {
            return false;
        }

        try
        {
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
        if (!TryGetStoredOwnedProcess(out Process? process, out SessionProcessState? state) ||
            process is null)
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
            catch
            {
                // Best effort recovery of a Serpium-owned process only.
            }
        }

        DeleteStateFile();

        if (!string.IsNullOrWhiteSpace(state?.InterfaceName))
        {
            await WaitForInterfaceToDisappearAsync(
                state.InterfaceName,
                InterfaceStopTimeout,
                CancellationToken.None);
        }
    }

    private async Task KillCurrentProcessAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync(cancellationToken);
            }
        }
        catch
        {
            // Best effort cleanup only.
        }
        finally
        {
            _process?.Dispose();
            _process = null;
            CloseKillOnCloseJob();
        }
    }

    private void AttachProcessToKillOnCloseJob(Process process)
    {
        CloseKillOnCloseJob();

        try
        {
            SafeFileHandle jobHandle = CreateKillOnCloseJob();
            if (!AssignProcessToJobObject(jobHandle, process.Handle))
            {
                int error = Marshal.GetLastWin32Error();
                jobHandle.Dispose();
                LogReceived?.Invoke(
                    $"Kill-On-Close недоступен (Win32 {error}); используется штатное отключение.");
                return;
            }

            _killOnCloseJob = jobHandle;
            LogReceived?.Invoke("Аварийная очистка TUN Kill-On-Close активна.");
        }
        catch (Exception ex)
        {
            CloseKillOnCloseJob();
            LogReceived?.Invoke(
                "Kill-On-Close недоступен; используется штатное отключение (" +
                ex.GetType().Name + ").");
        }
    }

    private static SafeFileHandle CreateKillOnCloseJob()
    {
        SafeFileHandle jobHandle = CreateJobObject(IntPtr.Zero, null);
        if (jobHandle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        JobObjectExtendedLimitInformation information = new()
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose
            }
        };

        int informationLength = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        IntPtr informationPointer = Marshal.AllocHGlobal(informationLength);
        try
        {
            Marshal.StructureToPtr(information, informationPointer, false);
            if (!SetInformationJobObject(
                    jobHandle,
                    JobObjectExtendedLimitInformationClass,
                    informationPointer,
                    (uint)informationLength))
            {
                int error = Marshal.GetLastWin32Error();
                jobHandle.Dispose();
                throw new Win32Exception(error);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(informationPointer);
        }

        return jobHandle;
    }

    private void CloseKillOnCloseJob()
    {
        try
        {
            _killOnCloseJob?.Dispose();
        }
        catch
        {
            // Windows also closes process handles on application termination.
        }
        finally
        {
            _killOnCloseJob = null;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(
        IntPtr jobAttributes,
        string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle jobHandle,
        int informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(
        SafeFileHandle jobHandle,
        IntPtr processHandle);

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private static bool IsSameProcess(
        Process process,
        SessionProcessState state)
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

    private static bool IsCurrentProcessAdministrator()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private void DeleteStateFile()
    {
        try
        {
            File.Delete(_statePath);
        }
        catch
        {
            // State contains no key material; cleanup is best effort.
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
            if (HasLiveProcess || State != RelayGatewayState.Stopped)
                StopAsync().GetAwaiter().GetResult();
        }
        catch
        {
            // Best effort shutdown on application exit.
        }
        finally
        {
            CloseKillOnCloseJob();
        }

        _disposed = true;
        StopActiveConnectionMonitor();
        _process?.Dispose();
        _process = null;
        _clashApiClient.Dispose();
    }

    private sealed class SessionProcessState
    {
        public int ProcessId { get; init; }
        public string ExecutablePath { get; init; } = string.Empty;
        public string InterfaceName { get; init; } = string.Empty;
        public DateTime StartedAtUtc { get; init; }
    }
}
