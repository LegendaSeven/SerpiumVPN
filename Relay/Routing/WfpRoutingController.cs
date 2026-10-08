using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Product-side owner for the Serpium.Flow WFP-4A control plane.
/// It keeps kernel policy updates atomic and owns the guarded TCP/UDP bridge process.
/// </summary>
public sealed class WfpRoutingController : IDisposable
{
    private const int MaximumApplicationPaths = 128;
    private const int MaximumDomainRules = 512;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan BridgeStartTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan BridgeStopTimeout = TimeSpan.FromSeconds(4);

    private static readonly HashSet<string> ForbiddenProcessNames = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "SerpiumVPN.exe",
        "Serpium.Flow.Service.exe",
        "sing-box.exe",
        "xray.exe",
        "xray-client.exe",
        "xray-key-client.exe",
        "SerpiumNet.exe"
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<int>> _domainPolicyAcks = new();
    private Process? _bridgeProcess;
    private string? _servicePath;
    private bool? _batchReplaceSupported;
    private bool _udpAppRoutingSupported;
    private bool _quicTcpFallbackSupported;
    private HashSet<string> _appliedApplicationPaths = new(
        StringComparer.OrdinalIgnoreCase);
    private DomainPolicyRule[] _domainPolicyRules = Array.Empty<DomainPolicyRule>();
    private long _domainPolicySequence;
    private bool _disposed;

    public event Action<string>? LogReceived;

    public bool IsBridgeRunning =>
        _bridgeProcess is { HasExited: false };

    public string? LastError { get; private set; }

    public bool SupportsUdpApplicationRouting => _udpAppRoutingSupported;

    public bool SupportsQuicTcpFallback => _quicTcpFallbackSupported;

    public WfpProductReadinessSnapshot GetProductReadiness(
        bool force = false) =>
        WfpProductReadiness.Inspect(force);

    public async Task<WfpAvailabilityResult> CheckAvailabilityAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        WfpProductReadinessSnapshot readiness =
            WfpProductReadiness.Inspect(force: true);

        // A packaged runtime is the product path. Do not execute its user-mode
        // service until Serpium can prove that the production driver belongs to
        // this exact runtime payload. Legacy developer fallbacks remain
        // available only when no packaged runtime exists at all.
        if (readiness.PackagePresent && !readiness.CanUseWfp)
        {
            LastError = readiness.Detail;
            return new WfpAvailabilityResult(
                false,
                readiness.Summary + " " + readiness.Detail);
        }

        string? servicePath = ResolveServicePath();
        if (servicePath is null)
        {
            return new WfpAvailabilityResult(
                false,
                LastError ??
                "Serpium.Flow.Service.exe не найден. WFP runtime будет доступен после упаковки native-компонента.");
        }

        WfpCommandResult status = await RunCommandAsync(
            servicePath,
            ["status"],
            CommandTimeout,
            cancellationToken);

        if (status.ExitCode != 0 ||
            !status.StandardOutput.Contains(
                "SERPIUM_WFP4A_ROUTE_CORE_READY",
                StringComparison.Ordinal))
        {
            string reason = FirstUsefulLine(status.StandardError)
                ?? FirstUsefulLine(status.StandardOutput)
                ?? "WFP-4A driver пока недоступен.";

            return new WfpAvailabilityResult(false, reason);
        }

        _servicePath = servicePath;
        _udpAppRoutingSupported = status.StandardOutput.Contains(
            "SERPIUM_WFP4A_UDP_APP_ROUTING_READY",
            StringComparison.Ordinal);
        _quicTcpFallbackSupported = status.StandardOutput.Contains(
            "SERPIUM_WFP4A_QUIC_TCP_FALLBACK_READY",
            StringComparison.Ordinal);
        return new WfpAvailabilityResult(
            true,
            _quicTcpFallbackSupported
                ? "WFP-4A TCP/UDP route core + QUIC→TCP fallback готов."
                : _udpAppRoutingSupported
                    ? "WFP-4A TCP/UDP route core готов; QUIC fallback появится после обновления native runtime."
                    : "WFP-4A TCP route core готов; UDP app routing появится после обновления native runtime.");
    }

    public async Task<WfpRuleSyncResult> SyncApplicationRulesAsync(
        IReadOnlyList<RoutingRegistryEntry> entries,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(entries);

        string servicePath = _servicePath
            ?? ResolveServicePath()
            ?? throw new InvalidOperationException(
                "Serpium.Flow.Service.exe не найден.");

        DomainPolicyRule[] domainRules = CollectEnabledDomainRules(entries);
        ReplaceDomainPolicySnapshot(domainRules);

        string[] paths = CollectEnabledApplicationPaths(entries);
        if (paths.Length > MaximumApplicationPaths)
        {
            throw new InvalidOperationException(
                $"WFP поддерживает максимум {MaximumApplicationPaths} EXE в одной policy generation.");
        }

        int estimatedCommandLength =
            servicePath.Length +
            " sync-vpn-rules ".Length +
            paths.Sum(path => path.Length + 3);

        if (estimatedCommandLength > 28000)
        {
            throw new InvalidOperationException(
                "Список EXE слишком длинный для безопасной передачи WFP policy.");
        }

        if (_batchReplaceSupported != false)
        {
            List<string> arguments = new(paths.Length + 1)
            {
                "sync-vpn-rules"
            };
            arguments.AddRange(paths);

            WfpCommandResult batchResult = await RunCommandAsync(
                servicePath,
                arguments,
                CommandTimeout,
                cancellationToken);

            if (batchResult.ExitCode == 0 &&
                batchResult.StandardOutput.Contains(
                    "SERPIUM_WFP4A_SYNC_RULES_PASS",
                    StringComparison.Ordinal))
            {
                _batchReplaceSupported = true;
                ReplaceAppliedPathSnapshot(paths);

                WfpRuleSyncResult result = ParseRuleSyncResult(
                    batchResult.StandardOutput,
                    paths);
                await PushDomainPolicyIfBridgeRunningAsync(cancellationToken);
                LogRuleSync(result, atomic: true);
                return result;
            }

            _batchReplaceSupported = false;
            LogReceived?.Invoke(
                "WFP atomic replace недоступен на текущем native runtime; " +
                "используем совместимый delta-update без clear-rules в активном bridge.");
        }

        WfpRuleSyncResult legacyResult = await SyncApplicationRulesCompatibleAsync(
            servicePath,
            paths,
            cancellationToken);
        await PushDomainPolicyIfBridgeRunningAsync(cancellationToken);
        LogRuleSync(legacyResult, atomic: false);
        return legacyResult;
    }

    private async Task<WfpRuleSyncResult> SyncApplicationRulesCompatibleAsync(
        string servicePath,
        string[] desiredPaths,
        CancellationToken cancellationToken)
    {
        HashSet<string> desired = new(
            desiredPaths,
            StringComparer.OrdinalIgnoreCase);

        int generation = 0;
        int ruleCount = _appliedApplicationPaths.Count;

        // Before the bridge is armed there is no enforced route, so a clean
        // reset is safe and removes any stale policy left by an older service.
        if (!IsBridgeRunning)
        {
            WfpCommandResult clear = await RunCommandAsync(
                servicePath,
                ["clear-rules"],
                CommandTimeout,
                cancellationToken);
            EnsureMutationSucceeded(clear, "SERPIUM_WFP4A_CLEAR_RULES_PASS");
            generation = ParseInt(clear.StandardOutput, @"(?im)^Policy generation:\s*(\d+)\s*$");
            ruleCount = ParseInt(clear.StandardOutput, @"(?im)^Rules:\s*(\d+)/\d+\s*$");

            _appliedApplicationPaths.Clear();

            foreach (string path in desiredPaths)
            {
                WfpCommandResult add = await RunCommandAsync(
                    servicePath,
                    ["add-rule", "VPN", path],
                    CommandTimeout,
                    cancellationToken);
                EnsureMutationSucceeded(add, "SERPIUM_WFP4A_ADD_RULE_PASS");
                generation = ParseInt(add.StandardOutput, @"(?im)^Policy generation:\s*(\d+)\s*$");
                ruleCount = ParseInt(add.StandardOutput, @"(?im)^Rules:\s*(\d+)/\d+\s*$");
                _appliedApplicationPaths.Add(path);
            }

            return new WfpRuleSyncResult(
                generation,
                ruleCount,
                desiredPaths);
        }

        string[] additions = desired
            .Except(_appliedApplicationPaths, StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        string[] removals = _appliedApplicationPaths
            .Except(desired, StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // Add first, remove second. This avoids a transient empty ruleset
        // (which means Full Tunnel) while moving between two Split policies.
        foreach (string path in additions)
        {
            WfpCommandResult add = await RunCommandAsync(
                servicePath,
                ["add-rule", "VPN", path],
                CommandTimeout,
                cancellationToken);
            EnsureMutationSucceeded(add, "SERPIUM_WFP4A_ADD_RULE_PASS");
            generation = ParseInt(add.StandardOutput, @"(?im)^Policy generation:\s*(\d+)\s*$");
            ruleCount = ParseInt(add.StandardOutput, @"(?im)^Rules:\s*(\d+)/\d+\s*$");
            _appliedApplicationPaths.Add(path);
        }

        foreach (string path in removals)
        {
            WfpCommandResult remove = await RunCommandAsync(
                servicePath,
                ["remove-rule", path],
                CommandTimeout,
                cancellationToken);
            EnsureMutationSucceeded(remove, "SERPIUM_WFP4A_REMOVE_RULE_PASS");
            generation = ParseInt(remove.StandardOutput, @"(?im)^Policy generation:\s*(\d+)\s*$");
            ruleCount = ParseInt(remove.StandardOutput, @"(?im)^Rules:\s*(\d+)/\d+\s*$");
            _appliedApplicationPaths.Remove(path);
        }

        if (additions.Length == 0 && removals.Length == 0)
        {
            WfpCommandResult status = await RunCommandAsync(
                servicePath,
                ["status"],
                CommandTimeout,
                cancellationToken);
            if (status.ExitCode != 0)
                throw CreateCommandFailure(status, "WFP status недоступен.");

            generation = ParseInt(status.StandardOutput, @"(?im)^Policy generation:\s*(\d+)\s*$");
            ruleCount = ParseInt(status.StandardOutput, @"(?im)^Rules:\s*(\d+)/\d+\s*$");
        }

        return new WfpRuleSyncResult(
            generation,
            ruleCount,
            desiredPaths);
    }

    private static void EnsureMutationSucceeded(
        WfpCommandResult result,
        string successMarker)
    {
        if (result.ExitCode == 0 &&
            result.StandardOutput.Contains(successMarker, StringComparison.Ordinal))
        {
            return;
        }

        throw CreateCommandFailure(
            result,
            "WFP policy mutation не была применена.");
    }

    private static InvalidOperationException CreateCommandFailure(
        WfpCommandResult result,
        string fallback) =>
        new(
            FirstUsefulLine(result.StandardError)
            ?? FirstUsefulLine(result.StandardOutput)
            ?? fallback);

    private static WfpRuleSyncResult ParseRuleSyncResult(
        string output,
        string[] paths)
    {
        int generation = ParseInt(
            output,
            @"(?im)^Policy generation:\s*(\d+)\s*$");
        int ruleCount = ParseInt(
            output,
            @"(?im)^Rules:\s*(\d+)/\d+\s*$");

        return new WfpRuleSyncResult(
            generation,
            ruleCount,
            paths);
    }

    private void ReplaceAppliedPathSnapshot(IEnumerable<string> paths)
    {
        _appliedApplicationPaths = new HashSet<string>(
            paths,
            StringComparer.OrdinalIgnoreCase);
    }

    private void LogRuleSync(WfpRuleSyncResult result, bool atomic)
    {
        string mode = atomic ? "atomic replace" : "compatible delta";
        int domainCount = _domainPolicyRules.Length;
        string transportScope = _udpAppRoutingSupported
            ? "TCP + UDP"
            : "TCP";
        LogReceived?.Invoke(
            domainCount > 0
                ? $"WFP {mode}, generation {result.PolicyGeneration}: VPN EXE {result.RuleCount} получают {transportScope}; domain exact/suffix {domainCount} применяются к TCP Host/SNI; остальное DIRECT."
                : result.ApplicationPaths.Count == 0
                    ? $"WFP {mode}, generation {result.PolicyGeneration}: Full Tunnel для новых {transportScope} flows."
                    : $"WFP {mode}, generation {result.PolicyGeneration}: VPN EXE {result.RuleCount} получают {transportScope}; остальные новые flows DIRECT.");
    }

    public async Task StartBridgeAsync(
        int socksPort,
        IEnumerable<int> backendProcessIds,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (socksPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(socksPort));

        ArgumentNullException.ThrowIfNull(backendProcessIds);

        int[] bypassProcessIds = backendProcessIds
            .Append(Environment.ProcessId)
            .Where(processId => processId > 0)
            .Distinct()
            .ToArray();

        if (bypassProcessIds.Length == 0 || bypassProcessIds.Length > 8)
        {
            throw new InvalidOperationException(
                "WFP bridge требует 1..8 уникальных bypass PID.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (IsBridgeRunning)
                throw new InvalidOperationException("WFP bridge уже запущен.");

            WfpAvailabilityResult availability =
                await CheckAvailabilityAsync(cancellationToken);
            if (!availability.Available)
                throw new InvalidOperationException(availability.Message);

            string servicePath = _servicePath
                ?? throw new InvalidOperationException(
                    "WFP service path не определён.");

            ProcessStartInfo startInfo = new()
            {
                FileName = servicePath,
                WorkingDirectory = Path.GetDirectoryName(servicePath)
                    ?? AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(false),
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            startInfo.ArgumentList.Add("bridge-domain");
            startInfo.ArgumentList.Add(
                socksPort.ToString(CultureInfo.InvariantCulture));
            foreach (int processId in bypassProcessIds)
            {
                startInfo.ArgumentList.Add(
                    processId.ToString(CultureInfo.InvariantCulture));
            }

            Process bridge = new()
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            TaskCompletionSource<bool> ready = new(
                TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource<int> exited = new(
                TaskCreationOptions.RunContinuationsAsynchronously);

            bridge.OutputDataReceived += (_, eventArgs) =>
            {
                string? line = eventArgs.Data;
                if (string.IsNullOrWhiteSpace(line))
                    return;

                LogReceived?.Invoke("WFP: " + line);

                Match policyAck = Regex.Match(
                    line.Trim(),
                    @"^SERPIUM_WFP4A_DOMAIN_POLICY_APPLIED\s+(\d+)\s+(\d+)$",
                    RegexOptions.CultureInvariant);
                if (policyAck.Success &&
                    long.TryParse(
                        policyAck.Groups[1].Value,
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out long policySequence) &&
                    int.TryParse(
                        policyAck.Groups[2].Value,
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out int policyCount) &&
                    _domainPolicyAcks.TryRemove(policySequence, out TaskCompletionSource<int>? ack))
                {
                    ack.TrySetResult(policyCount);
                }

                if (string.Equals(
                        line.Trim(),
                        "SERPIUM_WFP4A_UDP_APP_ROUTING_ACTIVE",
                        StringComparison.Ordinal))
                {
                    _udpAppRoutingSupported = true;
                }
                else if (string.Equals(
                             line.Trim(),
                             "SERPIUM_WFP4A_UDP_APP_ROUTING_UNAVAILABLE",
                             StringComparison.Ordinal))
                {
                    _udpAppRoutingSupported = false;
                }

                if (string.Equals(
                        line.Trim(),
                        "SERPIUM_WFP4A_BRIDGE_READY",
                        StringComparison.Ordinal))
                {
                    ready.TrySetResult(true);
                }
            };
            bridge.ErrorDataReceived += (_, eventArgs) =>
            {
                if (!string.IsNullOrWhiteSpace(eventArgs.Data))
                    LogReceived?.Invoke("WFP: " + eventArgs.Data);
            };
            bridge.Exited += (_, _) =>
            {
                int exitCode;
                try
                {
                    exitCode = bridge.ExitCode;
                }
                catch
                {
                    exitCode = -1;
                }

                exited.TrySetResult(exitCode);
            };

            if (!bridge.Start())
                throw new InvalidOperationException("Не удалось запустить WFP bridge.");

            bridge.BeginOutputReadLine();
            bridge.BeginErrorReadLine();

            Task timeout = Task.Delay(
                BridgeStartTimeout,
                cancellationToken);
            Task completed = await Task.WhenAny(
                ready.Task,
                exited.Task,
                timeout);

            if (completed == ready.Task && ready.Task.Result)
            {
                _bridgeProcess = bridge;
                try
                {
                    await SendDomainPolicyAsync(bridge, cancellationToken);
                    LastError = null;
                    return;
                }
                catch
                {
                    _bridgeProcess = null;
                    try
                    {
                        if (!bridge.HasExited)
                            bridge.Kill(entireProcessTree: true);
                    }
                    catch
                    {
                    }
                    throw;
                }
            }

            string reason;
            if (completed == exited.Task)
            {
                reason = $"WFP bridge завершился до READY, код {exited.Task.Result}.";
            }
            else if (cancellationToken.IsCancellationRequested)
            {
                reason = "Запуск WFP bridge отменён.";
            }
            else
            {
                reason = "WFP bridge не подтвердил READY вовремя.";
            }

            try
            {
                if (!bridge.HasExited)
                    bridge.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            bridge.Dispose();
            LastError = reason;
            throw new InvalidOperationException(reason);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopBridgeAsync(
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
            return;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            Process? bridge = _bridgeProcess;
            _bridgeProcess = null;

            if (bridge is null)
                return;

            try
            {
                if (!bridge.HasExited)
                {
                    string? servicePath = _servicePath ?? ResolveServicePath();
                    if (servicePath is not null)
                    {
                        await RunCommandAsync(
                            servicePath,
                            ["disarm-route"],
                            CommandTimeout,
                            cancellationToken);
                    }

                    using CancellationTokenSource stopCts =
                        CancellationTokenSource.CreateLinkedTokenSource(
                            cancellationToken);
                    stopCts.CancelAfter(BridgeStopTimeout);

                    try
                    {
                        await bridge.WaitForExitAsync(stopCts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        if (!bridge.HasExited)
                            bridge.Kill(entireProcessTree: true);
                    }
                }
            }
            finally
            {
                bridge.Dispose();
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static DomainPolicyRule[] CollectEnabledDomainRules(
        IReadOnlyList<RoutingRegistryEntry> entries)
    {
        List<DomainPolicyRule> result = new();

        foreach (RoutingRegistryEntry entry in entries
                     .Where(item =>
                         item.IsEnabled &&
                         item.Kind == RoutingTargetKind.Website)
                     .OrderBy(item => item.Id))
        {
            string domain = SecureRoutingRegistry.NormalizeDomain(
                entry.PrimaryValue);

            DomainPolicyRule exact = new(domain, false);
            if (!result.Contains(exact))
                result.Add(exact);

            if (entry.IncludeSubdomains)
            {
                DomainPolicyRule suffix = new(domain, true);
                if (!result.Contains(suffix))
                    result.Add(suffix);
            }
        }

        if (result.Count > MaximumDomainRules)
        {
            throw new InvalidOperationException(
                $"WFP domain bridge поддерживает максимум {MaximumDomainRules} exact/suffix правил.");
        }

        return result.ToArray();
    }

    private void ReplaceDomainPolicySnapshot(
        DomainPolicyRule[] rules)
    {
        _domainPolicyRules = rules.ToArray();
    }

    private async Task PushDomainPolicyIfBridgeRunningAsync(
        CancellationToken cancellationToken)
    {
        Process? bridge = _bridgeProcess;
        if (bridge is null || bridge.HasExited)
            return;

        await SendDomainPolicyAsync(bridge, cancellationToken);
    }

    private async Task SendDomainPolicyAsync(
        Process bridge,
        CancellationToken cancellationToken)
    {
        if (bridge.HasExited)
            throw new InvalidOperationException("WFP domain bridge уже остановлен.");

        DomainPolicyRule[] rules = _domainPolicyRules.ToArray();
        long sequence = Interlocked.Increment(ref _domainPolicySequence);
        TaskCompletionSource<int> ack = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_domainPolicyAcks.TryAdd(sequence, ack))
            throw new InvalidOperationException("Не удалось зарегистрировать WFP domain policy update.");

        try
        {
            await bridge.StandardInput.WriteLineAsync(
                $"POLICY {sequence.ToString(CultureInfo.InvariantCulture)}");
            foreach (DomainPolicyRule rule in rules)
            {
                await bridge.StandardInput.WriteLineAsync(
                    $"{(rule.IncludeSubdomains ? "S" : "E")} {rule.Domain}");
            }
            await bridge.StandardInput.WriteLineAsync("APPLY");
            await bridge.StandardInput.FlushAsync(cancellationToken);

            Task timeout = Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
            Task completed = await Task.WhenAny(ack.Task, timeout);
            if (completed != ack.Task)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new InvalidOperationException(
                    "WFP domain bridge не подтвердил обновление policy.");
            }

            int appliedCount = await ack.Task;
            if (appliedCount != rules.Length)
            {
                throw new InvalidOperationException(
                    $"WFP domain bridge подтвердил {appliedCount} правил вместо {rules.Length}.");
            }

            LogReceived?.Invoke(
                appliedCount == 0
                    ? "WFP domain policy: сайтов нет; bridge использует app/full-tunnel policy."
                    : $"WFP domain policy: применено {appliedCount} exact/suffix правил без reconnect Relay.");
        }
        finally
        {
            _domainPolicyAcks.TryRemove(sequence, out _);
        }
    }

    private static string[] CollectEnabledApplicationPaths(
        IReadOnlyList<RoutingRegistryEntry> entries)
    {
        List<string> result = new();

        foreach (RoutingRegistryEntry entry in entries
                     .Where(item =>
                         item.IsEnabled &&
                         item.Kind == RoutingTargetKind.Application)
                     .OrderBy(item => item.Id))
        {
            IEnumerable<string> candidates =
                entry.RelatedExecutables.Length > 0
                    ? entry.RelatedExecutables
                    : [entry.PrimaryValue];

            int before = result.Count;

            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate))
                    continue;

                string fullPath;
                try
                {
                    fullPath = Path.GetFullPath(
                        candidate.Trim().Trim('"'));
                }
                catch
                {
                    continue;
                }

                if (!File.Exists(fullPath) ||
                    !string.Equals(
                        Path.GetExtension(fullPath),
                        ".exe",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string fileName = Path.GetFileName(fullPath);
                if (ForbiddenProcessNames.Contains(fileName))
                {
                    throw new InvalidOperationException(
                        $"Карточка «{entry.DisplayName}» содержит служебный процесс Serpium ({fileName}).");
                }

                if (!result.Contains(
                        fullPath,
                        StringComparer.OrdinalIgnoreCase))
                {
                    result.Add(fullPath);
                }
            }

            if (result.Count == before)
            {
                throw new InvalidOperationException(
                    $"Для включённой карточки «{entry.DisplayName}» не найден доступный EXE.");
            }
        }

        result.Sort(StringComparer.OrdinalIgnoreCase);
        return result.ToArray();
    }

    private string? ResolveServicePath()
    {
        if (!string.IsNullOrWhiteSpace(_servicePath) &&
            File.Exists(_servicePath))
        {
            return _servicePath;
        }

        WfpRuntimeResolution packaged =
            WfpRuntimeOwner.ResolvePackagedRuntime();
        if (packaged.Available &&
            !string.IsNullOrWhiteSpace(
                packaged.ServiceExecutablePath))
        {
            _servicePath = packaged.ServiceExecutablePath;
            LastError = null;
            return _servicePath;
        }

        // Once a packaged runtime exists it is authoritative. A damaged or
        // partial product payload must not silently fall back to a developer
        // artifact elsewhere on disk.
        if (packaged.PackagePresent)
        {
            LastError = packaged.Message;
            return null;
        }

        List<string> candidates = new();

        string programFiles = Environment.GetFolderPath(
            Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            candidates.Add(
                Path.Combine(
                    programFiles,
                    "Serpium",
                    "Flow",
                    "WFP4A",
                    "Service",
                    "Serpium.Flow.Service.exe"));
        }

        candidates.Add(
            Path.Combine(
                AppContext.BaseDirectory,
                "Serpium.Flow.Service.exe"));

        // Developer-tree fallback is intentionally kept only when no packaged
        // runtime exists. Release/publish builds use bin_files\wfp\x64.
        DirectoryInfo? current = new(
            Path.TrimEndingDirectorySeparator(
                AppContext.BaseDirectory));
        for (int depth = 0; depth < 7 && current is not null; depth++)
        {
            candidates.Add(
                Path.Combine(
                    current.FullName,
                    "Native",
                    "Serpium.Flow",
                    "artifacts",
                    "x64",
                    "Release",
                    "package",
                    "Serpium.Flow.Service.exe"));
            current = current.Parent;
        }

        _servicePath = candidates
            .Select(path =>
            {
                try
                {
                    return Path.GetFullPath(path);
                }
                catch
                {
                    return string.Empty;
                }
            })
            .FirstOrDefault(File.Exists);

        LastError = _servicePath is null
            ? "Packaged WFP runtime отсутствует, developer runtime тоже не найден."
            : null;

        return _servicePath;
    }

    private static async Task<WfpCommandResult> RunCommandAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = executablePath,
            WorkingDirectory = Path.GetDirectoryName(executablePath)
                ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using Process process = new()
        {
            StartInfo = startInfo
        };

        if (!process.Start())
        {
            return new WfpCommandResult(
                -1,
                string.Empty,
                "Не удалось запустить Serpium.Flow.Service.exe.");
        }

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();

        using CancellationTokenSource timeoutCts =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            if (cancellationToken.IsCancellationRequested)
                throw;

            return new WfpCommandResult(
                -1,
                await stdoutTask,
                "Serpium.Flow command timeout.");
        }

        string stdout = await stdoutTask;
        string stderr = await stderrTask;
        return new WfpCommandResult(
            process.ExitCode,
            stdout,
            stderr);
    }

    private static int ParseInt(
        string text,
        string pattern)
    {
        Match match = Regex.Match(
            text,
            pattern,
            RegexOptions.CultureInvariant);

        return match.Success &&
               int.TryParse(
                   match.Groups[1].Value,
                   NumberStyles.None,
                   CultureInfo.InvariantCulture,
                   out int value)
            ? value
            : 0;
    }

    private static string? FirstUsefulLine(string? text) =>
        text?
            .Split(
                ['\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries |
                StringSplitOptions.TrimEntries)
            .FirstOrDefault();

    public void Dispose()
    {
        if (_disposed)
            return;

        try
        {
            StopBridgeAsync().GetAwaiter().GetResult();
        }
        catch
        {
        }

        foreach (TaskCompletionSource<int> ack in _domainPolicyAcks.Values)
            ack.TrySetCanceled();
        _domainPolicyAcks.Clear();

        _disposed = true;
        _gate.Dispose();
    }

    private sealed record DomainPolicyRule(
        string Domain,
        bool IncludeSubdomains);

    private sealed record WfpCommandResult(
        int ExitCode,
        string StandardOutput,
        string StandardError);
}

public sealed record WfpAvailabilityResult(
    bool Available,
    string Message);

public sealed record WfpRuleSyncResult(
    int PolicyGeneration,
    int RuleCount,
    IReadOnlyList<string> ApplicationPaths);
