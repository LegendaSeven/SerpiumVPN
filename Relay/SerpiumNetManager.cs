using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SerpiumVPN.Core;
using SerpiumVPN.Core.Interfaces;

namespace SerpiumVPN.Relay;

/// <summary>
/// WPF-compatible adapter that preserves the existing Relay API while delegating
/// the native SerpiumNet lifecycle to the dynamically loaded external engine.
/// Browser authorization windows are intentionally not used: enrollment is handled
/// headlessly by Headscale and a one-time auth key.
/// </summary>
public sealed class SerpiumNetManager : IAsyncDisposable
{
    private const string EngineName = "SerpiumNet";
    private static readonly TimeSpan StopSynchronizationTimeout = TimeSpan.FromSeconds(8);

    private readonly object _sync = new();
    private IRelayGatewayEngine? _gatewayEngine;
    private CancellationTokenSource? _connectionCts;
    private TaskCompletionSource<bool>? _startCompletion;
    private bool _disposed;

    public bool HasLiveProcess
    {
        get
        {
            lock (_sync)
            {
                return _gatewayEngine?.HasLiveGatewayProcess == true;
            }
        }
    }

    public async Task<string> StartGatewayAsync(
        Window owner,
        int port,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ThrowIfDisposed();

        // Preserve the existing public signature for MainWindow, but Headscale
        // enrollment is fully headless and does not need an owner window.
        _ = owner;

        await StopAsync().ConfigureAwait(false);

        IRelayGatewayEngine engine = ResolveGatewayEngine();
        var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var completion = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var progress = new Progress<RelayGatewayEvent>(HandleGatewayEvent);

        lock (_sync)
        {
            _gatewayEngine = engine;
            _connectionCts = linkedCts;
            _startCompletion = completion;
        }

        bool started = false;

        try
        {
            RelayGatewayStartResult result = await engine
                .StartGatewayAsync(port, progress, linkedCts.Token)
                .ConfigureAwait(false);

            started = true;
            return result.VirtualAddress;
        }
        catch (OperationCanceledException)
        {
            await StopEngineSafelyAsync(engine).ConfigureAwait(false);
            throw;
        }
        catch
        {
            await StopEngineSafelyAsync(engine).ConfigureAwait(false);
            throw;
        }
        finally
        {
            lock (_sync)
            {
                if (ReferenceEquals(_connectionCts, linkedCts))
                {
                    _connectionCts = null;
                }

                if (!started && ReferenceEquals(_gatewayEngine, engine))
                {
                    _gatewayEngine = null;
                }

                if (ReferenceEquals(_startCompletion, completion))
                {
                    _startCompletion = null;
                }
            }

            completion.TrySetResult(true);
            linkedCts.Dispose();
        }
    }

    public async Task StopAsync()
    {
        CancellationTokenSource? connectionCts;
        IRelayGatewayEngine? engine;
        Task? activeStartTask;

        lock (_sync)
        {
            connectionCts = _connectionCts;
            _connectionCts = null;

            engine = _gatewayEngine;
            _gatewayEngine = null;

            activeStartTask = _startCompletion?.Task;
        }

        try
        {
            connectionCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Startup finished while shutdown was being requested.
        }

        if (engine is not null)
        {
            await StopEngineSafelyAsync(engine).ConfigureAwait(false);
        }

        // Let the concurrently awaited StartGatewayAsync unwind before the Stop
        // button handler returns. This prevents the old "SerpiumNet: connecting"
        // text from winning a UI race after the process has already stopped.
        if (activeStartTask is not null && !activeStartTask.IsCompleted)
        {
            try
            {
                await activeStartTask
                    .WaitAsync(StopSynchronizationTimeout)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                // The process has already been stopped; do not freeze the UI if a
                // caller keeps its startup continuation blocked for another reason.
            }
        }

        connectionCts?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private static IRelayGatewayEngine ResolveGatewayEngine()
    {
        PlatformRuntime runtime = PlatformRuntimeHost.Current
            ?? throw new InvalidOperationException(
                "Serpium platform runtime is not available. Restart SerpiumVPN and try again.");

        IEngine engine = runtime.EngineRegistry.GetRequired(EngineName);

        if (engine is not IRelayGatewayEngine gatewayEngine)
        {
            throw new NotSupportedException(
                "The loaded SerpiumNet engine does not expose the Relay gateway capability. " +
                "Rebuild and reinstall the MVP6.1.2 engine package.");
        }

        return gatewayEngine;
    }

    private static void HandleGatewayEvent(RelayGatewayEvent gatewayEvent)
    {
        // The existing MainWindow already derives its visible status from the
        // awaited Start/Stop calls. AuthorizationRequired is deliberately not
        // surfaced as a window: the engine converts it into a headless-mode error.
        _ = gatewayEvent;
    }

    private static async Task StopEngineSafelyAsync(IRelayGatewayEngine engine)
    {
        try
        {
            await engine.StopGatewayAsync().ConfigureAwait(false);
        }
        catch
        {
            // Relay cleanup must not mask the original startup/cancellation error.
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
