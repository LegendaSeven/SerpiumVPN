using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN.Core;

/// <summary>
/// Coordinates the lifecycle of the Serpium platform and its registered components.
/// </summary>
public sealed class PlatformRuntime : IAsyncDisposable
{
    private readonly ComponentLoader _componentLoader;
    private readonly DynamicEngineLoader _dynamicEngineLoader;
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);
    private readonly Action<string>? _log;
    private bool _disposed;

    public PlatformRuntime(
        ComponentRegistry componentRegistry,
        EngineRegistry engineRegistry,
        ComponentLoader componentLoader,
        Action<string>? log = null)
        : this(
            componentRegistry,
            engineRegistry,
            componentLoader,
            new DynamicEngineLoader(
                engineRegistry,
                Path.Combine(AppContext.BaseDirectory, "Engines"),
                log),
            log)
    {
    }

    public PlatformRuntime(
        ComponentRegistry componentRegistry,
        EngineRegistry engineRegistry,
        ComponentLoader componentLoader,
        DynamicEngineLoader dynamicEngineLoader,
        Action<string>? log = null)
    {
        ComponentRegistry = componentRegistry
            ?? throw new ArgumentNullException(nameof(componentRegistry));
        EngineRegistry = engineRegistry
            ?? throw new ArgumentNullException(nameof(engineRegistry));
        _componentLoader = componentLoader
            ?? throw new ArgumentNullException(nameof(componentLoader));
        _dynamicEngineLoader = dynamicEngineLoader
            ?? throw new ArgumentNullException(nameof(dynamicEngineLoader));
        _log = log;
    }

    public ComponentRegistry ComponentRegistry { get; }

    public EngineRegistry EngineRegistry { get; }

    public string DynamicEngineDirectory => _dynamicEngineLoader.EngineRootDirectory;

    public EngineDiscoveryResult LastEngineDiscovery { get; private set; } =
        EngineDiscoveryResult.Empty;

    public PlatformRuntimeState State { get; private set; } = PlatformRuntimeState.Created;

    public bool IsRunning => State == PlatformRuntimeState.Running;

    public async Task<PlatformRuntimeStartResult> StartAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (State == PlatformRuntimeState.Running)
            {
                var current = new ComponentLoadResult(
                    ComponentRegistry.Count,
                    ComponentRegistry.Count,
                    0);

                return new PlatformRuntimeStartResult(State, current)
                {
                    DynamicEngines = LastEngineDiscovery
                };
            }

            if (State is PlatformRuntimeState.Starting or PlatformRuntimeState.Stopping)
            {
                throw new InvalidOperationException(
                    $"Platform runtime cannot start while it is {State}.");
            }

            State = PlatformRuntimeState.Starting;
            WriteLog("[Runtime] Starting Serpium platform.");

            LastEngineDiscovery = _dynamicEngineLoader.DiscoverAndRegister();

            if (!LastEngineDiscovery.IsSuccessful)
            {
                WriteLog(
                    $"[Runtime] Dynamic engine discovery completed with " +
                    $"{LastEngineDiscovery.Failed} failure(s); platform startup will continue.");
            }

            var componentResult = await _componentLoader
                .InitializeAllAsync(cancellationToken)
                .ConfigureAwait(false);

            State = componentResult.IsSuccessful
                ? PlatformRuntimeState.Running
                : PlatformRuntimeState.Faulted;

            WriteLog(
                $"[Runtime] Start completed. State={State}; Engines={EngineRegistry.Count}.");

            return new PlatformRuntimeStartResult(State, componentResult)
            {
                DynamicEngines = LastEngineDiscovery
            };
        }
        catch
        {
            State = PlatformRuntimeState.Faulted;
            WriteLog("[Runtime] Start failed.");
            throw;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (State is PlatformRuntimeState.Created or PlatformRuntimeState.Stopped)
            {
                State = PlatformRuntimeState.Stopped;
                return;
            }

            if (State == PlatformRuntimeState.Stopping)
            {
                return;
            }

            State = PlatformRuntimeState.Stopping;
            WriteLog("[Runtime] Stopping Serpium platform.");

            await _componentLoader
                .ShutdownAllAsync(cancellationToken)
                .ConfigureAwait(false);

            State = PlatformRuntimeState.Stopped;
            WriteLog("[Runtime] Serpium platform stopped.");
        }
        catch
        {
            State = PlatformRuntimeState.Faulted;
            WriteLog("[Runtime] Stop failed.");
            throw;
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        if (State is not PlatformRuntimeState.Created and
            not PlatformRuntimeState.Stopped)
        {
            await StopAsync().ConfigureAwait(false);
        }

        _disposed = true;
        _lifecycleLock.Dispose();
        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private void WriteLog(string message)
    {
        _log?.Invoke(message);
    }
}
