using System;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN.Core;

/// <summary>
/// Initializes and shuts down components registered in <see cref="ComponentRegistry"/>.
/// Dynamic engine discovery is handled before initialization by <see cref="DynamicEngineLoader"/>.
/// </summary>
public sealed class ComponentLoader
{
    private readonly ComponentRegistry _registry;
    private readonly Action<string>? _log;

    public ComponentLoader(ComponentRegistry registry, Action<string>? log = null)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _log = log;
    }

    public async Task<ComponentLoadResult> InitializeAllAsync(
        CancellationToken cancellationToken = default)
    {
        int loaded = 0;
        int failed = 0;

        WriteLog($"[Components] Found: {_registry.Count}");

        foreach (var component in _registry.Components)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                WriteLog($"[Components] Initializing: {component.Info.Name} {component.Info.Version}");
                await component.InitializeAsync().ConfigureAwait(false);
                loaded++;
                WriteLog($"[Components] Loaded: {component.Info.Name}");
            }
            catch (Exception exception)
            {
                failed++;
                WriteLog($"[Components] Failed: {component.Info.Name}: {exception.Message}");
            }
        }

        var result = new ComponentLoadResult(_registry.Count, loaded, failed);
        WriteLog($"[Components] Summary: found={result.Found}, loaded={result.Loaded}, failed={result.Failed}");
        return result;
    }

    public async Task ShutdownAllAsync(CancellationToken cancellationToken = default)
    {
        for (int index = _registry.Components.Count - 1; index >= 0; index--)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var component = _registry.Components[index];

            try
            {
                WriteLog($"[Components] Shutting down: {component.Info.Name}");
                await component.ShutdownAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                WriteLog($"[Components] Shutdown failed: {component.Info.Name}: {exception.Message}");
            }
        }
    }

    private void WriteLog(string message)
    {
        _log?.Invoke(message);
    }
}
