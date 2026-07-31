using System;

namespace SerpiumVPN.Core;

/// <summary>
/// Exposes the runtime created by the WPF host to legacy application adapters.
/// External engines remain unaware of this host-side bridge.
/// </summary>
public static class PlatformRuntimeHost
{
    private static readonly object Sync = new();
    private static PlatformRuntime? _current;

    public static PlatformRuntime? Current
    {
        get
        {
            lock (Sync)
            {
                return _current;
            }
        }
    }

    public static void Attach(PlatformRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        lock (Sync)
        {
            if (_current is not null && !ReferenceEquals(_current, runtime))
            {
                throw new InvalidOperationException(
                    "A Serpium platform runtime is already attached to this process.");
            }

            _current = runtime;
        }
    }

    public static void Detach(PlatformRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        lock (Sync)
        {
            if (ReferenceEquals(_current, runtime))
            {
                _current = null;
            }
        }
    }
}
