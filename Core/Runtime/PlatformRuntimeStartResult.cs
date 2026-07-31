namespace SerpiumVPN.Core;

/// <summary>
/// Result of starting the platform runtime and initializing registered components.
/// </summary>
public sealed record PlatformRuntimeStartResult(
    PlatformRuntimeState State,
    ComponentLoadResult Components)
{
    public EngineDiscoveryResult DynamicEngines { get; init; } =
        EngineDiscoveryResult.Empty;

    public bool IsSuccessful =>
        State == PlatformRuntimeState.Running && Components.IsSuccessful;

    public bool HasEngineLoadFailures => DynamicEngines.Failed > 0;
}
