namespace SerpiumVPN.Core;

/// <summary>
/// Immutable metadata exposed by a Serpium component.
/// </summary>
public sealed class ComponentInfo
{
    public string Name { get; init; } = string.Empty;

    public string Version { get; init; } = string.Empty;

    public ComponentType Type { get; init; }
}
