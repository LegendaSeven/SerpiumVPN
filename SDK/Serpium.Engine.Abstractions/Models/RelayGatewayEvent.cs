namespace SerpiumVPN.Core;

/// <summary>
/// UI-neutral progress message emitted by an IRelayGatewayEngine implementation.
/// </summary>
public sealed class RelayGatewayEvent
{
    public RelayGatewayEventKind Kind { get; init; }

    public string Message { get; init; } = string.Empty;

    /// <summary>
    /// Optional machine-readable value, such as an authorization URL or virtual address.
    /// </summary>
    public string? Value { get; init; }
}
