namespace SerpiumVPN.Core;

/// <summary>
/// Result returned after a Relay gateway has become reachable on the virtual network.
/// </summary>
public sealed class RelayGatewayStartResult
{
    public string VirtualAddress { get; init; } = string.Empty;

    public int Port { get; init; }
}
