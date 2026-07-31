namespace SerpiumVPN.Core;

/// <summary>
/// Kind of lifecycle notification emitted while a Relay gateway is starting or running.
/// </summary>
public enum RelayGatewayEventKind
{
    Status,
    AuthorizationRequired,
    AddressAssigned,
    Ready,
    Error
}
