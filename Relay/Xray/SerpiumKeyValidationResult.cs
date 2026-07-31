namespace SerpiumVPN.Relay.Xray;

public sealed class SerpiumKeyValidationResult
{
    public required bool ConfigValid { get; init; }
    public required bool ServerReachable { get; init; }
    public required string Message { get; init; }
}
