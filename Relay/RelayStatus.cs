namespace SerpiumVPN.Relay;

public enum RelayStatus
{
    NotConfigured,
    KeyReady,
    KeyValid,
    InvalidKey,
    Connecting,
    Connected,
    Error
}
