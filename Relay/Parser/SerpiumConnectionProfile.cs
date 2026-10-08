namespace SerpiumVPN.Relay.Parser;

/// <summary>
/// Normalized connection profile produced by Serpium Parser.
/// The original key is intentionally not stored here.
/// </summary>
public sealed class SerpiumConnectionProfile
{
    public required string Protocol { get; init; }
    public required string Server { get; init; }
    public required int Port { get; init; }

    public string Name { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public int AlterId { get; init; }
    public string Encryption { get; init; } = "none";

    public string Security { get; init; } = "none";
    public string Transport { get; init; } = "tcp";
    public string Flow { get; init; } = string.Empty;
    public string ServerName { get; init; } = string.Empty;
    public string Fingerprint { get; init; } = string.Empty;
    public string PublicKey { get; init; } = string.Empty;
    public string ShortId { get; init; } = string.Empty;
    public string SpiderX { get; init; } = string.Empty;
    public bool AllowInsecure { get; init; }

    public string Path { get; init; } = string.Empty;
    public string HostHeader { get; init; } = string.Empty;
    public string ServiceName { get; init; } = string.Empty;
    public string Mode { get; init; } = string.Empty;
    public System.Text.Json.JsonElement? XhttpExtra { get; init; }
    public string Obfuscation { get; init; } = string.Empty;
    public string ObfuscationPassword { get; init; } = string.Empty;
    public string HeaderType { get; init; } = string.Empty;
    public string Seed { get; init; } = string.Empty;
    public string PacketEncoding { get; init; } = string.Empty;
    public IReadOnlyList<string> Alpn { get; init; } = Array.Empty<string>();

    public string DisplayName => string.IsNullOrWhiteSpace(Name)
        ? $"{Protocol.ToUpperInvariant()} · {Server}:{Port}"
        : Name;
}
