namespace SerpiumVPN.Relay.Parser;

/// <summary>
/// Opaque provider-specific key container such as avo://profile-id:payload.
/// The payload stays in memory and must never be written to diagnostics.
/// </summary>
public sealed class ProviderEnvelope
{
    public required string Scheme { get; init; }
    public required string ProviderName { get; init; }
    public required string ProfileId { get; init; }
    public required string Payload { get; init; }
    public int PayloadByteCount { get; init; }

    public string DisplayScheme => Scheme.ToUpperInvariant();

    public string MaskedProfileId
    {
        get
        {
            if (string.IsNullOrWhiteSpace(ProfileId))
                return "—";
            if (ProfileId.Length <= 8)
                return new string('•', ProfileId.Length);

            return ProfileId[..4] + "…" + ProfileId[^4..];
        }
    }

    public override string ToString() =>
        $"{DisplayScheme} · {MaskedProfileId} · защищённый пакет {PayloadByteCount} Б";
}
