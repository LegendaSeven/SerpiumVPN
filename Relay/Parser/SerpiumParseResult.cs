namespace SerpiumVPN.Relay.Parser;

public sealed class SerpiumParseResult
{
    private SerpiumParseResult(
        bool success,
        SerpiumConnectionProfile? profile,
        ProviderEnvelope? envelope,
        string error)
    {
        Success = success;
        Profile = profile;
        Envelope = envelope;
        Error = error;
    }

    public bool Success { get; }
    public SerpiumConnectionProfile? Profile { get; }
    public ProviderEnvelope? Envelope { get; }
    public string Error { get; }

    public bool IsConnectionProfile => Profile is not null;
    public bool IsProviderEnvelope => Envelope is not null;

    public static SerpiumParseResult Ok(SerpiumConnectionProfile profile) =>
        new(true, profile, null, string.Empty);

    public static SerpiumParseResult Provider(ProviderEnvelope envelope) =>
        new(true, null, envelope, string.Empty);

    public static SerpiumParseResult Fail(string error) =>
        new(false, null, null, error);
}
