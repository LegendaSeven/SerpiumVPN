using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Providers;

/// <summary>
/// Resolves an opaque provider envelope into a normalized Serpium profile.
/// Implementations are isolated modules and must not log raw payloads.
/// </summary>
public interface IProviderEnvelopeAdapter
{
    string Scheme { get; }

    Task<ProviderResolveResult> ResolveAsync(
        ProviderEnvelope envelope,
        CancellationToken cancellationToken = default);
}
