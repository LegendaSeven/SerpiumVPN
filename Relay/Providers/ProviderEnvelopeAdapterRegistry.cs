namespace SerpiumVPN.Relay.Providers;

/// <summary>
/// Registry for optional provider-specific envelope adapters.
/// MVP7.0A.4 ships the contract and AVO recognition only; no closed
/// provider protocol is reverse-engineered or guessed.
/// </summary>
public sealed class ProviderEnvelopeAdapterRegistry
{
    private readonly Dictionary<string, IProviderEnvelopeAdapter> _adapters =
        new(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<IProviderEnvelopeAdapter> Adapters => _adapters.Values;

    public void Register(IProviderEnvelopeAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        if (string.IsNullOrWhiteSpace(adapter.Scheme))
            throw new ArgumentException("Схема адаптера не указана.", nameof(adapter));

        _adapters[adapter.Scheme.Trim()] = adapter;
    }

    public IProviderEnvelopeAdapter? Find(string? scheme)
    {
        if (string.IsNullOrWhiteSpace(scheme))
            return null;

        return _adapters.TryGetValue(scheme.Trim(), out IProviderEnvelopeAdapter? adapter)
            ? adapter
            : null;
    }
}
