using System.Security.Cryptography;

namespace SerpiumVPN.Relay.Providers;

/// <summary>
/// Provider-native runtime profile kept only in memory.
/// The sensitive configuration is never exposed through ToString or diagnostics.
/// </summary>
public sealed class ProviderRuntimeProfile : IDisposable
{
    private byte[]? _configurationUtf8;

    public ProviderRuntimeProfile(
        string providerName,
        string profileId,
        string engine,
        byte[] configurationUtf8,
        IEnumerable<string> protocols,
        int inboundCount,
        int outboundCount,
        int routeRuleCount,
        int dnsServerCount,
        string safeSchemaSummary = "")
    {
        if (string.IsNullOrWhiteSpace(providerName))
            throw new ArgumentException("Имя провайдера не указано.", nameof(providerName));
        if (string.IsNullOrWhiteSpace(profileId))
            throw new ArgumentException("Идентификатор профиля не указан.", nameof(profileId));
        if (string.IsNullOrWhiteSpace(engine))
            throw new ArgumentException("Движок профиля не указан.", nameof(engine));
        ArgumentNullException.ThrowIfNull(configurationUtf8);
        if (configurationUtf8.Length == 0)
            throw new ArgumentException("Конфигурация провайдера пуста.", nameof(configurationUtf8));

        ProviderName = providerName;
        ProfileId = profileId;
        Engine = engine;
        _configurationUtf8 = configurationUtf8;
        Protocols = protocols
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        InboundCount = Math.Max(0, inboundCount);
        OutboundCount = Math.Max(0, outboundCount);
        RouteRuleCount = Math.Max(0, routeRuleCount);
        DnsServerCount = Math.Max(0, dnsServerCount);
        SafeSchemaSummary = string.IsNullOrWhiteSpace(safeSchemaSummary)
            ? "Структура provider JSON ещё не исследована."
            : safeSchemaSummary.Trim();
    }

    public string ProviderName { get; }
    public string ProfileId { get; }
    public string Engine { get; }
    public IReadOnlyList<string> Protocols { get; }
    public int InboundCount { get; }
    public int OutboundCount { get; }
    public int RouteRuleCount { get; }
    public int DnsServerCount { get; }
    public string SafeSchemaSummary { get; }
    public int ConfigurationByteCount => _configurationUtf8?.Length ?? 0;
    public bool IsDisposed => _configurationUtf8 is null;

    public string MaskedProfileId
    {
        get
        {
            if (ProfileId.Length <= 8)
                return new string('•', ProfileId.Length);

            return ProfileId[..4] + "…" + ProfileId[^4..];
        }
    }

    /// <summary>
    /// Used by a provider runtime in a later stage. The caller owns the returned copy.
    /// </summary>
    public byte[] CopyConfiguration()
    {
        byte[] source = _configurationUtf8 ??
            throw new ObjectDisposedException(nameof(ProviderRuntimeProfile));
        return source.ToArray();
    }

    public void Dispose()
    {
        byte[]? buffer = Interlocked.Exchange(ref _configurationUtf8, null);
        if (buffer is not null)
            CryptographicOperations.ZeroMemory(buffer);
    }
}
