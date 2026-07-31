namespace SerpiumVPN.Relay.Providers.Avo;

internal sealed class AvoProviderJsonMappingResult
{
    public AvoProviderJsonMappingResult(
        byte[] configurationUtf8,
        IEnumerable<string> protocols,
        int inboundCount,
        int outboundCount,
        int routeRuleCount,
        int dnsServerCount,
        string safeMappingSummary)
    {
        ArgumentNullException.ThrowIfNull(configurationUtf8);
        if (configurationUtf8.Length == 0)
            throw new ArgumentException("Сформированный sing-box профиль пуст.", nameof(configurationUtf8));

        ConfigurationUtf8 = configurationUtf8;
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
        SafeMappingSummary = string.IsNullOrWhiteSpace(safeMappingSummary)
            ? "provider-json преобразован в sing-box профиль."
            : safeMappingSummary.Trim();
    }

    public byte[] ConfigurationUtf8 { get; }
    public IReadOnlyList<string> Protocols { get; }
    public int InboundCount { get; }
    public int OutboundCount { get; }
    public int RouteRuleCount { get; }
    public int DnsServerCount { get; }
    public string SafeMappingSummary { get; }
}
