namespace SerpiumVPN.Relay.Parser;

public sealed class SerpiumParser
{
    private readonly IReadOnlyList<ISerpiumKeyParser> _parsers;

    public SerpiumParser()
    {
        _parsers = new ISerpiumKeyParser[]
        {
            new VlessKeyParser(),
            new VmessKeyParser(),
            new TrojanKeyParser(),
            new Hysteria2KeyParser(),
            new AvoEnvelopeKeyParser()
        };
    }

    public SerpiumParseResult Parse(string? key)
    {
        string normalized = key?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalized))
            return SerpiumParseResult.Fail("Вставьте VPN-ключ.");

        ISerpiumKeyParser? parser = _parsers.FirstOrDefault(item => item.CanParse(normalized));
        if (parser is null)
        {
            string scheme = GetScheme(normalized);
            return SerpiumParseResult.Fail(
                string.IsNullOrWhiteSpace(scheme)
                    ? "Формат ключа не распознан. Сейчас поддерживаются VLESS, VMess, Trojan и провайдерские контейнеры."
                    : $"Формат {scheme.ToUpperInvariant()} пока не поддерживается Serpium Parser.");
        }

        return parser.Parse(normalized);
    }

    private static string GetScheme(string key)
    {
        int separator = key.IndexOf("://", StringComparison.Ordinal);
        if (separator <= 0)
            return string.Empty;
        return key[..separator].Trim();
    }
}
