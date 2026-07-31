namespace SerpiumVPN.Relay.Parser;

public sealed class TrojanKeyParser : ISerpiumKeyParser
{
    public bool CanParse(string key) =>
        key.TrimStart().StartsWith("trojan://", StringComparison.OrdinalIgnoreCase);

    public SerpiumParseResult Parse(string key)
    {
        try
        {
            if (!Uri.TryCreate(key.Trim(), UriKind.Absolute, out Uri? uri) ||
                !uri.Scheme.Equals("trojan", StringComparison.OrdinalIgnoreCase))
            {
                return SerpiumParseResult.Fail("Некорректная Trojan-ссылка.");
            }

            string password = SerpiumParserUtilities.SafeUnescape(uri.UserInfo);
            if (string.IsNullOrWhiteSpace(password))
                return SerpiumParseResult.Fail("В Trojan-ключе отсутствует пароль.");
            if (string.IsNullOrWhiteSpace(uri.Host))
                return SerpiumParseResult.Fail("В Trojan-ключе отсутствует адрес сервера.");
            if (uri.Port is < 1 or > 65535)
                return SerpiumParseResult.Fail("В Trojan-ключе указан некорректный порт.");

            Dictionary<string, string> query = SerpiumParserUtilities.ParseQuery(uri.Query);
            string security = SerpiumParserUtilities.NormalizeSecurity(
                SerpiumParserUtilities.Get(query, "security", "tls"));

            SerpiumConnectionProfile profile = new()
            {
                Protocol = "trojan",
                Server = uri.Host,
                Port = uri.Port,
                Name = SerpiumParserUtilities.SafeUnescape(uri.Fragment.TrimStart('#')),
                Password = password,
                Security = security,
                Transport = SerpiumParserUtilities.NormalizeTransport(
                    SerpiumParserUtilities.Get(query, "type", "tcp")),
                ServerName = SerpiumParserUtilities.Get(query, "sni", uri.Host),
                Fingerprint = SerpiumParserUtilities.Get(query, "fp", "chrome"),
                AllowInsecure = SerpiumParserUtilities.GetBoolean(query, "allowInsecure"),
                Path = SerpiumParserUtilities.Get(query, "path"),
                HostHeader = SerpiumParserUtilities.Get(query, "host"),
                ServiceName = SerpiumParserUtilities.Get(query, "serviceName"),
                Mode = SerpiumParserUtilities.Get(query, "mode"),
                HeaderType = SerpiumParserUtilities.Get(query, "headerType"),
                Alpn = SerpiumParserUtilities.ParseList(
                    SerpiumParserUtilities.Get(query, "alpn"))
            };

            return SerpiumParseResult.Ok(profile);
        }
        catch (Exception ex)
        {
            return SerpiumParseResult.Fail("Не удалось разобрать Trojan-ключ: " + ex.Message);
        }
    }
}
