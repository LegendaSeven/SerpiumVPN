namespace SerpiumVPN.Relay.Parser;

public sealed class VlessKeyParser : ISerpiumKeyParser
{
    public bool CanParse(string key) =>
        key.TrimStart().StartsWith("vless://", StringComparison.OrdinalIgnoreCase);

    public SerpiumParseResult Parse(string key)
    {
        try
        {
            if (!Uri.TryCreate(key.Trim(), UriKind.Absolute, out Uri? uri) ||
                !uri.Scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
            {
                return SerpiumParseResult.Fail("Некорректная VLESS-ссылка.");
            }

            string userId = SerpiumParserUtilities.SafeUnescape(uri.UserInfo);
            if (string.IsNullOrWhiteSpace(userId))
                return SerpiumParseResult.Fail("В VLESS-ключе отсутствует идентификатор пользователя.");
            if (string.IsNullOrWhiteSpace(uri.Host))
                return SerpiumParseResult.Fail("В VLESS-ключе отсутствует адрес сервера.");
            if (uri.Port is < 1 or > 65535)
                return SerpiumParseResult.Fail("В VLESS-ключе указан некорректный порт.");

            Dictionary<string, string> query = SerpiumParserUtilities.ParseQuery(uri.Query);
            string security = SerpiumParserUtilities.NormalizeSecurity(
                SerpiumParserUtilities.Get(query, "security", "none"));
            string transport = SerpiumParserUtilities.NormalizeTransport(
                SerpiumParserUtilities.Get(query, "type", "tcp"));
            string serverName = SerpiumParserUtilities.Get(query, "sni", uri.Host);
            string publicKey = SerpiumParserUtilities.Get(query, "pbk");

            if (security == "reality" && string.IsNullOrWhiteSpace(publicKey))
                return SerpiumParseResult.Fail("В VLESS Reality-ключе отсутствует параметр pbk.");

            SerpiumConnectionProfile profile = new()
            {
                Protocol = "vless",
                Server = uri.Host,
                Port = uri.Port,
                Name = SerpiumParserUtilities.SafeUnescape(uri.Fragment.TrimStart('#')),
                UserId = userId,
                Encryption = SerpiumParserUtilities.Get(query, "encryption", "none"),
                Security = security,
                Transport = transport,
                Flow = SerpiumParserUtilities.Get(query, "flow"),
                ServerName = serverName,
                Fingerprint = SerpiumParserUtilities.Get(query, "fp", "chrome"),
                PublicKey = publicKey,
                ShortId = SerpiumParserUtilities.Get(query, "sid"),
                SpiderX = SerpiumParserUtilities.Get(query, "spx"),
                AllowInsecure = SerpiumParserUtilities.GetBoolean(query, "allowInsecure"),
                Path = SerpiumParserUtilities.Get(query, "path"),
                HostHeader = SerpiumParserUtilities.Get(query, "host"),
                ServiceName = SerpiumParserUtilities.Get(query, "serviceName"),
                Mode = SerpiumParserUtilities.Get(query, "mode"),
                HeaderType = SerpiumParserUtilities.Get(query, "headerType"),
                Seed = SerpiumParserUtilities.Get(query, "seed"),
                PacketEncoding = SerpiumParserUtilities.Get(query, "packetEncoding"),
                Alpn = SerpiumParserUtilities.ParseList(
                    SerpiumParserUtilities.Get(query, "alpn"))
            };

            return SerpiumParseResult.Ok(profile);
        }
        catch (Exception ex)
        {
            return SerpiumParseResult.Fail("Не удалось разобрать VLESS-ключ: " + ex.Message);
        }
    }
}
