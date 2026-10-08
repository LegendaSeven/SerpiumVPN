namespace SerpiumVPN.Relay.Parser;

public sealed class Hysteria2KeyParser : ISerpiumKeyParser
{
    public bool CanParse(string key) => key.TrimStart().StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) ||
        key.TrimStart().StartsWith("hy2://", StringComparison.OrdinalIgnoreCase);

    public SerpiumParseResult Parse(string key)
    {
        if (!Uri.TryCreate(key.Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("hysteria2" or "hy2") || string.IsNullOrWhiteSpace(uri.Host))
            return SerpiumParseResult.Fail("Некорректная Hysteria2-ссылка.");
        int port = uri.Port == -1 ? 443 : uri.Port;
        if (port is < 1 or > 65535) return SerpiumParseResult.Fail("Некорректный порт Hysteria2.");
        var query = SerpiumParserUtilities.ParseQuery(uri.Query);
        // Do not silently ignore certificate pinning/ECH or newer obfuscation modes.
        if (query.Keys.Any(k => !new[] { "sni", "insecure", "obfs", "obfs-password" }.Contains(k, StringComparer.OrdinalIgnoreCase)))
            return SerpiumParseResult.Fail("Параметр Hysteria2 пока не поддерживается.");
        string obfs = SerpiumParserUtilities.Get(query, "obfs");
        string obfsPassword = SerpiumParserUtilities.Get(query, "obfs-password");
        if (obfs is not ("" or "salamander") || (obfs.Length > 0 && obfsPassword.Length == 0) || (obfs.Length == 0 && obfsPassword.Length > 0))
            return SerpiumParseResult.Fail("Некорректные параметры маскировки Hysteria2.");
        if (query.TryGetValue("insecure", out string? insecure) && insecure is not ("0" or "1"))
            return SerpiumParseResult.Fail("Некорректный параметр TLS Hysteria2.");
        return SerpiumParseResult.Ok(new SerpiumConnectionProfile
        {
            Protocol = "hysteria2", Server = uri.IdnHost.Trim('[', ']'), Port = port,
            Password = SerpiumParserUtilities.SafeUnescape(uri.UserInfo),
            Name = SerpiumParserUtilities.SafeUnescape(uri.Fragment.TrimStart('#')),
            Security = "tls", ServerName = SerpiumParserUtilities.Get(query, "sni", uri.IdnHost.Trim('[', ']')),
            AllowInsecure = insecure == "1", Obfuscation = obfs, ObfuscationPassword = obfsPassword
        });
    }
}
