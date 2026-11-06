using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay.Parser;

/// <summary>Outline's ordinary SIP002/legacy keys. Unsupported transports fail closed.</summary>
public sealed class ShadowsocksKeyParser : ISerpiumKeyParser
{
    private static readonly HashSet<string> Methods = new(StringComparer.Ordinal)
        { "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305" };

    public bool CanParse(string key) => key.TrimStart().StartsWith("ss://", StringComparison.OrdinalIgnoreCase);

    public SerpiumParseResult Parse(string key)
    {
        try
        {
            string value = key.Trim();
            if (!CanParse(value) || value.Length > 8192) throw new FormatException();
            string body = value[5..];
            string name = "Outline";
            int fragment = body.IndexOf('#');
            if (fragment >= 0) { name = Uri.UnescapeDataString(body[(fragment + 1)..]); body = body[..fragment]; }
            int query = body.IndexOf('?');
            if (query >= 0)
            {
                foreach (string parameter in body[(query + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    string[] pair = parameter.Split('=', 2);
                    // Do not silently discard prefix/plugin options that change the transport.
                    if (Uri.UnescapeDataString(pair[0]) != "outline" || pair.Length != 2 || pair[1] != "1")
                        return SerpiumParseResult.Fail("Этот вариант Outline пока не поддерживается.");
                }
                body = body[..query];
            }
            if (!body.Contains('@')) body = DecodeBase64(body);
            int separator = body.LastIndexOf('@');
            if (separator <= 0) throw new FormatException();
            string credentials = body[..separator];
            if (!credentials.Contains(':')) credentials = DecodeBase64(credentials);
            else credentials = Uri.UnescapeDataString(credentials);
            int colon = credentials.IndexOf(':');
            if (colon <= 0) throw new FormatException();
            string method = credentials[..colon], password = credentials[(colon + 1)..];
            if (!Methods.Contains(method) || password.Length is 0 or > 2048 || password.Any(char.IsControl))
                throw new FormatException();
            if (!Uri.TryCreate("ss://" + body[(separator + 1)..], UriKind.Absolute, out var endpoint) ||
                endpoint.Port is < 1 or > 65535 || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 ||
                endpoint.Fragment.Length != 0 || endpoint.AbsolutePath is not ("" or "/") || endpoint.Host.Length == 0)
                throw new FormatException();
            return SerpiumParseResult.Ok(new SerpiumConnectionProfile
            {
                Protocol = "shadowsocks", Server = endpoint.IdnHost.Trim('[', ']'), Port = endpoint.Port,
                Encryption = method, Password = password, Name = name
            });
        }
        catch (Exception error) when (error is FormatException or ArgumentException)
        { return SerpiumParseResult.Fail("Ключ Outline повреждён или использует неподдерживаемые параметры."); }
    }

    public static string DecodeBase64(string input)
    {
        string normalized = input.Replace('-', '+').Replace('_', '/');
        normalized += new string('=', (4 - normalized.Length % 4) % 4);
        byte[] bytes = Convert.FromBase64String(normalized);
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static string FromJson(string json)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count() || root.EnumerateObject().Any(p =>
            p.Name is not ("server" or "server_port" or "method" or "password"))) throw new FormatException();
        string host = root.GetProperty("server").GetString() ?? throw new FormatException();
        int port = root.GetProperty("server_port").GetInt32();
        string method = root.GetProperty("method").GetString() ?? throw new FormatException();
        string password = root.GetProperty("password").GetString() ?? throw new FormatException();
        if (host.IndexOfAny(['/', '@', '?', '#', '\\']) >= 0 || host.Any(char.IsWhiteSpace) || port is < 1 or > 65535)
            throw new FormatException();
        if (IPAddress.TryParse(host.Trim('[', ']'), out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            host = "[" + address + "]";
        byte[] bytes = Encoding.UTF8.GetBytes(method + ":" + password);
        try
        {
            string key = "ss://" + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') +
                "@" + host + ":" + port.ToString(CultureInfo.InvariantCulture) + "#Outline";
            if (!new ShadowsocksKeyParser().Parse(key).Success) throw new FormatException();
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
