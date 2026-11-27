using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Outline;

public static class OutlinePrefixConfiguration
{
    public const string Marker = "serpium_outline_tcp_prefix";
    public const string ExecutableName = "Serpium.Outline.exe";

    public static JsonObject? FindOutbound(JsonObject root)
    {
        var matches = (root["outbounds"] as JsonArray)?.OfType<JsonObject>().Where(o => o.ContainsKey(Marker)).ToArray() ?? [];
        if (matches.Length > 1) throw new InvalidDataException("В профиле допускается один транспорт Outline prefix.");
        if (matches.Length == 0) return null;
        var outbound = matches[0];
        if (outbound["type"]?.GetValue<string>() != "shadowsocks") throw new InvalidDataException("Некорректный транспорт Outline.");
        string method = outbound["method"]!.GetValue<string>();
        byte[] prefix = Convert.FromBase64String(outbound[Marker]!.GetValue<string>());
        if (prefix.Length == 0) throw new InvalidDataException("Пустой prefix Outline.");
        ShadowsocksKeyParser.ValidatePrefix(method, Encoding.Latin1.GetString(prefix));
        return outbound;
    }

    public static JsonObject HelperConfiguration(JsonObject outbound, string localSecret) => new()
    {
        ["server"] = outbound["server"]!.DeepClone(), ["port"] = outbound["server_port"]!.DeepClone(),
        ["method"] = outbound["method"]!.DeepClone(), ["password"] = outbound["password"]!.DeepClone(),
        ["prefix"] = outbound[Marker]!.DeepClone(), ["local_password"] = localSecret
    };

    public static void Bind(JsonObject outbound, int port, string secret)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        outbound.Remove(Marker);
        outbound["server"] = "127.0.0.1"; outbound["server_port"] = port;
        outbound["method"] = "chacha20-ietf-poly1305"; outbound["password"] = secret;
    }

    // Config checks must validate the same loopback transport as a real connection, without starting it.
    public static byte[] PrepareCheck(byte[] configuration)
    {
        var root = JsonNode.Parse(configuration)!.AsObject();
        var outbound = FindOutbound(root);
        if (outbound is null) return configuration;
        try
        {
            Bind(outbound, 1, "compatibility-fixture-local-password");
            return Encoding.UTF8.GetBytes(root.ToJsonString());
        }
        finally { CryptographicOperations.ZeroMemory(configuration); }
    }
}
