using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay;

public static class RelayKeyBuilder
{
    private const string Prefix = "serpium://relay/";

    public static string Build(RelayKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        RelayKeyParser.ValidateModel(key);

        string json = JsonSerializer.Serialize(key);
        return Prefix + ToBase64Url(Encoding.UTF8.GetBytes(json));
    }

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
