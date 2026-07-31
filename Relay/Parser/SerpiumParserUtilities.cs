using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay.Parser;

internal static class SerpiumParserUtilities
{
    public static Dictionary<string, string> ParseQuery(string query)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
            return values;

        string source = query.TrimStart('?');
        foreach (string item in source.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = item.IndexOf('=');
            string rawName = separator >= 0 ? item[..separator] : item;
            string rawValue = separator >= 0 ? item[(separator + 1)..] : string.Empty;

            string name = SafeUnescape(rawName);
            string value = SafeUnescape(rawValue);
            if (!string.IsNullOrWhiteSpace(name))
                values[name] = value;
        }

        return values;
    }

    public static string Get(
        IReadOnlyDictionary<string, string> values,
        string name,
        string fallback = "") =>
        values.TryGetValue(name, out string? value) ? value : fallback;

    public static bool GetBoolean(
        IReadOnlyDictionary<string, string> values,
        string name,
        bool fallback = false)
    {
        string value = Get(values, name);
        if (string.IsNullOrWhiteSpace(value))
            return fallback;

        return value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    public static IReadOnlyList<string> ParseList(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Array.Empty<string>();

        return value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToArray();
    }

    public static string DecodeBase64Text(string value)
    {
        string normalized = value.Trim()
            .Replace('-', '+')
            .Replace('_', '/');

        int remainder = normalized.Length % 4;
        if (remainder != 0)
            normalized = normalized.PadRight(normalized.Length + (4 - remainder), '=');

        byte[] bytes = Convert.FromBase64String(normalized);
        return Encoding.UTF8.GetString(bytes);
    }

    public static string ReadJsonString(JsonElement root, string propertyName, string fallback = "")
    {
        if (!root.TryGetProperty(propertyName, out JsonElement value))
            return fallback;

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? fallback,
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => fallback
        };
    }

    public static int ReadJsonInt(JsonElement root, string propertyName, int fallback = 0)
    {
        string value = ReadJsonString(root, propertyName);
        return int.TryParse(value, out int parsed) ? parsed : fallback;
    }

    public static string SafeUnescape(string value)
    {
        try { return Uri.UnescapeDataString(value); }
        catch { return value; }
    }

    public static string NormalizeTransport(string value)
    {
        string transport = value.Trim().ToLowerInvariant();
        return transport switch
        {
            "raw" => "tcp",
            "websocket" => "ws",
            "h2" => "http",
            "httpupgrade" => "httpupgrade",
            "splithttp" => "xhttp",
            "" => "tcp",
            _ => transport
        };
    }

    public static string NormalizeSecurity(string value)
    {
        string security = value.Trim().ToLowerInvariant();
        return security switch
        {
            "xtls" => "tls",
            "" => "none",
            _ => security
        };
    }
}
