using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SerpiumVPN.Relay;

public static partial class RelayKeyParser
{
    private const string Prefix = "serpium://relay/";

    public static RelayKey Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException("Поле ключа пустое.");

        string trimmed = value.Trim();
        if (!trimmed.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            throw new FormatException("Ключ должен начинаться с serpium://relay/.");

        string payload = trimmed[Prefix.Length..];
        if (payload.Length is < 8 or > 8192)
            throw new FormatException("Некорректный размер ключа.");

        byte[] jsonBytes;
        try
        {
            jsonBytes = FromBase64Url(payload);
        }
        catch (FormatException)
        {
            throw new FormatException("Повреждён Base64URL-блок ключа.");
        }

        RelayKey? key;
        try
        {
            key = JsonSerializer.Deserialize<RelayKey>(jsonBytes);
        }
        catch (JsonException)
        {
            throw new FormatException("Ключ содержит повреждённую конфигурацию JSON.");
        }

        if (key is null)
            throw new FormatException("Не удалось прочитать конфигурацию ключа.");

        ValidateModel(key);
        return key;
    }

    public static bool TryParse(string value, out RelayKey? key, out string error)
    {
        try
        {
            key = Parse(value);
            error = "";
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            key = null;
            error = ex.Message;
            return false;
        }
    }

    public static void ValidateModel(RelayKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Schema != 1)
            throw new FormatException($"Версия ключа schema={key.Schema} пока не поддерживается.");

        if (string.IsNullOrWhiteSpace(key.Name) || key.Name.Length > 80)
            throw new FormatException("Некорректное имя шлюза.");

        string transport = key.Transport.Trim().ToLowerInvariant();
        if (transport is not ("tailscale" or "localtonet" or "cloudflare" or "serpium-node"))
            throw new FormatException("Неизвестный транспорт Relay.");

        if (!string.Equals(key.Protocol, "vless", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("На этом этапе поддерживается только протокол VLESS.");

        if (key.Port is < 1 or > 65535)
            throw new FormatException("Порт должен быть в диапазоне 1–65535.");

        if (!Guid.TryParse(key.Uuid, out _))
            throw new FormatException("UUID в ключе повреждён.");

        if (!IsValidHost(key.Host))
            throw new FormatException("Некорректный адрес шлюза.");

        if (!string.Equals(key.Network, "tcp", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("На первом этапе поддерживается только TCP.");
    }

    private static bool IsValidHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253)
            return false;

        string value = host.Trim();
        if (IPAddress.TryParse(value, out _))
            return true;

        return HostRegex().IsMatch(value);
    }

    private static byte[] FromBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => "",
            _ => throw new FormatException()
        };
        return Convert.FromBase64String(padded);
    }

    [GeneratedRegex(@"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")]
    private static partial Regex HostRegex();
}
