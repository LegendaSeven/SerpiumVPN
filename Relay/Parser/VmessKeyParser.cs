using System.Text.Json;

namespace SerpiumVPN.Relay.Parser;

public sealed class VmessKeyParser : ISerpiumKeyParser
{
    public bool CanParse(string key) =>
        key.TrimStart().StartsWith("vmess://", StringComparison.OrdinalIgnoreCase);

    public SerpiumParseResult Parse(string key)
    {
        try
        {
            string payload = key.Trim()["vmess://".Length..].Trim();
            if (string.IsNullOrWhiteSpace(payload))
                return SerpiumParseResult.Fail("VMess-ключ пуст.");

            string json = SerpiumParserUtilities.DecodeBase64Text(payload);
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;

            string server = SerpiumParserUtilities.ReadJsonString(root, "add");
            int port = SerpiumParserUtilities.ReadJsonInt(root, "port");
            string userId = SerpiumParserUtilities.ReadJsonString(root, "id");

            if (string.IsNullOrWhiteSpace(server))
                return SerpiumParseResult.Fail("В VMess-ключе отсутствует адрес сервера.");
            if (port is < 1 or > 65535)
                return SerpiumParseResult.Fail("В VMess-ключе указан некорректный порт.");
            if (string.IsNullOrWhiteSpace(userId))
                return SerpiumParseResult.Fail("В VMess-ключе отсутствует UUID.");

            string security = SerpiumParserUtilities.NormalizeSecurity(
                SerpiumParserUtilities.ReadJsonString(root, "tls", "none"));
            string transport = SerpiumParserUtilities.NormalizeTransport(
                SerpiumParserUtilities.ReadJsonString(root, "net", "tcp"));

            SerpiumConnectionProfile profile = new()
            {
                Protocol = "vmess",
                Server = server,
                Port = port,
                Name = SerpiumParserUtilities.ReadJsonString(root, "ps"),
                UserId = userId,
                AlterId = SerpiumParserUtilities.ReadJsonInt(root, "aid"),
                Encryption = SerpiumParserUtilities.ReadJsonString(root, "scy", "auto"),
                Security = security,
                Transport = transport,
                ServerName = SerpiumParserUtilities.ReadJsonString(root, "sni", server),
                Fingerprint = SerpiumParserUtilities.ReadJsonString(root, "fp", "chrome"),
                AllowInsecure = SerpiumParserUtilities.ReadJsonString(root, "allowInsecure") is "1" or "true",
                Path = SerpiumParserUtilities.ReadJsonString(root, "path"),
                HostHeader = SerpiumParserUtilities.ReadJsonString(root, "host"),
                ServiceName = SerpiumParserUtilities.ReadJsonString(root, "path"),
                HeaderType = SerpiumParserUtilities.ReadJsonString(root, "type"),
                Alpn = SerpiumParserUtilities.ParseList(
                    SerpiumParserUtilities.ReadJsonString(root, "alpn"))
            };

            return SerpiumParseResult.Ok(profile);
        }
        catch (FormatException)
        {
            return SerpiumParseResult.Fail("VMess-ключ содержит некорректный Base64.");
        }
        catch (JsonException)
        {
            return SerpiumParseResult.Fail("VMess-ключ содержит некорректный JSON.");
        }
        catch (Exception ex)
        {
            return SerpiumParseResult.Fail("Не удалось разобрать VMess-ключ: " + ex.Message);
        }
    }
}
