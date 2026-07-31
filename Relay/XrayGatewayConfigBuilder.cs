using System.Text.Json;
using System.IO;
namespace SerpiumVPN.Relay;

public static class XrayGatewayConfigBuilder
{
    public static string Build(string listenAddress, int port, string uuid, string logDirectory)
    {
        if (string.IsNullOrWhiteSpace(listenAddress))
            throw new ArgumentException("Адрес прослушивания не задан.", nameof(listenAddress));
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), "Порт должен быть в диапазоне 1–65535.");
        if (!Guid.TryParse(uuid, out _))
            throw new ArgumentException("Некорректный UUID.", nameof(uuid));

        Directory.CreateDirectory(logDirectory);

        var config = new
        {
            log = new
            {
                loglevel = "warning",
                access = Path.Combine(logDirectory, "xray-access.log"),
                error = Path.Combine(logDirectory, "xray-error.log")
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "serpium-vless-in",
                    listen = listenAddress,
                    port,
                    protocol = "vless",
                    settings = new
                    {
                        clients = new object[]
                        {
                            new { id = uuid, email = "serpium-gateway" }
                        },
                        decryption = "none"
                    },
                    streamSettings = new
                    {
                        network = "tcp",
                        security = "none"
                    }
                }
            },
            outbounds = new object[]
            {
                new { tag = "direct", protocol = "freedom", settings = new { } },
                new { tag = "blocked", protocol = "blackhole", settings = new { } }
            }
        };

        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }
}

