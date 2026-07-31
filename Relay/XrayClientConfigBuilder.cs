using System.Text.Json;
using System.IO;

namespace SerpiumVPN.Relay;

public static class XrayClientConfigBuilder
{
    public static string Build(
        RelayKey key,
        int socksPort,
        string logDirectory)
    {
        ArgumentNullException.ThrowIfNull(key);

        var config = new
        {
            log = new
            {
                loglevel = "warning",
                access = Path.Combine(logDirectory, "xray-client-access.log"),
                error = Path.Combine(logDirectory, "xray-client-error.log")
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "serpium-socks",
                    listen = "127.0.0.1",
                    port = socksPort,
                    protocol = "socks",
                    settings = new
                    {
                        auth = "noauth",
                        udp = true
                    }
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "serpium-relay",
                    protocol = "vless",
                    settings = new
                    {
                        vnext = new object[]
                        {
                            new
                            {
                                address = key.Host,
                                port = key.Port,
                                users = new object[]
                                {
                                    new
                                    {
                                        id = key.Uuid,
                                        encryption = "none"
                                    }
                                }
                            }
                        }
                    },
                    streamSettings = new
                    {
                        network = key.Network
                    }
                },
                new
                {
                    tag = "direct",
                    protocol = "freedom"
                },
                new
                {
                    tag = "block",
                    protocol = "blackhole"
                }
            }
        };

        return JsonSerializer.Serialize(
            config,
            new JsonSerializerOptions { WriteIndented = true });
    }
}
