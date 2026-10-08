using System.Text.Json;
using System.Text.Json.Serialization;
using SerpiumVPN.Relay.Parser;
using System.IO;

namespace SerpiumVPN.Relay.Xray;

public static class SerpiumXrayConfigBuilder
{
    public static string Build(
        SerpiumConnectionProfile profile,
        int socksPort,
        string logDirectory)
    {
        ArgumentNullException.ThrowIfNull(profile);

        Dictionary<string, object?> outbound = new(StringComparer.Ordinal)
        {
            ["tag"] = "serpium-vpn",
            ["protocol"] = profile.Protocol,
            ["settings"] = BuildProtocolSettings(profile),
            ["streamSettings"] = BuildStreamSettings(profile)
        };

        Dictionary<string, object?> config = new(StringComparer.Ordinal)
        {
            ["log"] = new Dictionary<string, object?>
            {
                ["loglevel"] = "warning",
                ["access"] = "none",
                // Engine diagnostics flow through the application's redactor, not raw files.
                ["error"] = ""
            },
            ["inbounds"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["tag"] = "serpium-socks",
                    ["listen"] = "127.0.0.1",
                    ["port"] = socksPort,
                    ["protocol"] = "socks",
                    ["settings"] = new Dictionary<string, object?>
                    {
                        ["auth"] = "noauth",
                        ["udp"] = true
                    },
                    ["sniffing"] = new Dictionary<string, object?>
                    {
                        ["enabled"] = true,
                        ["destOverride"] = new[] { "http", "tls", "quic" },
                        ["routeOnly"] = true
                    }
                }
            },
            ["outbounds"] = new object[]
            {
                outbound,
                new Dictionary<string, object?>
                {
                    ["tag"] = "direct",
                    ["protocol"] = "freedom"
                },
                new Dictionary<string, object?>
                {
                    ["tag"] = "block",
                    ["protocol"] = "blackhole"
                }
            },
            ["routing"] = new Dictionary<string, object?>
            {
                ["domainStrategy"] = "AsIs",
                ["rules"] = Array.Empty<object>()
            }
        };

        return JsonSerializer.Serialize(
            config,
            new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });
    }

    private static object BuildProtocolSettings(SerpiumConnectionProfile profile)
    {
        return profile.Protocol.ToLowerInvariant() switch
        {
            "vless" => BuildVlessSettings(profile),
            "vmess" => BuildVmessSettings(profile),
            "trojan" => BuildTrojanSettings(profile),
            _ => throw new NotSupportedException(
                $"Xray-конфиг для протокола {profile.Protocol} пока не реализован.")
        };
    }

    private static object BuildVlessSettings(SerpiumConnectionProfile profile)
    {
        Dictionary<string, object?> user = new(StringComparer.Ordinal)
        {
            ["id"] = profile.UserId,
            ["encryption"] = string.IsNullOrWhiteSpace(profile.Encryption)
                ? "none"
                : profile.Encryption
        };

        if (!string.IsNullOrWhiteSpace(profile.Flow))
            user["flow"] = profile.Flow;
        if (!string.IsNullOrWhiteSpace(profile.PacketEncoding))
            user["packetEncoding"] = profile.PacketEncoding;

        return new Dictionary<string, object?>
        {
            ["vnext"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["address"] = profile.Server,
                    ["port"] = profile.Port,
                    ["users"] = new object[] { user }
                }
            }
        };
    }

    private static object BuildVmessSettings(SerpiumConnectionProfile profile)
    {
        return new Dictionary<string, object?>
        {
            ["vnext"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["address"] = profile.Server,
                    ["port"] = profile.Port,
                    ["users"] = new object[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["id"] = profile.UserId,
                            ["alterId"] = profile.AlterId,
                            ["security"] = string.IsNullOrWhiteSpace(profile.Encryption)
                                ? "auto"
                                : profile.Encryption
                        }
                    }
                }
            }
        };
    }

    private static object BuildTrojanSettings(SerpiumConnectionProfile profile)
    {
        return new Dictionary<string, object?>
        {
            ["servers"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["address"] = profile.Server,
                    ["port"] = profile.Port,
                    ["password"] = profile.Password
                }
            }
        };
    }

    private static object BuildStreamSettings(SerpiumConnectionProfile profile)
    {
        string transport = NormalizeXrayTransport(profile.Transport);
        Dictionary<string, object?> stream = new(StringComparer.Ordinal)
        {
            ["network"] = transport,
            ["security"] = profile.Security.Equals("none", StringComparison.OrdinalIgnoreCase)
                ? "none"
                : profile.Security
        };

        AddSecuritySettings(stream, profile);
        AddTransportSettings(stream, profile, transport);
        return stream;
    }

    private static void AddSecuritySettings(
        IDictionary<string, object?> stream,
        SerpiumConnectionProfile profile)
    {
        if (profile.Security.Equals("tls", StringComparison.OrdinalIgnoreCase))
        {
            Dictionary<string, object?> tls = new(StringComparer.Ordinal)
            {
                ["serverName"] = string.IsNullOrWhiteSpace(profile.ServerName)
                    ? profile.Server
                    : profile.ServerName,
                ["allowInsecure"] = profile.AllowInsecure
            };

            if (!string.IsNullOrWhiteSpace(profile.Fingerprint))
                tls["fingerprint"] = profile.Fingerprint;
            if (profile.Alpn.Count > 0)
                tls["alpn"] = profile.Alpn;

            stream["tlsSettings"] = tls;
        }
        else if (profile.Security.Equals("reality", StringComparison.OrdinalIgnoreCase))
        {
            stream["realitySettings"] = new Dictionary<string, object?>
            {
                ["show"] = false,
                ["fingerprint"] = string.IsNullOrWhiteSpace(profile.Fingerprint)
                    ? "chrome"
                    : profile.Fingerprint,
                ["serverName"] = string.IsNullOrWhiteSpace(profile.ServerName)
                    ? profile.Server
                    : profile.ServerName,
                ["publicKey"] = profile.PublicKey,
                ["shortId"] = profile.ShortId,
                ["spiderX"] = string.IsNullOrWhiteSpace(profile.SpiderX)
                    ? "/"
                    : profile.SpiderX
            };
        }
    }

    private static void AddTransportSettings(
        IDictionary<string, object?> stream,
        SerpiumConnectionProfile profile,
        string transport)
    {
        switch (transport)
        {
            case "ws":
                stream["wsSettings"] = new Dictionary<string, object?>
                {
                    ["path"] = string.IsNullOrWhiteSpace(profile.Path) ? "/" : profile.Path,
                    ["headers"] = string.IsNullOrWhiteSpace(profile.HostHeader)
                        ? new Dictionary<string, object?>()
                        : new Dictionary<string, object?> { ["Host"] = profile.HostHeader }
                };
                break;

            case "grpc":
                stream["grpcSettings"] = new Dictionary<string, object?>
                {
                    ["serviceName"] = profile.ServiceName,
                    ["multiMode"] = profile.Mode.Equals("multi", StringComparison.OrdinalIgnoreCase)
                };
                break;

            case "http":
                stream["httpSettings"] = new Dictionary<string, object?>
                {
                    ["path"] = string.IsNullOrWhiteSpace(profile.Path) ? "/" : profile.Path,
                    ["host"] = string.IsNullOrWhiteSpace(profile.HostHeader)
                        ? Array.Empty<string>()
                        : new[] { profile.HostHeader }
                };
                break;

            case "httpupgrade":
                stream["httpupgradeSettings"] = new Dictionary<string, object?>
                {
                    ["path"] = string.IsNullOrWhiteSpace(profile.Path) ? "/" : profile.Path,
                    ["host"] = profile.HostHeader
                };
                break;

            case "xhttp":
                stream["xhttpSettings"] = new Dictionary<string, object?>
                {
                    ["path"] = string.IsNullOrWhiteSpace(profile.Path) ? "/" : profile.Path,
                    ["host"] = profile.HostHeader,
                    ["mode"] = string.IsNullOrWhiteSpace(profile.Mode) ? "auto" : profile.Mode,
                    ["extra"] = profile.XhttpExtra
                };
                break;

            case "kcp":
                stream["kcpSettings"] = new Dictionary<string, object?>
                {
                    ["seed"] = profile.Seed,
                    ["header"] = new Dictionary<string, object?>
                    {
                        ["type"] = string.IsNullOrWhiteSpace(profile.HeaderType)
                            ? "none"
                            : profile.HeaderType
                    }
                };
                break;

            case "tcp":
                if (!string.IsNullOrWhiteSpace(profile.HeaderType) &&
                    !profile.HeaderType.Equals("none", StringComparison.OrdinalIgnoreCase))
                {
                    stream["tcpSettings"] = new Dictionary<string, object?>
                    {
                        ["header"] = new Dictionary<string, object?>
                        {
                            ["type"] = profile.HeaderType
                        }
                    };
                }
                break;
        }
    }

    private static string NormalizeXrayTransport(string transport)
    {
        return transport.ToLowerInvariant() switch
        {
            "raw" => "tcp",
            "websocket" => "ws",
            "splithttp" => "xhttp",
            "" => "tcp",
            _ => transport.ToLowerInvariant()
        };
    }
}
