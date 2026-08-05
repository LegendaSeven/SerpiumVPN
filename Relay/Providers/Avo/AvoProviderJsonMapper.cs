using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay.Providers.Avo;

/// <summary>
/// Converts the compact provider JSON stored in a bare avo:// key into a
/// Serpium-owned sing-box configuration. The source values are never logged.
/// </summary>
internal static class AvoProviderJsonMapper
{
    private static readonly string[] ExpectedFieldNames =
    [
        "domain", "domain2", "domain3",
        "ip", "ip2", "ip3",
        "o_pass", "o_pass2", "o_pass3",
        "p_h", "p_mt", "p_mu", "p_t", "p_v", "p_vt",
        "pass", "pbk", "sni", "user"
    ];

    public static AvoProviderJsonMappingResult Map(
        string profileId,
        JsonElement providerRoot)
    {
        if (providerRoot.ValueKind != JsonValueKind.Object)
            throw new FormatException("AVO provider-json должен быть объектом.");
        if (!Guid.TryParse(profileId, out Guid profileGuid))
            throw new FormatException("Идентификатор AVO-профиля не является UUID.");

        string server = ReadRequiredString(providerRoot, "ip", 1, 255);
        string tlsDomain = ReadRequiredString(providerRoot, "domain", 1, 255);
        string commonPassword = ReadRequiredString(providerRoot, "pass", 1, 4096);
        string hysteriaObfuscationPassword =
            ReadRequiredString(providerRoot, "o_pass", 1, 4096);

        ValidateServer(server);
        ValidateTlsName(tlsDomain);

        int trojanPort = ReadPort(providerRoot, "p_t", 443);
        int hysteriaPort = ReadPort(providerRoot, "p_h", 443);
        int vlessTlsPort = ReadPort(providerRoot, "p_vt", 543);

        string interfaceName = BuildInterfaceName(profileGuid);
        string tunAddress = BuildTunAddress(profileGuid);

        Dictionary<string, object?> configuration = new(StringComparer.Ordinal)
        {
            ["log"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["disabled"] = false,
                ["level"] = "info",
                ["output"] = string.Empty,
                ["timestamp"] = true
            },
            ["inbounds"] = new object[]
            {
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "tun",
                    ["tag"] = "tun-in",
                    ["interface_name"] = interfaceName,
                    ["address"] = new[] { tunAddress },
                    ["mtu"] = 1492,
                    ["auto_route"] = true,
                    ["endpoint_independent_nat"] = true,
                    ["stack"] = "mixed"
                }
            },
            ["outbounds"] = new object[]
            {
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "urltest",
                    ["tag"] = "proxy",
                    ["outbounds"] = new[]
                    {
                        "hysteria-out",
                        "trojan-out",
                        "vless-tls-out"
                    },
                    ["url"] = "https://www.gstatic.com/generate_204",
                    ["interval"] = "30m"
                },
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "trojan",
                    ["tag"] = "trojan-out",
                    ["server"] = server,
                    ["server_port"] = trojanPort,
                    ["password"] = commonPassword,
                    ["tls"] = new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["enabled"] = true,
                        ["insecure"] = false,
                        ["server_name"] = tlsDomain,
                        ["utls"] = new Dictionary<string, object?>(StringComparer.Ordinal)
                        {
                            ["enabled"] = true,
                            ["fingerprint"] = "chrome"
                        }
                    }
                },
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "hysteria2",
                    ["tag"] = "hysteria-out",
                    ["server"] = server,
                    ["server_port"] = hysteriaPort,
                    ["password"] = commonPassword,
                    ["obfs"] = new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["type"] = "salamander",
                        ["password"] = hysteriaObfuscationPassword
                    },
                    ["tls"] = new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["enabled"] = true,
                        ["insecure"] = false,
                        ["server_name"] = tlsDomain
                    }
                },
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "vless",
                    ["tag"] = "vless-tls-out",
                    ["server"] = server,
                    ["server_port"] = vlessTlsPort,
                    ["uuid"] = profileGuid.ToString("D"),
                    ["tls"] = new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["enabled"] = true,
                        ["insecure"] = false,
                        ["server_name"] = tlsDomain,
                        ["utls"] = new Dictionary<string, object?>(StringComparer.Ordinal)
                        {
                            ["enabled"] = true,
                            ["fingerprint"] = "random"
                        }
                    }
                },
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "direct",
                    ["tag"] = "direct"
                },
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["type"] = "direct",
                    ["tag"] = "bypass"
                }
            },
            ["route"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["rules"] = new object[]
                {
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["inbound"] = "tun-in",
                        ["action"] = "sniff"
                    },
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["protocol"] = "dns",
                        ["action"] = "hijack-dns"
                    },
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["ip_cidr"] = new[] { "224.0.0.0/3" },
                        ["source_ip_cidr"] = new[] { "224.0.0.0/3" },
                        ["action"] = "reject"
                    },
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["ip_cidr"] = new[]
                        {
                            "10.0.0.0/8",
                            "172.16.0.0/12",
                            "192.168.0.0/16",
                            "127.0.0.0/8"
                        },
                        ["outbound"] = "direct"
                    }
                },
                ["auto_detect_interface"] = true,
                ["final"] = "proxy",
                // The mapped profile can later receive dynamic process_path rules.
                ["find_process"] = true
            },
            ["dns"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["servers"] = new object[]
                {
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["type"] = "udp",
                        ["tag"] = "dns-proxy",
                        ["server"] = "8.8.8.8",
                        ["server_port"] = 53,
                        ["detour"] = "proxy"
                    }
                },
                ["final"] = "dns-proxy",
                ["strategy"] = "ipv4_only"
            }
        };

        byte[] configurationUtf8 = JsonSerializer.SerializeToUtf8Bytes(
            configuration,
            new JsonSerializerOptions
            {
                WriteIndented = true
            });

        try
        {
            ValidateGeneratedConfiguration(configurationUtf8);
            string safeSummary = BuildSafeMappingSummary(providerRoot);

            return new AvoProviderJsonMappingResult(
                configurationUtf8,
                ["hysteria2", "trojan", "vless"],
                inboundCount: 1,
                outboundCount: 6,
                routeRuleCount: 4,
                dnsServerCount: 1,
                safeMappingSummary: safeSummary);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(configurationUtf8);
            throw;
        }
    }

    private static string ReadRequiredString(
        JsonElement root,
        string propertyName,
        int minimumLength,
        int maximumLength)
    {
        if (!root.TryGetProperty(propertyName, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw new FormatException($"В AVO provider-json отсутствует строковое поле {propertyName}.");
        }

        string? result = value.GetString();
        if (string.IsNullOrWhiteSpace(result))
            throw new FormatException($"Поле {propertyName} в AVO provider-json пусто.");

        result = result.Trim();
        if (result.Length < minimumLength || result.Length > maximumLength)
            throw new FormatException($"Поле {propertyName} имеет недопустимую длину.");

        return result;
    }

    private static int ReadPort(
        JsonElement root,
        string propertyName,
        int defaultValue)
    {
        if (!root.TryGetProperty(propertyName, out JsonElement value))
            return defaultValue;

        int port;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out port))
        {
            // Parsed below.
        }
        else if (value.ValueKind == JsonValueKind.String &&
                 int.TryParse(value.GetString(), out port))
        {
            // Parsed below.
        }
        else
        {
            throw new FormatException($"Поле {propertyName} не является TCP/UDP-портом.");
        }

        if (port is < 1 or > 65535)
            throw new FormatException($"Поле {propertyName} содержит порт вне диапазона 1–65535.");

        return port;
    }

    private static void ValidateServer(string server)
    {
        if (IPAddress.TryParse(server, out _))
            return;

        UriHostNameType hostType = Uri.CheckHostName(server);
        if (hostType is not UriHostNameType.Dns)
            throw new FormatException("Поле ip не содержит допустимый IP-адрес или DNS-имя.");
    }

    private static void ValidateTlsName(string tlsName)
    {
        UriHostNameType hostType = Uri.CheckHostName(tlsName);
        if (hostType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
            throw new FormatException("Поле domain не содержит допустимое TLS-имя.");
    }

    private static string BuildInterfaceName(Guid profileId)
    {
        string suffix = profileId.ToString("N")[..6];
        return "spavo-" + suffix;
    }

    private static string BuildTunAddress(Guid profileId)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(profileId.ToString("D")));
        try
        {
            int thirdOctet = hash[0];
            int hostOctet = ((hash[1] % 14) + 1);
            return $"172.29.{thirdOctet}.{hostOctet}/28";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static void ValidateGeneratedConfiguration(byte[] configurationUtf8)
    {
        using JsonDocument document = JsonDocument.Parse(configurationUtf8);
        JsonElement root = document.RootElement;

        if (!root.TryGetProperty("inbounds", out JsonElement inbounds) ||
            inbounds.ValueKind != JsonValueKind.Array ||
            inbounds.GetArrayLength() != 1)
        {
            throw new InvalidOperationException("Сформированный AVO-профиль не содержит TUN-вход.");
        }

        if (!root.TryGetProperty("outbounds", out JsonElement outbounds) ||
            outbounds.ValueKind != JsonValueKind.Array ||
            outbounds.GetArrayLength() != 6)
        {
            throw new InvalidOperationException("Сформированный AVO-профиль содержит неверный набор выходов.");
        }

        if (!root.TryGetProperty("route", out JsonElement route) ||
            route.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("dns", out JsonElement dns) ||
            dns.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Сформированный AVO-профиль не содержит маршрутизацию или DNS.");
        }
    }

    private static string BuildSafeMappingSummary(JsonElement providerRoot)
    {
        int recognizedFields = 0;
        foreach (string fieldName in ExpectedFieldNames)
        {
            if (providerRoot.TryGetProperty(fieldName, out _))
                recognizedFields++;
        }

        int totalFields = providerRoot.EnumerateObject().Count();
        int unrecognizedFields = Math.Max(0, totalFields - recognizedFields);

        StringBuilder summary = new();
        summary.AppendLine("Маппинг provider-json → sing-box выполнен локально.");
        summary.AppendLine("Созданы выходы: HYSTERIA2, TROJAN, VLESS-TLS.");
        summary.AppendLine("Группа URLTest: 3 защищённых выхода; fallback выполняет sing-box.");
        summary.AppendLine("TUN / маршрутизация / DNS: 1 / 4 / 1.");
        summary.Append("Распознано полей provider-json: ");
        summary.Append(recognizedFields);
        summary.Append(" из ");
        summary.Append(totalFields);
        summary.Append("; неизвестных: ");
        summary.Append(unrecognizedFields);
        summary.AppendLine(".");
        summary.Append("Значения серверов, UUID, паролей, SNI и ключей не выводятся.");
        return summary.ToString();
    }
}
