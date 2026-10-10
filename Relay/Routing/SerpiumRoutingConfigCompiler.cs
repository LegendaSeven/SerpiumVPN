using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Providers;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Compiles the encrypted Routing Registry into a sing-box selective-routing policy.
/// The generated configuration exists only in managed memory and is passed to sing-box over stdin.
/// </summary>
public static class SerpiumRoutingConfigCompiler
{
    private const string ProxyOutboundTag = "proxy";
    private const string DirectOutboundTag = "direct";
    private const string ProxyDnsTag = "dns-proxy";
    private const string DirectDnsTag = "dns-direct";
    private const string ConnectivityProbeDomain = "www.gstatic.com";
    public const string DynamicRuleSetTag = "serpium-routing-live";
    private const int MaximumExecutablePaths = 256;
    private const int MaximumDomains = 256;

    private static readonly HashSet<string> ForbiddenProcessNames = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "SerpiumVPN.exe",
        "sing-box.exe",
        "xray.exe",
        "xray-client.exe",
        "xray-key-client.exe"
    };

    private static readonly string[] XrayBridgeProcessNames =
    [
        "xray.exe",
        "xray-client.exe",
        "xray-key-client.exe"
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true
    };

    public static ProviderRuntimeProfile CompileProviderProfile(
        ProviderRuntimeProfile sourceProfile,
        IReadOnlyList<RoutingRegistryEntry> registryEntries) =>
        CompileProviderProfile(sourceProfile, registryEntries, ruleSetPath: null);

    public static ProviderRuntimeProfile CompileProviderProfile(
        ProviderRuntimeProfile sourceProfile,
        IReadOnlyList<RoutingRegistryEntry> registryEntries,
        string? ruleSetPath,
        bool applicationSelectionOnly = false)
    {
        ArgumentNullException.ThrowIfNull(sourceProfile);
        ArgumentNullException.ThrowIfNull(registryEntries);

        RoutingPolicy policy = BuildPolicy(registryEntries);
        string? normalizedRuleSetPath = NormalizeRuleSetPath(ruleSetPath);
        if (!policy.HasRules && normalizedRuleSetPath is null)
            throw new InvalidOperationException(
                "Для выборочной маршрутизации включите хотя бы одно приложение или сайт.");

        byte[] sourceConfiguration = sourceProfile.CopyConfiguration();
        byte[]? compiledConfiguration = null;
        try
        {
            JsonObject root = ParseRoot(sourceConfiguration);
            JsonObject route = RequireObject(root, "route");
            string proxyTag = ResolveProviderProxyTag(root, route);
            if (applicationSelectionOnly)
            {
                // Provider catch-all rules must not override the user's app switches.
                route["rules"] = CreateBaseRoute()["rules"]!.DeepClone();
                if (root["dns"] is JsonObject providerDns)
                    providerDns["rules"] = new JsonArray();
            }
            (int clashApiPort, string clashApiSecret) =
                ConfigurePrivateClashApi(root);

            EnsureDirectOutbound(root);
            ApplyRoutePolicy(
                route,
                policy,
                proxyTag,
                normalizedRuleSetPath);
            ApplyDnsPolicy(
                root,
                policy,
                proxyTag,
                normalizedRuleSetPath);

            compiledConfiguration = JsonSerializer.SerializeToUtf8Bytes(
                root,
                SerializerOptions);

            ProviderRuntimeProfile result = new(
                sourceProfile.ProviderName,
                sourceProfile.ProfileId,
                sourceProfile.Engine,
                compiledConfiguration,
                sourceProfile.Protocols,
                CountArray(root, "inbounds"),
                CountArray(root, "outbounds"),
                CountNestedArray(root, "route", "rules"),
                CountNestedArray(root, "dns", "servers"),
                BuildSafeSummary(sourceProfile.SafeSchemaSummary, policy),
                clashApiPort,
                clashApiSecret);

            compiledConfiguration = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceConfiguration);
            if (compiledConfiguration is not null)
                CryptographicOperations.ZeroMemory(compiledConfiguration);
        }
    }


    public static ProviderRuntimeProfile BuildXrayBridgeProfile(
        Guid savedProfileId,
        int socksPort,
        IReadOnlyList<RoutingRegistryEntry> registryEntries) =>
        BuildXrayBridgeProfile(
            savedProfileId,
            socksPort,
            registryEntries,
            ruleSetPath: null);

    public static ProviderRuntimeProfile BuildXrayBridgeProfile(
        Guid savedProfileId,
        int socksPort,
        IReadOnlyList<RoutingRegistryEntry> registryEntries,
        string? ruleSetPath)
    {
        if (savedProfileId == Guid.Empty)
            throw new ArgumentException("Идентификатор профиля пуст.", nameof(savedProfileId));
        if (socksPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(socksPort));
        ArgumentNullException.ThrowIfNull(registryEntries);

        RoutingPolicy policy = BuildPolicy(registryEntries);
        string? normalizedRuleSetPath = NormalizeRuleSetPath(ruleSetPath);
        if (!policy.HasRules && normalizedRuleSetPath is null)
            throw new InvalidOperationException(
                "Для Xray TUN включите хотя бы одно приложение или сайт.");

        string interfaceName = "sproute-" + savedProfileId.ToString("N")[..6];
        string tunAddress = BuildTunAddress(savedProfileId);

        JsonObject root = new()
        {
            ["log"] = new JsonObject
            {
                ["disabled"] = false,
                ["level"] = "info",
                ["output"] = string.Empty,
                ["timestamp"] = true
            },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "tun",
                    ["tag"] = "tun-in",
                    ["interface_name"] = interfaceName,
                    ["address"] = new JsonArray(tunAddress),
                    ["mtu"] = 1492,
                    ["auto_route"] = true,
                    ["endpoint_independent_nat"] = true,
                    ["stack"] = "mixed"
                }
            },
            ["outbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "socks",
                    ["tag"] = ProxyOutboundTag,
                    ["server"] = "127.0.0.1",
                    ["server_port"] = socksPort,
                    ["version"] = "5"
                },
                new JsonObject
                {
                    ["type"] = "direct",
                    ["tag"] = DirectOutboundTag
                }
            },
            ["route"] = CreateBaseRoute(),
            ["dns"] = CreateBaseDns(ProxyOutboundTag)
        };

        (int clashApiPort, string clashApiSecret) =
            ConfigurePrivateClashApi(root);

        ApplyRoutePolicy(
            RequireObject(root, "route"),
            policy,
            ProxyOutboundTag,
            normalizedRuleSetPath);
        ApplyDnsPolicy(
            root,
            policy,
            ProxyOutboundTag,
            normalizedRuleSetPath);

        byte[]? configuration = JsonSerializer.SerializeToUtf8Bytes(
            root,
            SerializerOptions);
        try
        {
            ProviderRuntimeProfile result = new(
                "Serpium Xray Bridge",
                savedProfileId.ToString("D"),
                "sing-box+xray",
                configuration,
                ["socks5", "xray"],
                CountArray(root, "inbounds"),
                CountArray(root, "outbounds"),
                CountNestedArray(root, "route", "rules"),
                CountNestedArray(root, "dns", "servers"),
                BuildSafeSummary(
                    "Xray SOCKS5 подключён к Serpium TUN без записи конфигурации на диск.",
                    policy),
                clashApiPort,
                clashApiSecret);

            configuration = null;
            return result;
        }
        finally
        {
            if (configuration is not null)
                CryptographicOperations.ZeroMemory(configuration);
        }
    }

    public static int CountEnabledRules(
        IEnumerable<RoutingRegistryEntry> registryEntries)
    {
        ArgumentNullException.ThrowIfNull(registryEntries);
        return registryEntries.Count(entry => entry.IsEnabled);
    }


    public static byte[] BuildRuleSetSource(
        IReadOnlyList<RoutingRegistryEntry> registryEntries,
        bool excludeXrayBridgeProcessesFromFullTunnel,
        bool fullTunnelWhenEmpty = true,
        string? activationProbe = null)
    {
        ArgumentNullException.ThrowIfNull(registryEntries);
        RoutingPolicy policy = BuildPolicy(registryEntries);
        JsonArray rules = new();

        if (!policy.HasRules)
        {
            // A contradictory logical match is valid even in engines that reject an
            // empty rule-set. No process can match both the rule and its inverse.
            rules.Add(fullTunnelWhenEmpty
                ? BuildFullTunnelRule(excludeXrayBridgeProcessesFromFullTunnel)
                : new JsonObject
                {
                    ["type"] = "logical",
                    ["mode"] = "and",
                    ["rules"] = new JsonArray
                    {
                        new JsonObject { ["network"] = new JsonArray("tcp", "udp") },
                        new JsonObject { ["network"] = new JsonArray("tcp", "udp"), ["invert"] = true }
                    }
                });
        }
        else
        {
            rules = WebsiteRoutingPolicy.BuildMatches(policy.ExecutablePaths, policy.Websites);
            if (rules.Count == 0) rules.Add(new JsonObject { ["network"] = new JsonArray("tcp", "udp"), ["invert"] = true });
        }

        if (activationProbe is not null)
        {
            SfpPolicyAcknowledgement.ValidateProbe(activationProbe);
            rules.Add(new JsonObject { ["domain"] = new JsonArray(activationProbe) });
        }

        JsonObject source = new()
        {
            ["version"] = 3,
            ["rules"] = rules
        };

        return JsonSerializer.SerializeToUtf8Bytes(
            source,
            SerializerOptions);
    }

    private static JsonObject BuildFullTunnelRule(
        bool excludeXrayBridgeProcesses)
    {
        JsonObject networkRule = new()
        {
            ["network"] = new JsonArray("tcp", "udp")
        };

        if (!excludeXrayBridgeProcesses)
            return networkRule;

        return new JsonObject
        {
            ["type"] = "logical",
            ["mode"] = "and",
            ["rules"] = new JsonArray
            {
                networkRule,
                new JsonObject
                {
                    ["process_name"] =
                        ToJsonArray(XrayBridgeProcessNames),
                    ["invert"] = true
                }
            }
        };
    }

    private static RoutingPolicy BuildPolicy(
        IReadOnlyList<RoutingRegistryEntry> registryEntries)
    {
        List<string> executablePaths = new();
        List<string> exactDomains = new();
        List<string> suffixDomains = new();
        int applicationCards = 0;
        int websiteCards = 0;

        foreach (RoutingRegistryEntry entry in registryEntries.Where(item => item.IsEnabled))
        {
            if (entry.Kind == RoutingTargetKind.Application)
            {
                applicationCards++;
                IEnumerable<string> candidates = entry.RelatedExecutables.Length > 0
                    ? entry.RelatedExecutables
                    : [entry.PrimaryValue];

                int beforeCount = executablePaths.Count;
                foreach (string candidate in candidates)
                {
                    if (string.IsNullOrWhiteSpace(candidate))
                        continue;

                    string fullPath;
                    try
                    {
                        fullPath = Path.GetFullPath(candidate.Trim().Trim('"'));
                    }
                    catch
                    {
                        continue;
                    }

                    if (!string.Equals(
                            Path.GetExtension(fullPath),
                            ".exe",
                            StringComparison.OrdinalIgnoreCase) ||
                        !File.Exists(fullPath))
                    {
                        continue;
                    }

                    string fileName = Path.GetFileName(fullPath);
                    if (ForbiddenProcessNames.Contains(fileName))
                    {
                        throw new InvalidOperationException(
                            $"Карточка «{entry.DisplayName}» содержит служебный процесс Serpium ({fileName}). " +
                            "Удалите его из состава группы, чтобы избежать сетевого цикла.");
                    }

                    if (!executablePaths.Contains(fullPath, StringComparer.OrdinalIgnoreCase))
                        executablePaths.Add(fullPath);
                }

                if (executablePaths.Count == beforeCount)
                {
                    throw new InvalidOperationException(
                        $"Для включённой карточки «{entry.DisplayName}» не найден ни один доступный EXE.");
                }
            }
            else if (entry.Kind == RoutingTargetKind.Website)
            {
                websiteCards++;
                string domain = SecureRoutingRegistry.NormalizeDomain(entry.PrimaryValue);
                if (!exactDomains.Contains(domain, StringComparer.OrdinalIgnoreCase))
                    exactDomains.Add(domain);

                if (entry.IncludeSubdomains)
                {
                    string suffix = "." + domain.TrimStart('.');
                    if (!suffixDomains.Contains(suffix, StringComparer.OrdinalIgnoreCase))
                        suffixDomains.Add(suffix);
                }
            }
        }

        if (executablePaths.Count > MaximumExecutablePaths)
        {
            throw new InvalidOperationException(
                $"Включено слишком много EXE: {executablePaths.Count}. Максимум: {MaximumExecutablePaths}.");
        }

        if (registryEntries.Count(item => item.Kind == RoutingTargetKind.Website) > MaximumDomains)
        {
            throw new InvalidOperationException(
                $"Включено слишком много доменных правил. Максимум: {MaximumDomains}.");
        }

        executablePaths.Sort(StringComparer.OrdinalIgnoreCase);
        exactDomains.Sort(StringComparer.OrdinalIgnoreCase);
        suffixDomains.Sort(StringComparer.OrdinalIgnoreCase);

        return new RoutingPolicy(
            executablePaths.ToArray(),
            exactDomains.ToArray(),
            suffixDomains.ToArray(),
            applicationCards,
            websiteCards, WebsiteRoutingPolicy.Read(registryEntries));
    }

    private static (int Port, string Secret)
        ConfigurePrivateClashApi(JsonObject root)
    {
        int port = FindAvailableLoopbackPort();
        string secret = Convert.ToHexString(
            RandomNumberGenerator.GetBytes(24));

        JsonObject experimental =
            root["experimental"] as JsonObject ??
            new JsonObject();

        root["experimental"] = experimental;
        experimental["clash_api"] = new JsonObject
        {
            ["external_controller"] = $"127.0.0.1:{port}",
            ["secret"] = secret
        };

        return (port, secret);
    }

    private static int FindAvailableLoopbackPort()
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        try
        {
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private static JsonObject ParseRoot(byte[] configurationUtf8)
    {
        JsonNode? node = JsonNode.Parse(configurationUtf8);
        return node as JsonObject ??
            throw new FormatException("Конфигурация sing-box не является JSON-объектом.");
    }

    private static JsonObject RequireObject(JsonObject parent, string propertyName)
    {
        return parent[propertyName] as JsonObject ??
            throw new FormatException($"Конфигурация sing-box не содержит объект {propertyName}.");
    }

    private static JsonArray RequireArray(JsonObject parent, string propertyName)
    {
        return parent[propertyName] as JsonArray ??
            throw new FormatException($"Конфигурация sing-box не содержит массив {propertyName}.");
    }

    private static string ResolveProviderProxyTag(JsonObject root, JsonObject route)
    {
        string? configuredFinal = route["final"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(configuredFinal) &&
            !string.Equals(configuredFinal, DirectOutboundTag, StringComparison.OrdinalIgnoreCase))
        {
            return configuredFinal;
        }

        JsonArray outbounds = RequireArray(root, "outbounds");
        foreach (JsonNode? node in outbounds)
        {
            if (node is not JsonObject outbound)
                continue;

            string? tag = outbound["tag"]?.GetValue<string>();
            if (string.Equals(tag, ProxyOutboundTag, StringComparison.OrdinalIgnoreCase))
                return ProxyOutboundTag;
        }

        throw new FormatException("В provider-конфигурации не найден VPN outbound.");
    }

    private static void EnsureDirectOutbound(JsonObject root)
    {
        JsonArray outbounds = RequireArray(root, "outbounds");
        bool directExists = outbounds
            .OfType<JsonObject>()
            .Any(outbound => string.Equals(
                outbound["tag"]?.GetValue<string>(),
                DirectOutboundTag,
                StringComparison.OrdinalIgnoreCase));

        if (!directExists)
        {
            outbounds.Add(new JsonObject
            {
                ["type"] = "direct",
                ["tag"] = DirectOutboundTag
            });
        }
    }

    private static JsonObject CreateBaseRoute()
    {
        return new JsonObject
        {
            ["rules"] = new JsonArray
            {
                new JsonObject
                {
                    ["inbound"] = "tun-in",
                    ["action"] = "sniff"
                },
                new JsonObject
                {
                    ["protocol"] = "dns",
                    ["action"] = "hijack-dns"
                },
                new JsonObject
                {
                    ["ip_cidr"] = new JsonArray("224.0.0.0/3"),
                    ["source_ip_cidr"] = new JsonArray("224.0.0.0/3"),
                    ["action"] = "reject"
                },
                new JsonObject
                {
                    ["ip_cidr"] = ToJsonArray(SfpDirectRouteExceptions.DestinationCidrs),
                    ["action"] = "route",
                    ["outbound"] = DirectOutboundTag
                }
            },
            ["auto_detect_interface"] = true,
            ["default_domain_resolver"] = CreateDefaultDomainResolver(),
            ["final"] = DirectOutboundTag,
            // Dynamic rule-set can gain process_path rules after startup.
            // Keep process lookup ready even when the profile starts in full-TUN mode.
            ["find_process"] = true
        };
    }

    private static JsonObject CreateBaseDns(string proxyTag)
    {
        return new JsonObject
        {
            ["servers"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "udp",
                    ["tag"] = ProxyDnsTag,
                    ["server"] = "8.8.8.8",
                    ["server_port"] = 53,
                    ["detour"] = proxyTag
                },
                CreateDirectDnsServer()
            },
            ["rules"] = new JsonArray(),
            ["final"] = DirectDnsTag,
            ["strategy"] = "ipv4_only",
            ["reverse_mapping"] = true
        };
    }

    private static void ApplyRoutePolicy(
        JsonObject route,
        RoutingPolicy policy,
        string proxyTag,
        string? ruleSetPath)
    {
        JsonArray rules;
        if (route["rules"] is JsonArray existingRules)
        {
            rules = existingRules;
        }
        else
        {
            rules = new JsonArray();
            route["rules"] = rules;
        }

        rules.Add(new JsonObject
        {
            ["domain"] = new JsonArray(ConnectivityProbeDomain),
            ["process_name"] = new JsonArray("SerpiumVPN.exe"),
            ["action"] = "route",
            ["outbound"] = proxyTag
        });

        if (ruleSetPath is not null)
        {
            ConfigureLocalRuleSet(route, ruleSetPath);
            rules.Add(new JsonObject
            {
                ["rule_set"] = DynamicRuleSetTag,
                ["action"] = "route",
                ["outbound"] = proxyTag
            });
        }
        else
        {
            foreach (JsonObject match in WebsiteRoutingPolicy.BuildMatches(policy.ExecutablePaths, policy.Websites).OfType<JsonObject>())
            {
                var rule = (JsonObject)match.DeepClone();
                rule["action"] = "route"; rule["outbound"] = proxyTag; rules.Add(rule);
            }
        }

        route["auto_detect_interface"] = true;
        route["default_domain_resolver"] = CreateDefaultDomainResolver();
        // Local rule-set hot reload may introduce process_path rules later.
        // Enabling lookup now avoids requiring a TUN/profile restart.
        route["find_process"] = true;
        route["final"] = DirectOutboundTag;
    }

    private static void ApplyDnsPolicy(
        JsonObject root,
        RoutingPolicy policy,
        string proxyTag,
        string? ruleSetPath)
    {
        JsonObject dns;
        if (root["dns"] is JsonObject existingDns)
        {
            dns = existingDns;
        }
        else
        {
            dns = new JsonObject();
            root["dns"] = dns;
        }

        JsonArray servers;
        if (dns["servers"] is JsonArray existingServers)
        {
            servers = existingServers;
        }
        else
        {
            servers = new JsonArray();
            dns["servers"] = servers;
        }

        string proxyDnsTag = ResolveProxyDnsTag(servers, proxyTag);
        EnsureDirectDnsServer(servers);

        JsonArray originalRules = dns["rules"] as JsonArray ?? new JsonArray();
        JsonArray selectiveRules = new();
        if (ruleSetPath is not null)
            SfpPolicyAcknowledgement.AddDnsRules(selectiveRules, DynamicRuleSetTag);

        selectiveRules.Add(new JsonObject
        {
            ["domain"] = new JsonArray(ConnectivityProbeDomain),
            ["action"] = "route",
            ["server"] = proxyDnsTag
        });

        if (ruleSetPath is not null)
        {
            selectiveRules.Add(new JsonObject
            {
                ["rule_set"] = DynamicRuleSetTag,
                ["action"] = "route",
                ["server"] = proxyDnsTag
            });
        }
        else
        {
            foreach (JsonObject match in WebsiteRoutingPolicy.BuildMatches(policy.ExecutablePaths, policy.Websites).OfType<JsonObject>())
            {
                var rule = (JsonObject)match.DeepClone();
                rule["action"] = "route"; rule["server"] = proxyDnsTag; selectiveRules.Add(rule);
            }
        }

        foreach (JsonNode? originalRule in originalRules)
            selectiveRules.Add(originalRule?.DeepClone());

        dns["rules"] = selectiveRules;
        dns["final"] = DirectDnsTag;
        dns["reverse_mapping"] = true;
        // A domain switched to VPN must not reuse the direct resolver's cached answer.
        dns["independent_cache"] = true;
        if (dns["strategy"] is null)
            dns["strategy"] = "ipv4_only";
    }

    private static void ConfigureLocalRuleSet(
        JsonObject route,
        string ruleSetPath)
    {
        JsonArray ruleSets;
        if (route["rule_set"] is JsonArray existingRuleSets)
        {
            ruleSets = existingRuleSets;
        }
        else
        {
            ruleSets = new JsonArray();
            route["rule_set"] = ruleSets;
        }

        for (int index = ruleSets.Count - 1; index >= 0; index--)
        {
            if (ruleSets[index] is JsonObject existing &&
                string.Equals(
                    existing["tag"]?.GetValue<string>(),
                    DynamicRuleSetTag,
                    StringComparison.OrdinalIgnoreCase))
            {
                ruleSets.RemoveAt(index);
            }
        }

        ruleSets.Add(new JsonObject
        {
            ["type"] = "local",
            ["tag"] = DynamicRuleSetTag,
            ["format"] = "source",
            ["path"] = ruleSetPath
        });
    }

    private static string? NormalizeRuleSetPath(string? ruleSetPath)
    {
        if (string.IsNullOrWhiteSpace(ruleSetPath))
            return null;

        string fullPath = Path.GetFullPath(ruleSetPath.Trim());
        if (!Path.IsPathFullyQualified(fullPath))
            throw new ArgumentException("Путь dynamic rule-set должен быть абсолютным.", nameof(ruleSetPath));
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("Dynamic rule-set ещё не подготовлен.", fullPath);
        if (!string.Equals(Path.GetExtension(fullPath), ".json", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Dynamic rule-set должен использовать source JSON.", nameof(ruleSetPath));

        return fullPath;
    }

    private static string ResolveProxyDnsTag(JsonArray servers, string proxyTag)
    {
        foreach (JsonNode? node in servers)
        {
            if (node is not JsonObject server)
                continue;

            string? tag = server["tag"]?.GetValue<string>();
            string? detour = server["detour"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(tag) &&
                string.Equals(detour, proxyTag, StringComparison.OrdinalIgnoreCase))
            {
                return tag;
            }
        }

        foreach (JsonNode? node in servers)
        {
            if (node is JsonObject server &&
                !string.IsNullOrWhiteSpace(server["tag"]?.GetValue<string>()))
            {
                return server["tag"]!.GetValue<string>();
            }
        }

        JsonObject proxyDnsServer = new()
        {
            ["type"] = "udp",
            ["tag"] = ProxyDnsTag,
            ["server"] = "8.8.8.8",
            ["server_port"] = 53,
            ["detour"] = proxyTag
        };
        servers.Add(proxyDnsServer);
        return ProxyDnsTag;
    }

    private static void EnsureDirectDnsServer(JsonArray servers)
    {
        JsonObject? directServer = servers
            .OfType<JsonObject>()
            .FirstOrDefault(server => string.Equals(
                server["tag"]?.GetValue<string>(),
                DirectDnsTag,
                StringComparison.OrdinalIgnoreCase));

        if (directServer is null)
        {
            servers.Add(CreateDirectDnsServer());
            return;
        }

        string? detour = directServer["detour"]?.GetValue<string>();
        if (string.Equals(
                detour,
                DirectOutboundTag,
                StringComparison.OrdinalIgnoreCase))
        {
            directServer.Remove("detour");
        }
    }

    private static JsonObject CreateDirectDnsServer()
    {
        return new JsonObject
        {
            ["type"] = "udp",
            ["tag"] = DirectDnsTag,
            ["server"] = "1.1.1.1",
            ["server_port"] = 53
        };
    }

    private static JsonObject CreateDefaultDomainResolver()
    {
        return new JsonObject
        {
            ["server"] = DirectDnsTag,
            ["strategy"] = "ipv4_only"
        };
    }

    private static JsonArray ToJsonArray(IEnumerable<string> values)
    {
        JsonArray array = new();
        foreach (string value in values)
            array.Add(value);
        return array;
    }

    private static int CountArray(JsonObject root, string propertyName) =>
        root[propertyName] is JsonArray array ? array.Count : 0;

    private static int CountNestedArray(
        JsonObject root,
        string objectName,
        string arrayName) =>
        root[objectName] is JsonObject nested &&
        nested[arrayName] is JsonArray array
            ? array.Count
            : 0;

    private static string BuildSafeSummary(
        string baseSummary,
        RoutingPolicy policy)
    {
        if (!policy.HasRules)
        {
            return baseSummary.Trim() + Environment.NewLine +
                "Динамическая маршрутизация: полный TUN для TCP/UDP; " +
                "изменения карточек применяются без переподключения.";
        }

        return baseSummary.Trim() + Environment.NewLine +
            $"Выборочная маршрутизация: карточек приложений {policy.ApplicationCards}, " +
            $"EXE {policy.ExecutablePaths.Length}, сайтов {policy.WebsiteCards}; " +
            "остальной трафик направляется напрямую.";
    }

    private static string BuildTunAddress(Guid profileId)
    {
        byte[] hash = SHA256.HashData(profileId.ToByteArray());
        try
        {
            int thirdOctet = hash[0];
            int hostOctet = (hash[1] % 14) + 1;
            return $"172.30.{thirdOctet}.{hostOctet}/28";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private sealed record RoutingPolicy(
        string[] ExecutablePaths,
        string[] ExactDomains,
        string[] SuffixDomains,
        int ApplicationCards,
        int WebsiteCards, WebsiteRoute[] Websites)
    {
        public bool HasRules =>
            ExecutablePaths.Length > 0 ||
            ExactDomains.Length > 0 ||
            SuffixDomains.Length > 0 || Websites.Length > 0;
    }
}
