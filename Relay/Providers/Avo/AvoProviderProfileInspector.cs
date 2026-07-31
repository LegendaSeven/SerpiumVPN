using System.Security.Cryptography;
using System.Text.Json;

namespace SerpiumVPN.Relay.Providers.Avo;

internal static class AvoProviderProfileInspector
{
    public static ProviderRuntimeProfile Create(
        string profileId,
        byte[] plaintextUtf8)
    {
        ArgumentNullException.ThrowIfNull(plaintextUtf8);

        byte[]? runtimeConfiguration = null;
        try
        {
            using JsonDocument document = JsonDocument.Parse(plaintextUtf8);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new FormatException("Расшифрованный AVO-профиль не является JSON-объектом.");

            JsonElement root = document.RootElement;
            string safeSchemaSummary = AvoProviderJsonSchemaInspector.Inspect(root);

            if (LooksLikeSingBox(root))
            {
                int inboundCount = GetArrayCount(root, "inbounds");
                int outboundCount = GetArrayCount(root, "outbounds");
                int routeRuleCount = GetNestedArrayCount(root, "route", "rules");
                int dnsServerCount = GetNestedArrayCount(root, "dns", "servers");
                string[] protocols = ReadOutboundTypes(root);

                runtimeConfiguration = plaintextUtf8;
                plaintextUtf8 = Array.Empty<byte>();

                ProviderRuntimeProfile nativeProfile = new(
                    "Avo",
                    profileId,
                    "sing-box",
                    runtimeConfiguration,
                    protocols,
                    inboundCount,
                    outboundCount,
                    routeRuleCount,
                    dnsServerCount,
                    safeSchemaSummary);

                runtimeConfiguration = null;
                return nativeProfile;
            }

            AvoProviderJsonMappingResult mapped =
                AvoProviderJsonMapper.Map(profileId, root);
            runtimeConfiguration = mapped.ConfigurationUtf8;

            CryptographicOperations.ZeroMemory(plaintextUtf8);
            plaintextUtf8 = Array.Empty<byte>();

            string combinedSafeSummary =
                safeSchemaSummary + Environment.NewLine + Environment.NewLine +
                "Безопасный результат маппинга:" + Environment.NewLine +
                mapped.SafeMappingSummary;

            ProviderRuntimeProfile mappedProfile = new(
                "Avo",
                profileId,
                "sing-box",
                runtimeConfiguration,
                mapped.Protocols,
                mapped.InboundCount,
                mapped.OutboundCount,
                mapped.RouteRuleCount,
                mapped.DnsServerCount,
                combinedSafeSummary);

            runtimeConfiguration = null;
            return mappedProfile;
        }
        catch
        {
            if (plaintextUtf8.Length > 0)
                CryptographicOperations.ZeroMemory(plaintextUtf8);
            if (runtimeConfiguration is not null)
                CryptographicOperations.ZeroMemory(runtimeConfiguration);
            throw;
        }
    }

    private static bool LooksLikeSingBox(JsonElement root) =>
        root.TryGetProperty("outbounds", out JsonElement outbounds) &&
        outbounds.ValueKind == JsonValueKind.Array &&
        (root.TryGetProperty("route", out _) || root.TryGetProperty("dns", out _));

    private static int GetArrayCount(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out JsonElement value) &&
               value.ValueKind == JsonValueKind.Array
            ? value.GetArrayLength()
            : 0;
    }

    private static int GetNestedArrayCount(
        JsonElement root,
        string objectName,
        string arrayName)
    {
        if (!root.TryGetProperty(objectName, out JsonElement objectValue) ||
            objectValue.ValueKind != JsonValueKind.Object ||
            !objectValue.TryGetProperty(arrayName, out JsonElement arrayValue) ||
            arrayValue.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        return arrayValue.GetArrayLength();
    }

    private static string[] ReadOutboundTypes(JsonElement root)
    {
        if (!root.TryGetProperty("outbounds", out JsonElement outbounds) ||
            outbounds.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        HashSet<string> values = new(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement outbound in outbounds.EnumerateArray())
        {
            if (outbound.ValueKind != JsonValueKind.Object ||
                !outbound.TryGetProperty("type", out JsonElement typeValue) ||
                typeValue.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            string? type = typeValue.GetString();
            if (!string.IsNullOrWhiteSpace(type) &&
                type is not ("direct" or "block" or "urltest" or "selector"))
            {
                values.Add(type.Trim());
            }
        }

        return values.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
