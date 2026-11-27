using System.Text;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Providers;

public static class OutlineProfileFactory
{
    public static JsonObject CreateOutbound(SerpiumConnectionProfile profile)
    {
        if (profile.Protocol != "shadowsocks") throw new ArgumentException("Expected Outline profile.");
        ShadowsocksKeyParser.ValidatePrefix(profile.Encryption, profile.OutlinePrefix);
        var outbound = new JsonObject
        {
            ["type"] = "shadowsocks", ["tag"] = "proxy", ["server"] = profile.Server,
            ["server_port"] = profile.Port, ["method"] = profile.Encryption, ["password"] = profile.Password
        };
        if (profile.OutlinePrefix.Length > 0)
            outbound[SerpiumVPN.Relay.Outline.OutlinePrefixConfiguration.Marker] = Convert.ToBase64String(Encoding.Latin1.GetBytes(profile.OutlinePrefix));
        return outbound;
    }

    public static ProviderRuntimeProfile Create(SerpiumConnectionProfile profile)
    {
        var config = new JsonObject
        {
            ["outbounds"] = new JsonArray(CreateOutbound(profile)),
            ["route"] = new JsonObject { ["final"] = "proxy" }
        };
        string name = SensitiveDiagnosticRedactor.SanitizeProfileName(profile.Name);
        return new ProviderRuntimeProfile("Outline", string.IsNullOrWhiteSpace(name) ? "Outline" : name,
            "sing-box", Encoding.UTF8.GetBytes(config.ToJsonString()), ["shadowsocks"], 0, 1, 0, 0);
    }
}
