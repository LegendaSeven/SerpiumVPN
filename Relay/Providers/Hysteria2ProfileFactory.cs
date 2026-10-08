using System.Text;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Providers;

public static class Hysteria2ProfileFactory
{
    public static ProviderRuntimeProfile Create(SerpiumConnectionProfile profile)
    {
        if (profile.Protocol != "hysteria2") throw new ArgumentException("Expected Hysteria2 profile.", nameof(profile));
        var outbound = new JsonObject
        {
            ["type"] = "hysteria2", ["tag"] = "proxy", ["server"] = profile.Server,
            ["server_port"] = profile.Port, ["password"] = profile.Password,
            ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = profile.ServerName, ["insecure"] = profile.AllowInsecure }
        };
        if (profile.Obfuscation.Length > 0)
            outbound["obfs"] = new JsonObject { ["type"] = profile.Obfuscation, ["password"] = profile.ObfuscationPassword };
        var config = new JsonObject { ["outbounds"] = new JsonArray(outbound), ["route"] = new JsonObject { ["final"] = "proxy" } };
        string safeName = SensitiveDiagnosticRedactor.SanitizeProfileName(profile.Name);
        if (string.IsNullOrWhiteSpace(safeName)) safeName = "Hysteria2";
        // Existing routing compiler adds the application's managed TUN, DNS and live rule-set.
        return new ProviderRuntimeProfile("Hysteria2", safeName, "sing-box", Encoding.UTF8.GetBytes(config.ToJsonString()),
            ["hysteria2"], 0, 1, 0, 0);
    }
}
