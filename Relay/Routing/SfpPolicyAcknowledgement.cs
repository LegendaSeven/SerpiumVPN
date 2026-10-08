using System.Text.Json.Nodes;

namespace SerpiumVPN.Relay.Routing;

/// <summary>A private, local-only challenge proving which shared rule-set the engine has loaded.</summary>
public static class SfpPolicyAcknowledgement
{
    public const string DomainSuffix = "sfp.invalid";
    public static string CreateProbe() => Guid.NewGuid().ToString("N") + "." + DomainSuffix;

    public static void ValidateProbe(string probe)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(probe);
        if (probe.Length != 32 + 1 + DomainSuffix.Length ||
            !probe.EndsWith("." + DomainSuffix, StringComparison.Ordinal) ||
            !Guid.TryParseExact(probe[..32], "N", out _))
            throw new ArgumentException("Invalid SFP activation challenge.", nameof(probe));
    }

    public static void AddDnsRules(JsonArray rules, string ruleSetTag)
    {
        // Both answers are generated inside sing-box, without asking any DNS server.
        // Cache bypass prevents an early NXDOMAIN response from masking a later reload.
        rules.Add(new JsonObject
        {
            ["domain_suffix"] = DomainSuffix, ["action"] = "route-options", ["disable_cache"] = true
        });
        rules.Add(new JsonObject
        {
            ["type"] = "logical", ["mode"] = "and",
            ["rules"] = new JsonArray(
                new JsonObject { ["domain_suffix"] = DomainSuffix },
                new JsonObject { ["rule_set"] = ruleSetTag }),
            ["action"] = "predefined", ["rcode"] = "NOERROR"
        });
        rules.Add(new JsonObject
        {
            ["domain_suffix"] = DomainSuffix, ["action"] = "predefined", ["rcode"] = "NXDOMAIN"
        });
    }
}
