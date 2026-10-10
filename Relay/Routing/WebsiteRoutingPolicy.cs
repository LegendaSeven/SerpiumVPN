using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SerpiumVPN.Relay.Routing;

internal sealed record WebsiteRoute(string Domain, bool IncludeSubdomains, bool Enabled)
{
    public bool Matches(string host) => string.Equals(host, Domain, StringComparison.OrdinalIgnoreCase) ||
        (IncludeSubdomains && host.EndsWith("." + Domain, StringComparison.OrdinalIgnoreCase));
    public JsonObject ToMatch() => IncludeSubdomains
        ? new JsonObject { ["domain"] = new JsonArray(Domain), ["domain_suffix"] = new JsonArray("." + Domain) }
        : new JsonObject { ["domain"] = new JsonArray(Domain) };
}

internal static class WebsiteRoutingPolicy
{
    internal static WebsiteRoute[] Read(IEnumerable<RoutingRegistryEntry> entries) => entries
        .Where(entry => entry.Kind == RoutingTargetKind.Website)
        .Select(entry => new WebsiteRoute(SecureRoutingRegistry.NormalizeDomain(entry.PrimaryValue), entry.IncludeSubdomains, entry.IsEnabled))
        .OrderByDescending(entry => entry.Domain.Length).ToArray();

    // Every explicit website rule overrides the app rule; the most specific host wins.
    // One atomic rule-set drives both routing and DNS, avoiding partly applied updates.
    internal static JsonArray BuildMatches(string[] paths, WebsiteRoute[] sites)
    {
        var result = new JsonArray();
        if (paths.Length > 0)
        {
            var app = new JsonObject { ["process_path"] = new JsonArray(paths.Select(path => (JsonNode?)JsonValue.Create(path)).ToArray()) };
            result.Add(Exclude(app, sites));
        }
        foreach (var site in sites.Where(site => site.Enabled))
            result.Add(Exclude(site.ToMatch(), sites.Where(other => other.Domain.Length > site.Domain.Length && site.Matches(other.Domain))));
        return result;
    }

    private static JsonObject Exclude(JsonObject match, IEnumerable<WebsiteRoute> excluded)
    {
        var exclusions = new JsonArray(excluded.Select(site => (JsonNode)site.ToMatch()).ToArray());
        if (exclusions.Count == 0) return match;
        return new JsonObject { ["type"] = "logical", ["mode"] = "and", ["rules"] = new JsonArray(match,
            new JsonObject { ["type"] = "logical", ["mode"] = "or", ["rules"] = exclusions, ["invert"] = true }) };
    }
}

/// <summary>Evaluates current policy only for connections affected by an edit.</summary>
public sealed class SfpRoutingPolicy
{
    private readonly HashSet<string> _enabledPaths;
    private readonly HashSet<string> _affectedPaths;
    private readonly WebsiteRoute[] _sites, _affectedSites;
    public SfpRoutingPolicy(IEnumerable<RoutingRegistryEntry> entries, IEnumerable<RoutingRegistryEntry> affected)
    {
        var current = entries.ToArray(); var changes = affected.ToArray();
        _sites = WebsiteRoutingPolicy.Read(current);
        _affectedSites = WebsiteRoutingPolicy.Read(changes);
        _enabledPaths = Paths(current.Where(item => item.IsEnabled));
        _affectedPaths = Paths(changes);
    }
    private static HashSet<string> Paths(IEnumerable<RoutingRegistryEntry> entries) => new(entries
        .Where(item => item.Kind == RoutingTargetKind.Application)
        .SelectMany(item => item.RelatedExecutables.Append(item.PrimaryValue)).Select(NormalizePath), StringComparer.OrdinalIgnoreCase);
    private static string NormalizePath(string value)
    {
        string path = value.Trim().Trim('"').Replace('/', '\\');
        return path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal) ? path[4..] : path;
    }
    private static string GetString(JsonElement metadata, string name) => metadata.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String ? value.GetString()! : "";
    public bool TryGetDesiredVpn(JsonElement metadata, out bool vpn)
    {
        vpn = false;
        string process = NormalizePath(GetString(metadata, "processPath"));
        string host = GetString(metadata, "host").TrimEnd('.');
        // Runtime metadata carries hosts, never URL paths. Normalize IDNs identically to saved rules.
        if (host.Length > 0)
        {
            try { host = new System.Globalization.IdnMapping().GetAscii(host).ToLowerInvariant(); }
            catch (ArgumentException) { host = ""; }
        }
        if (!_affectedPaths.Contains(process) && !_affectedSites.Any(site => site.Matches(host))) return false;
        if (SfpDirectRouteExceptions.BypassesVpn(GetString(metadata, "destinationIP"))) return true;
        var site = _sites.FirstOrDefault(site => site.Matches(host));
        vpn = site?.Enabled ?? _enabledPaths.Contains(process);
        return true;
    }
}
