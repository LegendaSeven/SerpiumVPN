using System.Text.Json.Serialization;

namespace SerpiumVPN.Relay;

public sealed class RelayKey
{
    [JsonPropertyName("schema")]
    public int Schema { get; set; } = 1;

    [JsonPropertyName("name")]
    public string Name { get; set; } = "Serpium Gateway";

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "tailscale";

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "vless";

    [JsonPropertyName("host")]
    public string Host { get; set; } = "";

    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("uuid")]
    public string Uuid { get; set; } = "";

    [JsonPropertyName("network")]
    public string Network { get; set; } = "tcp";
}
