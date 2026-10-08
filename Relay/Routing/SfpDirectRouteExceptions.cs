using System.Net;
using System.Net.Sockets;

namespace SerpiumVPN.Relay.Routing;

/// <summary>Destination exceptions shared by compiled routes and live connection cleanup.</summary>
public static class SfpDirectRouteExceptions
{
    public static IReadOnlyList<string> DestinationCidrs { get; } = Array.AsReadOnly(new[]
    {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    });

    private static readonly IPNetwork[] Networks = DestinationCidrs.Select(IPNetwork.Parse).ToArray();

    public static bool BypassesVpn(string? destinationIp)
    {
        // Match only the numeric destination and exactly the ranges emitted to the engine.
        // A host name, source address or unknown destination cannot grant an exception.
        return IPAddress.TryParse(destinationIp, out var address) &&
            address.AddressFamily == AddressFamily.InterNetwork &&
            Networks.Any(network => network.Contains(address));
    }
}
