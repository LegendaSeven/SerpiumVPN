using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using SerpiumVPN.Relay.Diagnostics;

namespace SerpiumVPN.Relay.Parser;

/// <summary>HTTPS subscriptions use public destinations, checked and pinned at socket creation.</summary>
public static class PublicSubscriptionTransport
{
    public static Uri ValidateUri(string source)
    {
        if (source.Length > 8192 || !Uri.TryCreate(source, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 ||
            Uri.CheckHostName(uri.Host) == UriHostNameType.Unknown ||
            (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address) && !IsPublicAddress(address)))
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
        return new UriBuilder(uri) { Fragment = "" }.Uri;
    }

    public static HttpClient CreateClient() => new(new SocketsHttpHandler
    {
        UseProxy = false, UseCookies = false, AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.All,
        ConnectCallback = async (context, token) =>
        {
            var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, token).ConfigureAwait(false);
            if (addresses.Length == 0 || addresses.Any(address => !IsPublicAddress(address)))
                throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
            foreach (var address in addresses)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch (SocketException) { socket.Dispose(); }
                catch { socket.Dispose(); throw; }
            }
            throw new HttpRequestException("Subscription unavailable.");
        }
    }) { Timeout = Timeout.InfiniteTimeSpan };

    public static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) return IsPublicAddress(address.MapToIPv4());
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;
        byte[] b = address.GetAddressBytes();
        if (b.Length == 4)
            return b[0] is not (0 or 10 or 127) && b[0] < 224 && !(b[0] == 169 && b[1] == 254) &&
                !(b[0] == 172 && b[1] is >= 16 and <= 31) && !(b[0] == 192 && b[1] == 168) &&
                !(b[0] == 100 && b[1] is >= 64 and <= 127) && !(b[0] == 198 && b[1] is 18 or 19) &&
                !(b[0] == 192 && b[1] == 0 && b[2] is 0 or 2) &&
                !(b[0] == 198 && b[1] == 51 && b[2] == 100) && !(b[0] == 203 && b[1] == 0 && b[2] == 113);
        // Only global IPv6 unicast; exclude embedded IPv4 tunnels and documentation addresses.
        return (b[0] & 0xe0) == 0x20 && !(b[0] == 0x20 && b[1] == 0x02) &&
            !(b[0] == 0x20 && b[1] == 0x01 && ((b[2] == 0 && b[3] == 0) || (b[2] == 0x0d && b[3] == 0xb8)));
    }
}
