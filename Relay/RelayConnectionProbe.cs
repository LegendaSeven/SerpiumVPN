using System.Net.Sockets;

namespace SerpiumVPN.Relay;

public static class RelayConnectionProbe
{
    public static async Task<bool> CanConnectAsync(
        string host,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        // A userspace tsnet client does not install an OS route to 100.64.0.0/10.
        // When the requested endpoint is currently represented by our local
        // SerpiumNet bridge, probe the bridge itself instead.
        if (SerpiumNetClientConfig.TryReadBridgeRuntime(
                out SerpiumNetBridgeRuntime? bridge) &&
            bridge is not null &&
            string.Equals(bridge.RemoteHost, host, StringComparison.OrdinalIgnoreCase) &&
            bridge.RemotePort == port)
        {
            host = "127.0.0.1";
            port = bridge.LocalPort;
        }

        using TcpClient client = new();
        using CancellationTokenSource timeoutCts =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            await client.ConnectAsync(host, port, timeoutCts.Token);
            return client.Connected;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return false;
        }
    }
}
