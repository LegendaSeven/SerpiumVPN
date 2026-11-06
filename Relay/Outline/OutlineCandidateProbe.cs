using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.Providers;

namespace SerpiumVPN.Relay.Outline;

/// <summary>A short-lived, authenticated loopback proxy. No TUN, route changes or config files.</summary>
public sealed class OutlineCandidateProbe(string executable)
{
    public async Task CheckAsync(string key, CancellationToken token)
    {
        if (!File.Exists(executable)) throw new ConnectionCheckException(ConnectionFailureKind.EngineMissing);
        var profile = new ShadowsocksKeyParser().Parse(key).Profile ?? throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
        Process? process = null;
        Task? stdout = null, stderr = null;
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(profile.Server, token);
            if (addresses.Length == 0 || addresses.Any(ip => !OutlineKeySource.IsPublicAddress(ip)))
                throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
            int port;
            using (var listener = new TcpListener(IPAddress.Loopback, 0))
            { listener.Start(); port = ((IPEndPoint)listener.LocalEndpoint).Port; }
            string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            var address = addresses.OrderBy(ip => ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).First();
            var config = BuildProbeConfiguration(profile, address, port, secret);
            var info = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(executable)!,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (string argument in new[] { "run", "--disable-color", "-c", "stdin" }) info.ArgumentList.Add(argument);
            process = Process.Start(info) ?? throw new ConnectionCheckException(ConnectionFailureKind.ProbeUnavailable);
            stdout = DrainAsync(process.StandardOutput); stderr = DrainAsync(process.StandardError);
            byte[] bytes = Encoding.UTF8.GetBytes(config.ToJsonString());
            try { await process.StandardInput.BaseStream.WriteAsync(bytes, token); process.StandardInput.Close(); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
            startup.CancelAfter(TimeSpan.FromSeconds(3));
            while (true)
            {
                if (process.HasExited) throw new ConnectionCheckException(ConnectionFailureKind.InvalidConfiguration);
                try
                {
                    using var socket = new TcpClient();
                    await socket.ConnectAsync(IPAddress.Loopback, port, startup.Token);
                    break;
                }
                catch (SocketException) { await Task.Delay(100, startup.Token); }
            }
            using var client = new HttpClient(new HttpClientHandler
            {
                Proxy = new WebProxy("socks5://127.0.0.1:" + port) { Credentials = new NetworkCredential("probe", secret) },
                UseProxy = true, UseCookies = false, AllowAutoRedirect = false
            }) { Timeout = Timeout.InfiniteTimeSpan };
            using var response = await client.GetAsync("https://www.gstatic.com/generate_204", HttpCompletionOption.ResponseHeadersRead, token);
            if (response.StatusCode != HttpStatusCode.NoContent)
                throw new ConnectionCheckException(ConnectionFailureKind.ProbeFailed);
            token.ThrowIfCancellationRequested();
        }
        catch (Exception error) when (error is HttpRequestException or SocketException or IOException)
        { throw new ConnectionCheckException(ConnectionFailureKind.ProbeFailed); }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
                    if (stdout is not null && stderr is not null) await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2));
                }
                catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException or TimeoutException)
                { throw new ConnectionCheckException(ConnectionFailureKind.ProbeUnavailable); }
                finally { process.Dispose(); }
            }
        }
    }

    private static JsonObject BuildProbeConfiguration(SerpiumConnectionProfile profile, IPAddress address, int port, string secret)
    {
        var outbound = OutlineProfileFactory.CreateOutbound(profile);
        outbound["server"] = address.ToString(); // Pin the checked address for this probe.
        return new JsonObject
        {
            ["log"] = new JsonObject { ["disabled"] = true },
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = port,
                ["users"] = new JsonArray(new JsonObject { ["username"] = "probe", ["password"] = secret })
            }),
            ["outbounds"] = new JsonArray(outbound), ["route"] = new JsonObject { ["final"] = "proxy" }
        };
    }

    private static async Task DrainAsync(StreamReader reader)
    {
        char[] buffer = new char[4096];
        try { while (await reader.ReadAsync(buffer) > 0) Array.Clear(buffer); }
        finally { Array.Clear(buffer); }
    }
}
