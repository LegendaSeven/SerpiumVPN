using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Xray;

static class Program
{
    static int checks;
    static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++; Console.WriteLine("PASS " + message);
    }

    static async Task<int> Main(string[] args)
    {
        try
        {
            string fixtures = Path.GetFullPath(args[0]), engines = Path.GetFullPath(args[1]);
            await CheckSources();
            foreach (string mode in new[] { "outline", "reality" })
                await CheckServer(mode, Path.Combine(fixtures, mode), engines, args.Length > 2 ? args[2] : "python");
            Console.WriteLine("SERVER_CLIENT_CHECKS_PASS=" + checks);
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(SensitiveDiagnosticRedactor.RedactText(error.ToString()));
            return 1;
        }
    }

    static async Task Rejected(Func<Task> action, ConnectionFailureKind kind, string message)
    {
        try { await action(); throw new Exception("Expected rejection: " + message); }
        catch (ConnectionCheckException error) { Check(error.Kind == kind, message); }
    }

    static async Task CheckSources()
    {
        string key = "ss://YWVzLTI1Ni1nY206dGVzdC1vbmx5@vpn.example.com:20000/?outline=1#Fixture";
        foreach (string uri in new[] { "https://127.0.0.1/secret", "https://[::1]/", "https://169.254.169.254/metadata", "https://user:secret@vpn.example.com/", "https://192.168.1.1/key", "https://[::ffff:127.0.0.1]/" })
        {
            int requests = 0;
            using var http = new HttpClient(new Stub((r, t) => { requests++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(key) }); }));
            await Rejected(() => new ConnectionKeySourceResolver(http).ResolveAsync(uri), ConnectionFailureKind.SubscriptionInvalid, "private or authenticated HTTPS source rejected");
            Check(requests == 0, "source rejected before HTTP request");
        }
        using (var http = new HttpClient(new Stub((r, t) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(key) }))))
        {
            Check((await new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/subscription")).Single() == key, "ordinary HTTPS source import");
            Check((await new ConnectionKeySourceResolver(http).ResolveAsync("ssconf://vpn.example.com/dynamic")).Single() == key, "dynamic Outline uses the same secure transport");
        }
        int redirects = 0;
        using (var http = new HttpClient(new Stub((r, t) => { redirects++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://127.0.0.1/private") } }); })))
        {
            await Rejected(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/subscription"), ConnectionFailureKind.SubscriptionInvalid, "redirect to local service rejected");
            Check(redirects == 1, "private redirect destination was never contacted");
        }
        using (var http = new HttpClient(new Stub((r, t) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Gone)))))
            await Rejected(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/expired"), ConnectionFailureKind.SubscriptionExpired, "expired subscription has an actionable error");
        using (var http = new HttpClient(new Stub(async (r, t) => { await Task.Delay(Timeout.Infinite, t); return new HttpResponseMessage(); })))
        using (var cancel = new CancellationTokenSource(50))
        {
            try { await new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/slow", cancel.Token); throw new Exception("Cancellation lost"); }
            catch (OperationCanceledException) { Check(true, "Stop cancels subscription loading"); }
        }
        foreach (string ip in new[] { "192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "100.64.0.1", "2002:7f00:1::" })
            Check(!PublicSubscriptionTransport.IsPublicAddress(IPAddress.Parse(ip)), "non-public source range rejected " + ip);
        // This uses the real socket factory: localhost must fail before opening a socket even with a public-looking URL syntax.
        await Rejected(() => new ConnectionKeySourceResolver().ResolveAsync("https://localhost/key"), ConnectionFailureKind.SubscriptionUnavailable, "DNS resolution to loopback blocked");
    }

    static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    static async Task<Process> Start(string executable, JsonObject config, bool xray, List<Process> processes, List<Task<string>> drains)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "run", xray ? "-config" : "-c", xray ? "stdin:" : "stdin" }) info.ArgumentList.Add(arg);
        var child = Process.Start(info)!; processes.Add(child);
        drains.Add(child.StandardOutput.ReadToEndAsync()); drains.Add(child.StandardError.ReadToEndAsync());
        await child.StandardInput.WriteAsync(config.ToJsonString()); child.StandardInput.Close();
        return child;
    }

    static async Task ListenReady(int port, Process process, CancellationToken token)
    {
        while (true)
        {
            if (process.HasExited) throw new Exception("Test transport exited before listening");
            try { using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, port, token); return; }
            catch (SocketException) { await Task.Delay(50, token); }
        }
    }

    static async Task CheckServer(string mode, string directory, string engines, string python)
    {
        string key = File.ReadAllText(Path.Combine(directory, "key.txt"));
        Check(ConnectionKeySourceResolver.ParseKeys(key).Count == 1, mode + " generated key passes actual importer");
        var parsed = new SerpiumParser().Parse(key);
        Check(parsed.Success, mode + " generated key parsed");
        var profile = parsed.Profile!;
        var server = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "config.json")))!.AsObject();
        int serverPort = FreePort(), socksPort = FreePort();
        bool xray = mode == "reality";
        string executable = Path.Combine(engines, xray ? "xray.exe" : "sing-box.exe");
        var client = xray ? JsonNode.Parse(SerpiumXrayConfigBuilder.Build(profile, socksPort, ""))!.AsObject() : new JsonObject
        {
            ["log"] = new JsonObject { ["disabled"] = true },
            ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "socks", ["listen"] = "127.0.0.1", ["listen_port"] = socksPort }),
            ["outbounds"] = new JsonArray(OutlineProfileFactory.CreateOutbound(profile)),
            ["route"] = new JsonObject { ["final"] = "proxy" }
        };
        // The production generator never exposes loopback/private destinations. Only this isolated fixture does.
        if (xray)
        {
            server["log"] = new JsonObject { ["loglevel"] = "debug", ["access"] = "none", ["error"] = "" };
            client["log"] = new JsonObject { ["loglevel"] = "debug", ["access"] = "none", ["error"] = "" };
            server["inbounds"]![0]!["listen"] = "127.0.0.1";
            server["inbounds"]![0]!["port"] = serverPort;
            server["routing"]!["rules"] = new JsonArray();
            client["outbounds"]![0]!["settings"]!["vnext"]![0]!["address"] = "127.0.0.1";
            client["outbounds"]![0]!["settings"]!["vnext"]![0]!["port"] = serverPort;
        }
        else
        {
            server["inbounds"]![0]!["listen"] = "127.0.0.1";
            server["inbounds"]![0]!["listen_port"] = serverPort;
            server["route"]!["rules"] = new JsonArray();
            client["outbounds"]![0]!["server"] = "127.0.0.1";
            client["outbounds"]![0]!["server_port"] = serverPort;
        }
        var processes = new List<Process>(); var drains = new List<Task<string>>();
        bool succeeded = false;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var target = new TcpListener(IPAddress.Loopback, 0); target.Start();
        int targetPort = ((IPEndPoint)target.LocalEndpoint).Port;
        int tlsPort = FreePort();
        string certFile = Path.Combine(directory, "fixture-cert.pem"), keyFile = Path.Combine(directory, "fixture-key.pem");
        if (xray)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=www.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            File.WriteAllText(certFile, certificate.ExportCertificatePem());
            File.WriteAllText(keyFile, rsa.ExportPkcs8PrivateKeyPem());
            server["inbounds"]![0]!["streamSettings"]!["realitySettings"]!["target"] = "127.0.0.1:" + tlsPort;
        }
        try
        {
            if (xray)
            {
                var info = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                string fixture = Path.Combine(Directory.GetParent(engines)!.Parent!.FullName, "Tests", "Server", "tls_fixture.py");
                foreach (string argument in new[] { fixture, tlsPort.ToString(), certFile, keyFile }) info.ArgumentList.Add(argument);
                var tlsProcess = Process.Start(info)!; processes.Add(tlsProcess);
                drains.Add(tlsProcess.StandardOutput.ReadToEndAsync()); drains.Add(tlsProcess.StandardError.ReadToEndAsync());
                await ListenReady(tlsPort, tlsProcess, deadline.Token);
            }
            var serverProcess = await Start(executable, server, xray, processes, drains);
            var clientProcess = await Start(executable, client, xray, processes, drains);
            await ListenReady(serverPort, serverProcess, deadline.Token);
            await ListenReady(socksPort, clientProcess, deadline.Token);
            var serve = Task.Run(async () =>
            {
                using var socket = await target.AcceptTcpClientAsync(deadline.Token);
                using var reader = new StreamReader(socket.GetStream(), leaveOpen: true);
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync(deadline.Token))) { }
                await socket.GetStream().WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"), deadline.Token);
            });
            using var http = new HttpClient(new HttpClientHandler { UseProxy = true, Proxy = new WebProxy("socks5://127.0.0.1:" + socksPort), AllowAutoRedirect = false });
            using var response = await http.GetAsync("http://127.0.0.1:" + targetPort, deadline.Token);
            await serve;
            Check(response.StatusCode == HttpStatusCode.NoContent, mode + " real client/server handshake and data exchange");

            // Restart with production access restrictions, then with the user's access revoked.
            foreach (bool revoke in new[] { false, true })
            {
                if (!serverProcess.HasExited) serverProcess.Kill(true);
                await serverProcess.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
                var original = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "config.json")))!;
                if (xray)
                {
                    server["routing"]!["rules"] = revoke ? new JsonArray() : original["routing"]!["rules"]!.DeepClone();
                    if (revoke) server["inbounds"]![0]!["settings"]!["clients"] = new JsonArray();
                }
                else
                {
                    server["route"]!["rules"] = revoke ? new JsonArray() : original["route"]!["rules"]!.DeepClone();
                    if (revoke) server["inbounds"]![0]!["password"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                }
                serverProcess = await Start(executable, server, xray, processes, drains);
                await ListenReady(serverPort, serverProcess, deadline.Token);
                using var rejection = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                rejection.CancelAfter(TimeSpan.FromSeconds(3));
                bool rejected = false;
                try { using var unexpected = await http.GetAsync("http://127.0.0.1:" + targetPort, rejection.Token); }
                catch (Exception error) when (error is HttpRequestException or OperationCanceledException) { rejected = true; }
                Check(rejected && !target.Pending(), mode + (revoke ? " revoked key cannot forward traffic" : " production rules block private destinations"));
            }
            succeeded = true;
        }
        finally
        {
            deadline.Cancel();
            foreach (var process in processes)
            { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)); process.Dispose(); }
            await Task.WhenAll(drains);
            if (!succeeded) foreach (var drain in drains) Console.Error.WriteLine(SensitiveDiagnosticRedactor.RedactText(await drain));
            if (xray) { File.Delete(certFile); File.Delete(keyFile); }
        }
    }

    sealed class Stub(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => handler(request, token); }
}
