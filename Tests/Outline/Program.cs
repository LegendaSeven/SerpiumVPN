using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media.Imaging;
using System.Xml.Linq;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Outline;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.ProfileVault;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Routing;
using SerpiumVPN.Relay.SingBox;
using SerpiumVPN.UI;

internal static class Program
{
    private static int count;
    private static readonly string Key = MakeKey("example-password");
    private static string MakeKey(string password, string endpoint = "example.test:8388") =>
        "ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("chacha20-ietf-poly1305:" + password)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + "@" + endpoint + "/?outline=1#Test";
    private static void Check(bool condition, string label)
    { if (!condition) throw new Exception("FAILED: " + label); count++; Console.WriteLine("PASS " + label); }
    private static async Task Fails(Func<Task> action, ConnectionFailureKind kind, string label)
    {
        try { await action(); throw new Exception("FAILED: " + label); }
        catch (ConnectionCheckException error) { Check(error.Kind == kind, label); }
    }

    [STAThread]
    private static int Main(string[] args)
    {
        string output = Path.GetFullPath(args[0]); Directory.CreateDirectory(output);
        try
        {
            RunAsync(output, Path.GetFullPath(args[1])).GetAwaiter().GetResult();
            CheckUi(output, Path.GetFullPath(args[1]));
            File.WriteAllText(Path.Combine(output, "result.txt"), "OUTLINE_CHECKS_PASS=" + count);
            Console.WriteLine("OUTLINE_CHECKS_PASS=" + count); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(SensitiveDiagnosticRedactor.RedactText(error.ToString())); return 1; }
    }

    private static async Task RunAsync(string output, string engine)
    {
        var parser = new SerpiumParser();
        var parsed = parser.Parse(Key);
        Check(parsed.Success && parsed.Profile?.Encryption == "chacha20-ietf-poly1305" && parsed.Profile.Password == "example-password", "SIP002 Outline fields");
        foreach (string method in new[] { "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305" })
            Check(parser.Parse("ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(method + ":test")) + "@example.test:1234").Success, method);
        Check(parser.Parse("ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-256-gcm:legacy@example.test:8388")) + "#Legacy").Success, "legacy Base64 key");
        Check(parser.Parse("ss://aes-256-gcm:hello%3Awith%40separators@example.test:1234").Profile?.Password == "hello:with@separators", "escaped credentials");
        Check(parser.Parse(MakeKey("test", "[2001:db8::1]:8388")).Profile?.Server == "2001:db8::1", "IPv6 server");
        Check(ConnectionKeySourceResolver.ParseKeys(Convert.ToBase64String(Encoding.UTF8.GetBytes(Key))).Count == 1, "encoded subscription import");
        foreach (string suffix in new[] { "&plugin=v2ray-plugin", "&prefix=%ZZ", "&unknown=1" })
            Check(!parser.Parse(Key.Replace("#Test", suffix)).Success, "unsupported transport rejected " + suffix.Split('=')[0]);
        foreach (string key in new[] { "ss://bad", "ss://aes-256-gcm:@example.test:12", "ss://aes-256-gcm:secret@example.test:0", "ss://aes-256-gcm:secret@example.test:65536", "ss://aes-256-gcm:secret@example.test:8388/path", "ss://rc4:secret@example.test:12", "ss://!!!!@example.test:12" })
            Check(!parser.Parse(key).Success, "invalid Outline key rejected");
        Check(SensitiveDiagnosticRedactor.RedactText(Key + " ssconf://example.test/private-token").Contains("[СКРЫТО]") &&
            !SensitiveDiagnosticRedactor.RedactText(Key + " ssconf://example.test/private-token").Contains("private-token"), "Outline diagnostics redact both schemes");
        string json = "{\"server\":\"example.test\",\"server_port\":8388,\"method\":\"aes-256-gcm\",\"password\":\"test\"}";
        Check(ConnectionKeySourceResolver.ParseKeys(json).Count == 1, "JSON dynamic config import");
        var keys = OutlineKeySource.ExtractCandidates("<script>" + Key + "</script><code>" + Key.Replace("outline=1", "outline=1") + "</code>\n" + Key);
        Check(keys.Count == 1, "HTML extraction removes scripts and duplicates");
        Check(OutlineKeySource.ExtractCandidates("<script>" + Key + "</script>").Count == 0, "scripts do not supply candidates");
        string key2 = MakeKey("second-example");
        Check(OutlineKeySource.ExtractCandidates(Key + "\n" + key2, true)[0] == key2, "newest Telegram candidates first");
        Check(OutlineKeySource.ExtractCandidates(string.Join('\n', Enumerable.Range(0, 50).Select(i => MakeKey("example-" + i)))).Count == 8, "candidate cap");
        Check(OutlineKeySource.ExtractCandidates(Convert.ToBase64String(Encoding.UTF8.GetBytes(Key))).Count == 1, "Base64 source list");
        Check(OutlineKeySource.ExtractCandidates("////").Count == 0, "invalid UTF8 source rejected without decoder exception");
        Check(OutlineKeySource.SourceUri("https://t.me/example_channel").AbsolutePath == "/s/example_channel", "public channel normalization");
        Check(OutlineKeySource.SourceUri("ssconf://example.test:8443/path?a=b#Name").AbsoluteUri == "https://example.test:8443/path?a=b", "dynamic URL preserves path and query, strips fragment");
        foreach (string ip in new[] { "127.0.0.1", "10.0.0.1", "192.168.0.1", "169.254.169.254", "172.16.1.1", "100.64.0.1", "224.0.0.1", "::1", "::", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "2002:7f00:1::", "64:ff9b::7f00:1" })
            Check(!OutlineKeySource.IsPublicAddress(IPAddress.Parse(ip)), "nonpublic source blocked " + ip);
        Check(OutlineKeySource.IsPublicAddress(IPAddress.Parse("1.1.1.1")) && OutlineKeySource.IsPublicAddress(IPAddress.Parse("2606:4700:4700::1111")), "public IPv4/IPv6 accepted");
        foreach (string url in new[] { "http://example.test/", "file:///secret", "https://user:password@example.test/", "https://127.0.0.1/" })
            await Fails(() => Task.FromResult(OutlineKeySource.SourceUri(url)), ConnectionFailureKind.SubscriptionInvalid, "unsafe source URI rejected");
        using var http = new HttpClient(new StubHandler((request, token) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(request.RequestUri!.AbsolutePath == "/json" ? json : Key) })));
        var resolver = new OutlineKeySource(http);
        Check((await resolver.ResolveAsync("https://example.test/keys", default)).Single() == Key, "source download");
        Check(parser.Parse(await resolver.ResolveDynamicAsync("ssconf://example.test/json", default)).Success, "dynamic JSON download");
        using var empty = new HttpClient(new StubHandler((r, t) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>captcha</html>") })));
        await Fails(() => new OutlineKeySource(empty).ResolveAsync("https://example.test/", default), ConnectionFailureKind.OutlineSourceNeedsManual, "captcha/empty source gives actionable failure");
        using var redirect = new HttpClient(new StubHandler((r, t) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("http://example.test/") } })));
        await Fails(() => new OutlineKeySource(redirect).ResolveAsync("https://example.test/", default), ConnectionFailureKind.SubscriptionInvalid, "HTTPS downgrade rejected");
        using var oversized = new HttpClient(new StubHandler((r, t) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('a', 524289)) })));
        await Fails(() => new OutlineKeySource(oversized).ResolveAsync("https://example.test/", default), ConnectionFailureKind.SubscriptionTooLarge, "source size cap");
        int tries = 0;
        var selector = new OutlineAutoSelector();
        string winner = await selector.FindAsync([Key, Key, key2], (key, token) =>
        { tries++; return key == key2 ? Task.CompletedTask : Task.FromException(new ConnectionCheckException(ConnectionFailureKind.ProbeFailed)); }, null, default);
        Check(winner == key2 && tries == 2, "failed key skipped and first working key chosen");
        await Fails(() => selector.FindAsync([Key], (k,t) => Task.FromException(new ConnectionCheckException(ConnectionFailureKind.ProbeFailed)), null, default), ConnectionFailureKind.OutlineNoWorkingKey, "all failed gives truthful status");
        tries = 0;
        await Fails(() => selector.FindAsync([Key,key2], (k,t) => { tries++; throw new ConnectionCheckException(ConnectionFailureKind.EngineMissing); }, null, default), ConnectionFailureKind.EngineMissing, "missing engine stops search");
        Check(tries == 1, "infrastructure failure not retried per key");
        using (var cancel = new CancellationTokenSource())
        {
            tries = 0;
            try
            {
                await selector.FindAsync([Key,key2], async (key, token) => { tries++; cancel.Cancel(); await Task.Delay(1000, token); }, null, cancel.Token);
                throw new Exception("Cancellation ignored");
            }
            catch (OperationCanceledException) { Check(tries == 1, "Stop cancels in-flight attempt and prevents next"); }
        }
        await Fails(() => new OutlineCandidateProbe(engine).CheckAsync(MakeKey("test", "127.0.0.1:8388"), default), ConnectionFailureKind.InvalidKey, "auto probe rejects private candidate before process launch");
        using var runtime = OutlineProfileFactory.Create(parsed.Profile!);
        var rules = new[] { new RoutingRegistryEntry { Kind = RoutingTargetKind.Application, PrimaryValue = Environment.ProcessPath!, IsEnabled = true } };
        using var compiled = SerpiumRoutingConfigCompiler.CompileProviderProfile(runtime, rules, null, applicationSelectionOnly: true);
        CheckTunSession(compiled, "ordinary Outline reaches the real TUN session preflight");
        await EngineCheck(engine, runtime.CopyConfiguration());
        await EngineCheck(engine, compiled.CopyConfiguration());
        await CheckLoopbackAsync(engine);
        await CheckPrefixAsync(output, engine);
        await CheckProviderTunAsync(output, engine, rules);
        var vault = new SecureProfileVault();
        string vaultDir = Path.Combine(output, "isolated-vault");
        typeof(SecureProfileVault).GetField("_vaultDirectory", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(vault, vaultDir);
        typeof(SecureProfileVault).GetField("_vaultPath", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(vault, Path.Combine(vaultDir, "profiles.svault"));
        var saved = await vault.SaveProviderProfileAsync(runtime, Key);
        using var reopened = await vault.OpenProviderProfileAsync(saved.Entry.Id);
        Check(runtime.CopyConfiguration().SequenceEqual(reopened.CopyConfiguration()), "encrypted Outline profile round trip");
        var again = await vault.SaveProviderProfileAsync(runtime, Key);
        Check(again.Entry.Id == saved.Entry.Id && (await vault.ListProfilesAsync()).Count == 1, "profile deduplication");
        Check(!Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(vaultDir, "profiles.svault"))).Contains("example-password"), "secret absent from plaintext vault");
    }

    private static async Task CheckPrefixAsync(string output, string engine)
    {
        const string encodedPrefix = "%16%03%01%00%C2%A8%01%01";
        string key = Key.Replace("outline=1", "outline=1&prefix=" + encodedPrefix);
        var parser = new SerpiumParser();
        var profile = parser.Parse(key).Profile!;
        Check(Convert.ToHexString(Encoding.Latin1.GetBytes(profile.OutlinePrefix)) == "16030100A80101", "Outline percent encoding maps UTF-8 codepoints to exact salt bytes");
        Check(parser.Parse(key.Replace("ss://", "ss\\://")).Success, "Markdown-escaped ss scheme accepted");
        Check(ConnectionKeySourceResolver.ParseKeys(key.Replace("ss://", "ss\\://")).Count == 1, "escaped scheme accepted through actual manual import pipeline");
        Check(OutlineKeySource.ExtractCandidates(key.Replace("ss://", "ss\\://")).Count == 1, "auto source recognizes escaped prefix keys");
        Check(!SensitiveDiagnosticRedactor.RedactText(key.Replace("ss://", "ss\\://")).Contains(key[5..key.IndexOf('@')]), "escaped key redacted from diagnostics");
        Check(parser.Parse(Key.Replace("outline=1", "prefix=POST%20")).Profile!.OutlinePrefix == "POST ", "printable prefix preserved");
        Check(parser.Parse(Key.Replace("outline=1", "prefix=%2B+")).Profile!.OutlinePrefix == "++", "plus stays a literal byte");
        foreach (string invalid in new[] { "%A8", "%C2", "%GG", "%", "%E2%82%AC", new string('A',17), "ok&prefix=second" })
            Check(!parser.Parse(Key.Replace("outline=1", "prefix=" + invalid)).Success, "invalid or overlong prefix rejected: " + invalid);
        Check(!parser.Parse("ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-128-gcm:test")) + "@example.test:443?prefix=POST").Success, "prefix cannot consume salt entropy below 128 bits");
        using var runtime = OutlineProfileFactory.Create(profile);
        var vault = new SecureProfileVault(); string vaultDir = Path.Combine(output,"prefix-vault");
        typeof(SecureProfileVault).GetField("_vaultDirectory",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(vault,vaultDir);
        typeof(SecureProfileVault).GetField("_vaultPath",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(vault,Path.Combine(vaultDir,"profiles.svault"));
        var saved = await vault.SaveProviderProfileAsync(runtime,key);
        using var reopened = await vault.OpenProviderProfileAsync(saved.Entry.Id);
        Check(reopened.CopyConfiguration().SequenceEqual(runtime.CopyConfiguration()), "prefix and credentials survive encrypted profile round trip");
        await EngineCheck(engine, OutlinePrefixConfiguration.PrepareCheck(reopened.CopyConfiguration()));
        using (var session = new OutlinePrefixSession())
        using (var prepared = await session.PrepareAsync(reopened, Path.Combine(Path.GetDirectoryName(engine)!, OutlinePrefixConfiguration.ExecutableName), default))
        using (var routed = SerpiumRoutingConfigCompiler.CompileProviderProfile(prepared,
            [new RoutingRegistryEntry { Kind = RoutingTargetKind.Application, PrimaryValue = Environment.ProcessPath!, IsEnabled = true }],
            null, applicationSelectionOnly: true, managedTunId: saved.Entry.Id))
        {
            CheckTunSession(routed, "saved prefix profile gains a TUN without reimporting its key");
            await EngineCheck(engine, routed.CopyConfiguration());
            await session.StopAsync();
        }
        await CheckLoopbackAsync(engine, encodedPrefix);
    }

    private static async Task CheckProviderTunAsync(string output, string engine, RoutingRegistryEntry[] rules)
    {
        using var source = Hysteria2ProfileFactory.Create(new SerpiumConnectionProfile
        { Protocol = "hysteria2", Server = "example.test", Port = 443, ServerName = "example.test", Password = "test-fixture", Name = "Fixture" });
        Guid id = Guid.NewGuid();
        using var compiled = SerpiumRoutingConfigCompiler.CompileProviderProfile(source, rules, null, true, id);
        CheckTunSession(compiled, "Hysteria2 outbound-only profile reaches real TUN session preflight");
        await EngineCheck(engine, compiled.CopyConfiguration());
        byte[] sourceBytes = source.CopyConfiguration(), firstBytes = compiled.CopyConfiguration();
        using var existing = SerpiumRoutingConfigCompiler.CompileProviderProfile(compiled, rules, null, true, Guid.NewGuid());
        byte[] secondBytes = existing.CopyConfiguration();
        try
        {
            Check(JsonNode.Parse(sourceBytes)!["inbounds"] is null, "runtime preparation leaves stored provider configuration unchanged");
            var first = JsonNode.Parse(firstBytes)!["inbounds"]!;
            var second = JsonNode.Parse(secondBytes)!["inbounds"]!;
            Check(JsonNode.DeepEquals(first, second) && second.AsArray().Count == 1, "existing provider TUN is preserved without duplicate interfaces");
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(sourceBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(firstBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secondBytes);
        }
        await EngineCheck(engine, existing.CopyConfiguration());
        Check(ConnectionFeedback.ClassifyDiagnostic("Конфигурация sing-box не содержит массив inbounds.") == ConnectionFailureKind.InvalidConfiguration,
            "invalid runtime configuration is distinguished from an invalid key");
        using var live = new SecureRoutingRuleSetRuntime(Path.Combine(output, "routing-fixture")) { FullTunnelWhenEmpty = false };
        await live.UpdateAsync([], false);
        using var idle = SerpiumRoutingConfigCompiler.CompileProviderProfile(source, [], live.RuleSetPath, true, id);
        CheckTunSession(idle, "connection preflight works with every app toggle off and live rules ready");
        await EngineCheck(engine, idle.CopyConfiguration());
        using var xray = SerpiumRoutingConfigCompiler.BuildXrayBridgeProfile(Guid.NewGuid(), 10808, rules);
        CheckTunSession(xray, "Xray bridge still passes the same TUN session preflight");
        await EngineCheck(engine, xray.CopyConfiguration());
    }

    private static async Task EngineCheck(string engine, byte[] config)
    {
        var info = new ProcessStartInfo(engine) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (string arg in new[] { "check", "-c", "stdin" }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        await process.StandardInput.BaseStream.WriteAsync(config); process.StandardInput.Close();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        if (process.ExitCode != 0) throw new Exception(SensitiveDiagnosticRedactor.RedactText(await stderr));
        await stdout; await stderr;
        Check(process.ExitCode == 0, "bundled sing-box accepts Outline configuration");
    }

    private static void CheckTunSession(ProviderRuntimeProfile runtime, string label)
    {
        byte[] config = runtime.CopyConfiguration();
        try
        {
            var validate = typeof(SerpiumSingBoxSessionManager).GetMethod("ReadAndValidateTunInterface", BindingFlags.Static | BindingFlags.NonPublic)!;
            string? interfaceName = (string?)validate.Invoke(null, [config]);
            Check(!string.IsNullOrWhiteSpace(interfaceName) && runtime.InboundCount > 0, label);
            Check(VpnOutboundProbe.ReadOutboundTag(config) == "proxy", "session checks the actual VPN outbound");
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(config); }
    }

    private static async Task CheckLoopbackAsync(string engine, string? prefix = null)
    {
        int FreePort() { using var socket = new TcpListener(IPAddress.Loopback, 0); socket.Start(); return ((IPEndPoint)socket.LocalEndpoint).Port; }
        int ssPort = FreePort(), proxyPort = FreePort();
        var serverConfig = new JsonObject
        {
            ["log"] = new JsonObject { ["disabled"] = true },
            ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["listen"] = "127.0.0.1", ["listen_port"] = ssPort, ["method"] = "chacha20-ietf-poly1305", ["password"] = "loopback-fixture" }),
            ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }), ["route"] = new JsonObject { ["final"] = "direct" }
        };
        string key = MakeKey("loopback-fixture", "127.0.0.1:" + ssPort);
        if (prefix is not null) key = key.Replace("outline=1", "outline=1&prefix=" + prefix);
        var profile = new SerpiumParser().Parse(key).Profile!;
        var clientConfig = (JsonObject)typeof(OutlineCandidateProbe).GetMethod("BuildProbeConfiguration", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, [profile, IPAddress.Loopback, proxyPort, "probe-fixture"])!;
        using var prefixSession = new OutlinePrefixSession();
        await prefixSession.PrepareAsync(clientConfig, Path.Combine(Path.GetDirectoryName(engine)!, OutlinePrefixConfiguration.ExecutableName), default);
        if (prefix is not null)
        {
            Check(prefixSession.IsRunning && !clientConfig.ToJsonString().Contains(OutlinePrefixConfiguration.Marker), "runtime binds prefix helper without unsupported engine fields");
            var rules = new[] { new RoutingRegistryEntry { Kind = RoutingTargetKind.Application, PrimaryValue = Environment.ProcessPath!, IsEnabled = true } };
            using var native = OutlineProfileFactory.Create(profile);
            using var otherSession = new OutlinePrefixSession();
            using var prepared = await otherSession.PrepareAsync(native, Path.Combine(Path.GetDirectoryName(engine)!, OutlinePrefixConfiguration.ExecutableName), default);
            using var compiled = SerpiumRoutingConfigCompiler.CompileProviderProfile(prepared, rules, null, applicationSelectionOnly: true);
            CheckTunSession(compiled, "reopened Outline prefix profile reaches the real TUN session preflight");
            byte[] compiledBytes = compiled.CopyConfiguration();
            try
            {
                var firstRule = JsonNode.Parse(compiledBytes)!["route"]!["rules"]![0]!;
                Check(firstRule["process_name"]![0]!.GetValue<string>() == "Serpium.Outline.exe" &&
                    firstRule["outbound"]!.GetValue<string>() == "direct" && firstRule.AsObject().Count == 3,
                    "adapter upstream bypasses all website and application VPN rules");
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(compiledBytes); }
            await EngineCheck(engine, compiled.CopyConfiguration());
            await otherSession.StopAsync();
            Check(!otherSession.IsRunning && !otherSession.Required, "helper stops and releases session state");
        }
        Check(!clientConfig.ToJsonString().Contains("tun") && clientConfig["route"]!["final"]!.GetValue<string>() == "proxy", "probe configuration uses proxy without TUN or direct fallback");
        var processes = new List<Process>();
        var drains = new List<Task<string>>();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var httpServer = new TcpListener(IPAddress.Loopback, 0); httpServer.Start();
        int targetPort = ((IPEndPoint)httpServer.LocalEndpoint).Port;
        try
        {
            foreach (var configuration in new[] { serverConfig, clientConfig })
            {
                var info = new ProcessStartInfo(engine) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
                foreach (string argument in new[] { "run", "-c", "stdin" }) info.ArgumentList.Add(argument);
                var process = Process.Start(info)!; processes.Add(process);
                drains.Add(process.StandardOutput.ReadToEndAsync()); drains.Add(process.StandardError.ReadToEndAsync());
                await process.StandardInput.WriteAsync(configuration.ToJsonString()); process.StandardInput.Close();
            }
            foreach (int port in new[] { ssPort, proxyPort })
            {
                while (true)
                {
                    try { using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, port, deadline.Token); break; }
                    catch (SocketException) { await Task.Delay(100, deadline.Token); }
                }
            }
            Task serve = Task.Run(async () =>
            {
                using var socket = await httpServer.AcceptTcpClientAsync(deadline.Token);
                using var reader = new StreamReader(socket.GetStream(), leaveOpen: true);
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(deadline.Token))) { }
                await socket.GetStream().WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"), deadline.Token);
            });
            using var client = new HttpClient(new HttpClientHandler
            {
                UseProxy = true, Proxy = new WebProxy("socks5://127.0.0.1:" + proxyPort) { Credentials = new NetworkCredential("probe", "probe-fixture") },
                UseCookies = false, AllowAutoRedirect = false
            });
            using var response = await client.GetAsync("http://127.0.0.1:" + targetPort + "/", deadline.Token);
            await serve;
            Check(response.StatusCode == HttpStatusCode.NoContent, "probe proxy sends traffic through real Shadowsocks loopback server");
            using var unauthorized = new HttpClient(new HttpClientHandler { UseProxy = true, Proxy = new WebProxy("socks5://127.0.0.1:" + proxyPort), AllowAutoRedirect = false });
            try { using var rejected = await unauthorized.GetAsync("http://127.0.0.1:" + targetPort + "/", deadline.Token); throw new Exception("Unauthorized proxy accepted"); }
            catch (HttpRequestException) { Check(true, "test proxy rejects other local clients without credential"); }
        }
        finally
        {
            deadline.Cancel();
            foreach (var process in processes)
            {
                if (!process.HasExited) process.Kill(true);
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
                process.Dispose();
            }
            await Task.WhenAll(drains);
            await prefixSession.StopAsync();
        }
    }

    private static void CheckUi(string output, string engine)
    {
        var app = new Application();
        string project = Directory.GetParent(Path.GetDirectoryName(engine)!)!.Parent!.FullName;
        var dictionary = XDocument.Load(Path.Combine(project, "App.xaml")).Descendants(XName.Get("ResourceDictionary", "http://schemas.microsoft.com/winfx/2006/xaml/presentation")).First();
        app.Resources = (ResourceDictionary)System.Windows.Markup.XamlReader.Parse(dictionary.ToString());
        var view = new SimpleHomeView();
        var id = Guid.NewGuid();
        view.SetProfiles([new SimpleProfileItem(id, "Outline · Test")], id);
        view.SetConnectionState(false, false, true, true);
        var key = (PasswordBox)view.FindName("KeyInput");
        var connect = (Button)view.FindName("ConnectButton");
        var auto = (ToggleButton)view.FindName("AutoConnectionMode");
        Check(!key.IsEnabled, "saved profile still locks manual key input");
        auto.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        Check(view.IsOutlineAutoMode && ((FrameworkElement)view.FindName("ProfilesPanel")).Visibility == Visibility.Collapsed, "auto mode replaces manual controls");
        Check(connect.Content?.ToString() == "Подобрать и подключиться", "auto action label");
        view.SetConnectionState(false, true, true, true, "Проверка ключа 1 из 8…", canStop: true);
        Check(connect.IsEnabled && connect.Content?.ToString() == "Стоп" && !auto.IsEnabled, "Stop available during probe, modes locked");
        view.SetConnectionState(true, false, true, true);
        Check(view.IsOutlineAutoMode && connect.Content?.ToString() == "Отключить" && !auto.IsEnabled, "auto mode persists during connection");
        view.SetConnectionState(false, false, true, true);
        Check(view.IsOutlineAutoMode && connect.Content?.ToString() == "Подобрать и подключиться", "next auto connection will fetch fresh candidates");
        foreach (var theme in new[] { AppTheme.Midnight, AppTheme.SoftPink })
        {
            AppThemes.Apply(view.Resources, theme); view.SetTheme(theme);
            Render(view, Path.Combine(output, "auto-" + theme + ".png"));
        }
        view.ShowManualConnectionMode();
        Check(!view.IsOutlineAutoMode && !key.IsEnabled && connect.Content?.ToString() == "Подключиться", "manual mode restored with profile selection");
        Render(view, Path.Combine(output, "manual.png"));
        app.Shutdown();
    }

    private static void Render(FrameworkElement view, string path)
    {
        view.Measure(new Size(1080, 700)); view.Arrange(new Rect(0, 0, 1080, 700)); view.UpdateLayout();
        var image = new RenderTargetBitmap(1080, 700, 96, 96, System.Windows.Media.PixelFormats.Pbgra32); image.Render(view);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        using var stream = File.Create(path); encoder.Save(stream);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken); }
}
