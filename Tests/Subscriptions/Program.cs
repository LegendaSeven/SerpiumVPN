using System.Net;
using System.Text;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;

static class Program
{
    const string Key = "vless://12345678-1234-1234-1234-123456789abc@vpn.example.com:443?type=tcp&security=tls#Fixture";
    const string Identity = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    static int count;
    static void Check(bool ok, string message) { if (!ok) throw new Exception(message); count++; Console.WriteLine("PASS " + message); }
    static string Notice(string text, string host = "127.0.0.1") => "vless://12345678-1234-1234-1234-123456789abc@" + host + ":1?security=none#" + Uri.EscapeDataString(text);
    static string Encoded(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
    static HttpResponseMessage Body(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text) };
    static async Task Fails(Func<Task> action, ConnectionFailureKind kind, string name)
    {
        try { await action(); throw new Exception("Missing failure: " + name); }
        catch (ConnectionCheckException error) { Check(error.Kind == kind, name); Check(!error.Message.Contains("SECRET_CANARY"), "error contains no source secrets"); }
    }
    static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0] == "--inspect")
            {
                foreach (string source in args.Skip(1))
                {
                    try { var keys = await new ConnectionKeySourceResolver().ResolveAsync(source); Console.WriteLine("LIVE IMPORT nodes=" + keys.Count); }
                    catch (ConnectionCheckException error) { Console.WriteLine("LIVE RESULT " + error.Kind); }
                }
                return 0;
            }
            await Tests(Path.GetFullPath(args[0]));
            Console.WriteLine("SUBSCRIPTION_CHECKS_PASS=" + count); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine("CHECK_FAILED " + error.GetType().Name + ": " + SensitiveDiagnosticRedactor.RedactText(error.Message)); return 1; }
    }

    static async Task Tests(string directory)
    {
        Check(ConnectionKeySourceResolver.ParseKeys(Encoded(Key)).Single() == Key, "Base64 import remains valid");
        Check(!SensitiveDiagnosticRedactor.RedactText("x-hwid: " + Identity).Contains(Identity), "device header redacted from diagnostics");
        Check(ConnectionKeySourceResolver.ParseKeys(Encoded(Encoded(Key))).Single() == Key, "double Base64 import remains valid");
        Check(ConnectionKeySourceResolver.ParseKeys(Key.Replace("443", "1")).Count == 1, "real external endpoint on port 1 is not mistaken for a notice");
        Check(ConnectionKeySourceResolver.ParseKeys(Key.Replace("vpn.example.com", "127.0.0.1")).Count == 1, "explicit local test server remains supported");
        foreach (var entry in new[] {
            ("App not supported", ConnectionFailureKind.SubscriptionClientRejected),
            ("Включите отправку HWID", ConnectionFailureKind.SubscriptionDeviceRequired),
            ("Устройство не определяется", ConnectionFailureKind.SubscriptionDeviceRequired),
            ("Device limit reached", ConnectionFailureKind.SubscriptionDeviceLimit),
            ("Срок подписки закончился SECRET_CANARY", ConnectionFailureKind.SubscriptionProviderNotice) })
        {
            await Fails(() => Task.FromResult(ConnectionKeySourceResolver.ParseKeys(Encoded(Notice(entry.Item1)))), entry.Item2, "provider notice classified");
        }
        foreach (string host in new[] { "localhost", "[::1]", "0.0.0.0", "[::]", "127.0.0.2" })
            await Fails(() => Task.FromResult(ConnectionKeySourceResolver.ParseKeys(Notice("App not supported", host))), ConnectionFailureKind.SubscriptionClientRejected, "loopback notice variant");
        await Fails(() => Task.FromResult(ConnectionKeySourceResolver.ParseKeys(Key + "\n" + Notice("App not supported"))), ConnectionFailureKind.SubscriptionClientRejected, "mixed real/notice list rejected before vault save");

        foreach (string flag in new[] { "x-hwid-max-devices-reached", "x-hwid-limit", "x-hwid-not-supported" })
        {
            using var http = new HttpClient(new Stub((r,t) => { var result = new HttpResponseMessage(HttpStatusCode.NotFound); result.Headers.Add(flag, "true"); return Task.FromResult(result); }));
            await Fails(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/SECRET_CANARY"),
                flag == "x-hwid-not-supported" ? ConnectionFailureKind.SubscriptionDeviceRequired : ConnectionFailureKind.SubscriptionDeviceLimit, "HWID headers take priority over HTTP 404");
        }
        int requests = 0, consent = 0;
        using (var http = new HttpClient(new Stub((r,t) =>
        {
            var result = Body(Notice("App not supported"));
            result.Headers.Add("x-hwid-active", "true"); result.Headers.Add("x-hwid-not-supported", "true"); result.Headers.Add("x-hwid-limit", "true");
            return Task.FromResult(result);
        })))
            await Fails(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionDeviceRequired, "specific missing-HWID flag wins over legacy limit flag and generic body");
        using (var http = new HttpClient(new Stub((r,t) =>
        {
            requests++;
            Check(r.Headers.UserAgent.ToString() == "SerpiumVPN/1.0", "client identifies itself as Serpium");
            if (requests == 1) { Check(!r.Headers.Contains("x-hwid"), "no identity before requirement and consent"); return Task.FromResult(Body(Encoded(Notice("Включите отправку HWID")))); }
            Check(r.Headers.GetValues("x-hwid").Single() == Identity, "authorized identity sent on retry");
            Check(!r.Headers.Contains("x-device-model") && !r.Headers.Contains("x-ver-os"), "no hardware details sent");
            return Task.FromResult(Body(Encoded(Key)));
        })))
        {
            var resolver = new ConnectionKeySourceResolver(http, (uri,t) => { consent++; Check(uri.Host == "vpn.example.com", "consent uses actual source origin"); return Task.FromResult<string?>(Identity); });
            Check((await resolver.ResolveAsync("https://vpn.example.com/SECRET_CANARY")).Single() == Key, "authorized device import succeeds");
            Check(consent == 1 && requests == 2, "one consent and one retry");
        }
        requests = 0;
        using (var http = new HttpClient(new Stub((r,t) =>
        {
            requests++; Check(r.Headers.GetValues("x-hwid").Single() == Identity, "previously approved identity sent immediately");
            return Task.FromResult(Body(Key));
        })))
        {
            Check((await new ConnectionKeySourceResolver(http, readAuthorizedDevice: uri => Identity).ResolveAsync("https://vpn.example.com/key")).Count == 1, "approved provider imports without another consent callback");
            Check(requests == 1, "approved import needs only one request");
        }
        requests = 0;
        using (var http = new HttpClient(new Stub((r,t) => { requests++; return Task.FromResult(Body(Notice("HWID"))); })))
        {
            await Fails(() => new ConnectionKeySourceResolver(http, (u,t) => Task.FromResult<string?>(null)).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionDeviceRequired, "declining consent stops import");
            Check(requests == 1, "declining sends no second request");
        }
        requests = 0;
        using (var http = new HttpClient(new Stub((r,t) => { requests++; return Task.FromResult(Body(Notice("HWID"))); })))
        {
            await Fails(() => new ConnectionKeySourceResolver(http, (u,t) => Task.FromResult<string?>(Identity)).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionDeviceRequired, "persistent requirement returns fixed error");
            Check(requests == 2, "no retry loop or identity rotation");
        }
        foreach (string invalid in new[] { "short", Identity + "\r\nx-injected: true", new string('a', 65) })
        {
            requests = 0;
            using var http = new HttpClient(new Stub((r,t) => { requests++; return Task.FromResult(Body(Notice("HWID"))); }));
            await Fails(() => new ConnectionKeySourceResolver(http, (u,t) => Task.FromResult<string?>(invalid)).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionDeviceStorage, "invalid identity rejected");
            Check(requests == 1, "invalid identity never sent");
        }
        requests = 0;
        using (var http = new HttpClient(new Stub((r,t) =>
        {
            requests++;
            if (requests == 1) return Task.FromResult(Body(Notice("HWID")));
            if (requests == 2) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://other.example.com/key") } });
            Check(!r.Headers.Contains("x-hwid"), "identity stripped on cross-origin redirect"); return Task.FromResult(Body(Key));
        })))
            Check((await new ConnectionKeySourceResolver(http, (u,t) => Task.FromResult<string?>(Identity)).ResolveAsync("https://vpn.example.com/key")).Count == 1, "public redirect still imports");
        using (var http = new HttpClient(new Stub((r,t) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new Uri("https://127.0.0.1/key") } }))))
            await Fails(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionInvalid, "private redirect rejected");
        using (var http = new HttpClient(new Stub((r,t) => Task.FromResult(Body(Notice("HWID"))))))
        using (var cancel = new CancellationTokenSource())
        {
            try { await new ConnectionKeySourceResolver(http, (u,t) => { cancel.Cancel(); return Task.FromResult<string?>(Identity); }).ResolveAsync("https://vpn.example.com/key", cancel.Token); throw new Exception("Cancellation lost"); }
            catch (OperationCanceledException) { Check(true, "Stop during consent prevents retry"); }
        }
        using (var http = new HttpClient(new Stub((r,t) => Task.FromResult(Body(new string('a', 131073))))))
            await Fails(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionTooLarge, "download size limit preserved");
        using (var http = new HttpClient(new Stub((r,t) => { var response=Body("<html>SECRET_CANARY</html>"); response.Content.Headers.ContentType=new("text/html"); return Task.FromResult(response); })))
            await Fails(() => new ConnectionKeySourceResolver(http).ResolveAsync("https://vpn.example.com/key"), ConnectionFailureKind.SubscriptionInvalid, "browser HTML never executed or imported");

        string privateDir = Path.Combine(directory, Guid.NewGuid().ToString("N"));
        var store = new SubscriptionDeviceIdentityStore(privateDir);
        Uri uriA = new("https://vpn.example.com/key-a"), uriB = new("https://other.example.com/key-b");
        Check(store.Read(uriA) is null && !Directory.Exists(privateDir), "no device file before consent");
        string id = store.Authorize(uriA);
        Check(id.Length == 64 && id.All(char.IsAsciiHexDigit), "identity meets provider header format");
        Check(new SubscriptionDeviceIdentityStore(privateDir).Read(uriA) == id, "same identity after store restart");
        Check(store.Authorize(new Uri("https://vpn.example.com/another-key#label")) == id, "same provider reuses identity across keys");
        Check(store.Read(uriB) is null, "unapproved provider gets no identity");
        Check(store.Authorize(uriB) != id, "providers cannot correlate identifiers");
        Check(store.Authorize(new Uri("https://vpn.example.com:8443/key")) != id, "origin port separates identity");
        Check(Directory.GetFiles(privateDir).All(path => !Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(id)), "identity is DPAPI encrypted on disk");
        var saved = Directory.GetFiles(privateDir).ToDictionary(path => path, File.ReadAllBytes);
        foreach (string file in saved.Keys) File.WriteAllText(file, "corrupt");
        await Fails(() => Task.FromResult(store.Authorize(uriA)), ConnectionFailureKind.SubscriptionDeviceStorage, "corrupted identity is never silently regenerated");
        Check(Directory.GetFiles(privateDir).Length == 3, "failed read creates no extra identities");
    }

    sealed class Stub(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> handle) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => handle(request,token); }
}
