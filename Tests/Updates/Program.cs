using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Xml.Linq;
using SerpiumVPN;
using SerpiumVPN.UI;
using SerpiumVPN.Updates;
using SerpiumUpdater;

internal static class Program
{
    private static int _checks;
    private static readonly string[] Required = ["SerpiumVPN.exe", "SerpiumVPN.dll", "SerpiumVPN.runtimeconfig.json", "SerpiumUpdater.exe", "bin_files/relay/sing-box.exe", "bin_files/relay/xray.exe", "Assets/Serpium.App.ico"];
    private const string Version = "1.0.56.15";
    private static readonly string ZipUrl = AppUpdateManager.RepositoryUrl + "/releases/download/v" + Version + "/SerpiumVPN-" + Version + ".zip";
    private static readonly string ManifestUrl = AppUpdateManager.RepositoryUrl + "/releases/download/v" + Version + "/update.json";

    [STAThread]
    private static int Main(string[] args)
    {
        string output = Path.GetFullPath(args[0]); Directory.CreateDirectory(output);
        NetworkChecks(output).GetAwaiter().GetResult();
        PackageChecks(output);
        InstallationChecks(output);
        UiChecks(output, Path.GetFullPath(args[1]));
        if (args.Length > 2)
        {
            UpdatePackage.Verify(args[2], Hash(File.ReadAllBytes(args[2])));
            Check(true, "real published release ZIP passes package validation");
        }
        if (args.Contains("--github"))
        {
            using var live = new AppUpdateManager(currentVersion: "1.0.56.13", cacheRoot: output);
            var release = live.CheckAsync().GetAwaiter().GetResult();
            Check(release is not null && release.ZipUrl.StartsWith(AppUpdateManager.RepositoryUrl + "/releases/download/", StringComparison.Ordinal), "live GitHub metadata and manifest resolve a newer official release");
            Console.WriteLine("GITHUB_LATEST=" + release!.Version);
        }
        Console.WriteLine("UPDATE_CHECKS_PASS=" + _checks);
        return 0;
    }

    private static void Check(bool pass, string message)
    { if (!pass) throw new Exception(message); _checks++; Console.WriteLine("PASS " + message); }
    private static async Task Reject(Func<Task> action, string message)
    { bool rejected = false; try { await action(); } catch (Exception e) when(e is InvalidDataException or OperationCanceledException or HttpRequestException or IOException) { rejected = true; } Check(rejected, message); }
    private static string Hash(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    private static byte[] Package(params string[] extra)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, true))
            foreach (var name in Required.Concat(extra))
            { using var stream = new StreamWriter(zip.CreateEntry(name).Open()); stream.Write("new:" + name); }
        return buffer.ToArray();
    }
    private static string Release(byte[] package, string version = Version, string? digest = null, string? assetUrl = null, bool prerelease = false) => JsonSerializer.Serialize(new
    {
        tag_name = "v" + version, draft = false, prerelease,
        assets = new[] {
            new { name = "update.json", browser_download_url = ManifestUrl, size = 100L, digest = (string?)null },
            new { name = "SerpiumVPN-" + Version + ".zip", browser_download_url = assetUrl ?? ZipUrl, size = (long)package.Length, digest = (string?)(digest ?? "sha256:" + Hash(package)) }
        }
    });
    private static string Manifest(byte[] package, string version = Version, string? hash = null, string? url = null) =>
        JsonSerializer.Serialize(new { version, zipUrl = url ?? ZipUrl, sha256 = hash ?? Hash(package) });

    private static async Task NetworkChecks(string output)
    {
        byte[] package = Package(); string metadata = Release(package), manifest = Manifest(package); int downloads = 0, requests = 0;
        var handler = new Stub((request, token) =>
        {
            token.ThrowIfCancellationRequested(); requests++;
            string uri = request.RequestUri!.AbsoluteUri;
            HttpContent content;
            if (uri == ZipUrl) { downloads++; content = new ByteArrayContent(package); }
            else content = new StringContent(uri == ManifestUrl ? manifest : metadata);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        });
        using var http = new HttpClient(handler);
        using var manager = new AppUpdateManager(http, "1.0.56.14", output);
        var found = await manager.CheckAsync();
        Check(found?.Version == Version && downloads == 0, "checking detects newer release without downloading");
        var progress = new InlineProgress(); await manager.DownloadAsync(progress);
        Check(manager.IsReady && progress.Values.Last() == 100 && downloads == 1, "download reports progress and becomes installable after hash/package validation");
        int before = requests; await manager.CheckAsync(); await manager.DownloadAsync(null);
        Check(requests == before && manager.IsReady, "ready update survives repeated checks without downloading twice");
        string pending = manager.PendingArchivePath!; manager.Dispose();
        Check(!File.Exists(pending), "closing without installing cleans downloaded package");

        async Task Bad(string description, string release, string descriptionJson)
        {
            metadata = release; manifest = descriptionJson;
            using var candidate = new AppUpdateManager(http, "1.0.56.14", output);
            int count = downloads;
            await Reject(async () => { await candidate.CheckAsync(); }, description);
            Check(downloads == count && !candidate.IsReady, description + " never downloads an executable");
        }
        await Bad("missing checksum rejected", Release(package), Manifest(package, hash: ""));
        await Bad("manifest version mismatch rejected", Release(package), Manifest(package, version: "1.0.56.99"));
        await Bad("foreign manifest URL rejected", Release(package), Manifest(package, url: "https://example.com/update.zip"));
        await Bad("foreign release asset rejected", Release(package, assetUrl: "https://example.com/update.zip"), Manifest(package));
        await Bad("conflicting GitHub digest rejected", Release(package, digest: "sha256:" + new string('a', 64)), Manifest(package));
        await Bad("prerelease rejected", Release(package, prerelease: true), Manifest(package));
        await Bad("invalid version rejected", Release(package, version: "1.0.56.15-preview"), Manifest(package));
        foreach (string current in new[] { Version, "1.0.56.16", "2.0.0" })
        {
            metadata = Release(package); manifest = Manifest(package);
            using var candidate = new AppUpdateManager(http, current, output);
            Check(await candidate.CheckAsync() is null, "equal/older release not offered: " + current);
        }
        metadata = Release(package); manifest = Manifest(package);
        using var damaged = new AppUpdateManager(http, "1.0.56.14", output);
        await damaged.CheckAsync(); byte[] original = package; package = package.ToArray(); package[10] ^= 1;
        await Reject(() => damaged.DownloadAsync(null), "tampered download rejected");
        Check(!damaged.IsReady && !Directory.EnumerateDirectories(output, "Serpium-download-*").Any(), "failed download leaves no installable/partial archive");
        package = original;
        using var cancel = new CancellationTokenSource();
        using var canceled = new AppUpdateManager(http, "1.0.56.14", output); await canceled.CheckAsync();
        await Reject(() => canceled.DownloadAsync(new InlineProgress(_ => cancel.Cancel()), cancel.Token), "download cancellation propagated");
        Check(!canceled.IsReady && !Directory.EnumerateDirectories(output, "Serpium-download-*").Any(), "cancellation cleans temporary download");
        using var outageClient = new HttpClient(new Stub((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))));
        using var outage = new AppUpdateManager(outageClient, "1.0.56.14", output);
        await Reject(async () => { await outage.CheckAsync(); }, "GitHub failure is reported");
        using var slow = new HttpClient(new Stub(async (_, token) => { await Task.Delay(Timeout.Infinite, token); return new HttpResponseMessage(); }));
        using var slowManager = new AppUpdateManager(slow, "1.0.56.14", output);
        using var stop = new CancellationTokenSource(100);
        await Reject(async () => { await slowManager.CheckAsync(stop.Token); }, "cancel interrupts metadata request");
    }

    private static void PackageChecks(string output)
    {
        foreach (string bad in new[] { "../escape.exe", "C:/escape.exe", "folder/../escape.exe", "file:stream", "CON.txt", "trailing. ", "SerpiumVPN.EXE", "SubscriptionDevices/device.sdevice", "bin_files/serpium.runtime.json", "Server/key.txt", "bin_files/relay/configs/key.json" })
        {
            byte[] bytes = Package(bad); string path = Path.Combine(output, "bad.zip"); File.WriteAllBytes(path, bytes);
            Reject(() => { UpdatePackage.Verify(path, Hash(bytes)); return Task.CompletedTask; }, "unsafe archive rejected: " + bad).GetAwaiter().GetResult();
        }
    }

    private static void InstallationChecks(string output)
    {
        string target = Path.Combine(output, "install-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(target);
        foreach (string name in Required)
        { string path = Path.Combine(target, name); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, "old:" + name); }
        string settings = Path.Combine(target, "bin_files", "serpium.runtime.json"); File.WriteAllText(settings, "user settings");
        string profile = Path.Combine(target, "personal.svault"); File.WriteAllText(profile, "encrypted fixture");
        byte[] package = Package("new-file.txt"); string archive = Path.Combine(output, "install.zip"); File.WriteAllBytes(archive, package);
        using (var locked = new FileStream(Path.Combine(target, "SerpiumVPN.dll"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Reject(() => { UpdateInstaller.Install(archive, Hash(package), target, Console.WriteLine); return Task.CompletedTask; }, "locked file stops installation and invokes rollback").GetAwaiter().GetResult();
            Check(Required.All(n => File.ReadAllText(Path.Combine(target, n)) == "old:" + n), "rollback restores all prior application files");
            Check(!File.Exists(Path.Combine(target, "new-file.txt")), "rollback removes files added by failed update");
        }
        UpdateInstaller.Install(archive, Hash(package), target, Console.WriteLine);
        Check(Required.All(n => File.ReadAllText(Path.Combine(target, n)) == "new:" + n), "successful update replaces program and components");
        Check(File.ReadAllText(settings) == "user settings" && File.ReadAllText(profile) == "encrypted fixture", "update preserves user settings and profiles");
        Check(!Directory.EnumerateFiles(target, "*.update-*", SearchOption.AllDirectories).Any(), "no temporary replacement files remain");
    }

    private static void UiChecks(string output, string project)
    {
        var app = new Application();
        var dictionary = XDocument.Load(Path.Combine(project, "App.xaml")).Descendants(XName.Get("ResourceDictionary", "http://schemas.microsoft.com/winfx/2006/xaml/presentation")).First();
        app.Resources = (ResourceDictionary)System.Windows.Markup.XamlReader.Parse(dictionary.ToString());
        var view = new SimpleHomeView();
        T Find<T>(string name) => (T)view.FindName(name);
        view.SetConnectionState(true, false, true, true);
        view.SetProgramUpdateState("1.0.56.14", "Доступна версия 1.0.56.15 · 134 МБ.", ProgramUpdateAction.Download, true, false);
        Check(Find<Button>("ProgramUpdateButton").IsEnabled, "download remains available while VPN connected");
        view.SetComponentUpdateState("Компоненты актуальны", false, false);
        Check(Find<System.Windows.Shapes.Ellipse>("UpdateBadge").Visibility == Visibility.Visible, "component refresh cannot hide application update badge");
        int actions = 0, canceled = 0, rechecks = 0;
        view.ProgramUpdateRequested += (_, _) => actions++;
        view.ProgramUpdateCancelRequested += (_, _) => canceled++;
        view.ProgramUpdateRecheckRequested += (_, _) => rechecks++;
        Find<Button>("ProgramUpdateButton").RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        Find<Button>("ProgramRecheckButton").RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        Check(actions == 1 && rechecks == 1, "download and recheck actions wired");
        view.SetProgramUpdateState("1.0.56.14", "Загрузка обновления: 42%", ProgramUpdateAction.Download, true, true, 42, true);
        Check(!Find<Button>("ProgramUpdateButton").IsEnabled && Find<Button>("ProgramUpdateCancelButton").Visibility == Visibility.Visible && Find<ProgressBar>("ProgramDownloadProgress").Value == 42, "progress shown, duplicate download blocked, cancel available");
        Find<Button>("ProgramUpdateCancelButton").RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        Check(canceled == 1, "cancel action wired");
        view.SetProgramUpdateState("1.0.56.14", "Версия 1.0.56.15 скачана и проверена. Можно установить.", ProgramUpdateAction.Install, true, false);
        Check(Find<Button>("ProgramUpdateButton").IsEnabled && Find<Button>("ProgramUpdateButton").Content!.ToString()!.Contains("перезапустить"), "installation remains discoverable after download while VPN connected");
        view.SetConnectionState(false, true, true, true);
        Check(!Find<Button>("ProgramUpdateButton").IsEnabled, "install blocked during connection/component operation");
        view.SetConnectionState(false, false, true, true);
        view.SetAutomaticProgramChecks(true);
        Check(Find<CheckBox>("AutomaticProgramChecks").IsChecked == true, "automatic check preference visible");
        foreach (var theme in new[] { AppTheme.Midnight, AppTheme.SoftPink })
        {
            AppThemes.Apply(view.Resources, theme); view.SetTheme(theme);
            var panel = (FrameworkElement)Find<Popup>("ComponentUpdatesPopup").Child;
            panel.Measure(new Size(350, 600)); panel.Arrange(new Rect(panel.DesiredSize)); panel.UpdateLayout();
            var image = new RenderTargetBitmap((int)Math.Ceiling(panel.ActualWidth), (int)Math.Ceiling(panel.ActualHeight), 96, 96, PixelFormats.Pbgra32); image.Render(panel);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
            using var stream = File.Create(Path.Combine(output, "updates-" + theme + ".png")); encoder.Save(stream);
        }
        app.Shutdown();
    }
    private sealed class Stub(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken); }
    private sealed class InlineProgress(Action<int>? report = null) : IProgress<int>
    { public List<int> Values { get; } = []; public void Report(int value) { Values.Add(value); report?.Invoke(value); } }
}
