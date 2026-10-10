using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SerpiumVPN.Relay.Routing;

public sealed record ManualApplicationTarget(string DisplayName, string PrimaryValue, bool IsWebApplication)
{
    public string ApplicationId { get; init; } = "";
    public string SourcePath { get; init; } = "";
    public string[] ExecutablePaths { get; init; } = [];
    public bool RequiresWebsiteAddress { get; init; }
    public bool RequiresRunningApplication { get; init; }
    public string UnsupportedReason { get; init; } = "";
}

/// <summary>Reads shortcut metadata without launching the target or accessing browser profile data.</summary>
public static class ManualApplicationResolver
{
    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "browser.exe", "browser_proxy.exe", "chrome.exe", "chrome_proxy.exe",
        "msedge.exe", "msedge_proxy.exe", "brave.exe", "vivaldi.exe", "opera.exe"
    };

    public static Task<ManualApplicationTarget> ResolveAsync(string path, CancellationToken token = default)
    {
        var completion = new TaskCompletionSource<ManualApplicationTarget>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                token.ThrowIfCancellationRequested(); var result = Inspect(path);
                if (result.RequiresWebsiteAddress) throw new InvalidOperationException("Это веб-приложение, но его адрес не указан в ярлыке. Укажите адрес сайта при добавлении.");
                if (result.RequiresRunningApplication) throw new InvalidOperationException("Запустите приложение и выберите его в списке «Запущенные».");
                token.ThrowIfCancellationRequested(); completion.TrySetResult(result);
            }
            catch (OperationCanceledException) { completion.TrySetCanceled(token); }
            catch (Exception error) { completion.TrySetException(error); }
        }) { IsBackground = true, Name = "Serpium shortcut reader" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task;
    }

    public static Task<ManualApplicationTarget> InspectAsync(string path, CancellationToken token = default) =>
        WindowsApplicationCatalog.OnSta(() => Inspect(path), token);

    internal static ManualApplicationTarget Inspect(string path)
    {
        path = LocalFile(path);
        string extension = Path.GetExtension(path);
        string label = Path.GetFileNameWithoutExtension(path);
        if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)) return Native(path, "");
        if (extension.Equals(".appref-ms", StringComparison.OrdinalIgnoreCase))
            return new(label, "", false) { SourcePath = path, RequiresRunningApplication = true };
        if (!extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase) && !extension.Equals(".url", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Выберите приложение EXE или ярлык LNK/URL.");
        if (new FileInfo(path).Length > 512 * 1024) throw new InvalidOperationException("Файл слишком большой для ярлыка.");
        if (extension.Equals(".url", StringComparison.OrdinalIgnoreCase))
        {
            string url = ReadInternetShortcut(path);
            if (Uri.TryCreate(url, UriKind.Absolute, out var protocol) && protocol.Scheme is not ("http" or "https" or "file" or "javascript" or "data"))
                return new(label, "", false) { SourcePath = path, RequiresRunningApplication = true };
            return Website(url, label) with { SourcePath = path };
        }

        object? shell = null, shortcut = null;
        try
        {
            shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell", throwOnError: true)!);
            shortcut = ((dynamic)shell!).CreateShortcut(path);
            string target = (string)((dynamic)shortcut).TargetPath;
            string arguments = (string)((dynamic)shortcut).Arguments;
            if (string.IsNullOrWhiteSpace(target) || Path.GetFileName(target).Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                var packaged = WindowsApplicationCatalog.ResolveShortcut(path, arguments);
                if (packaged is not null) return packaged with { SourcePath = path };
            }
            if (string.IsNullOrWhiteSpace(target))
                throw new InvalidOperationException("В ярлыке нет пути к приложению. Для веб-приложения добавьте адрес во вкладке «Сайты».");
            target = LocalFile(Environment.ExpandEnvironmentVariables(target));
            if (Browsers.Contains(Path.GetFileName(target)))
            {
                var args = ParseArguments(arguments);
                string? url = Switch(args, "--app"), id = Switch(args, "--app-id");
                if (url is not null && id is not null) throw new InvalidOperationException("Ярлык содержит несколько адресов приложения.");
                if (url is not null) return Website(url, label) with { SourcePath = path };
                if (id is not null)
                {
                    string? knownUrl = ResolveManifestUrl(id, label);
                    if (knownUrl is not null) return Website(knownUrl, label) with { SourcePath = path };
                    return new(label, "", true) { SourcePath = path, RequiresWebsiteAddress = true };
                }
            }
            if (Regex.IsMatch(arguments, @"(?:^|\s)-{1,2}(?:applaunch|launch-product|launch-game)(?:\s|=)|(?:^|[\s""'])(?:steam|com\.epicgames\.launcher|uplay|battlenet|riotclient):", RegexOptions.IgnoreCase))
                return new(label, "", false) { SourcePath = path, RequiresRunningApplication = true };
            string? resolved = InstalledApplicationDiscovery.ResolveShortcutTarget(target, arguments);
            if (resolved is null) throw new InvalidOperationException("Не удалось найти приложение из ярлыка. Выберите его EXE.");
            return Native(resolved, label) with { SourcePath = path };
        }
        catch (COMException error) { throw new InvalidOperationException("Windows не смогла прочитать ярлык. Выберите EXE или адрес сайта.", error); }
        finally
        {
            if (shortcut is not null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
        }
    }

    private static string LocalFile(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
            throw new InvalidOperationException("Выберите файл на этом компьютере.");
        path = Path.GetFullPath(path);
        if (!File.Exists(path)) throw new InvalidOperationException("Файл из ярлыка не найден. Возможно, приложение было перемещено.");
        return path;
    }

    private static ManualApplicationTarget Native(string path, string label)
    {
        path = LocalFile(path);
        if (Path.GetFileName(path).EndsWith("_proxy.exe", StringComparison.OrdinalIgnoreCase) && Browsers.Contains(Path.GetFileName(path)))
            throw new InvalidOperationException("Это общий запускатель браузера. Выберите сам ярлык веб-приложения или добавьте адрес во вкладке «Сайты».");
        if (!Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Ярлык должен указывать на приложение EXE или сайт.");
        return new(label, path, false);
    }

    private static ManualApplicationTarget Website(string url, string label)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
            throw new InvalidOperationException("В ярлыке нужен обычный адрес сайта HTTP или HTTPS.");
        string domain = SecureRoutingRegistry.NormalizeDomain(url);
        // A web-app row represents this site, including its www and other subdomains.
        if (domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) domain = domain[4..];
        return new(label, domain, true);
    }

    private static string ReadInternetShortcut(string path)
    {
        bool section = false;
        string? url = null;
        foreach (string raw in File.ReadLines(path))
        {
            string line = raw.Trim();
            if (line.StartsWith('[')) { section = line.Equals("[InternetShortcut]", StringComparison.OrdinalIgnoreCase); continue; }
            if (!section || !line.StartsWith("URL=", StringComparison.OrdinalIgnoreCase)) continue;
            if (url is not null) throw new InvalidOperationException("Ярлык содержит несколько адресов.");
            url = line[4..].Trim();
        }
        return url ?? throw new InvalidOperationException("В ярлыке не найден адрес сайта.");
    }

    internal static bool IsBrowserWebAppShortcut(string target, string arguments) => Browsers.Contains(Path.GetFileName(target)) &&
        Regex.IsMatch(arguments, @"(?:^|\s)--app(?:-id)?(?:=|\s|$)", RegexOptions.IgnoreCase);

    private static string? ResolveManifestUrl(string id, string label)
    {
        if (!Regex.IsMatch(id, "^[a-p]{32}$")) return null;
        // Known manifest URLs also work when the user has renamed the TikTok shortcut.
        var candidates = new List<string> { "https://www.tiktok.com/", "https://www.tiktok.com/?lang=en", "https://tiktok.com/" };
        string name = label.Trim().ToLowerInvariant();
        if (Regex.IsMatch(name, "^[a-z0-9][a-z0-9-]{0,62}$"))
        {
            candidates.Add("https://" + name + ".com/");
            candidates.Add("https://www." + name + ".com/");
        }
        // A label alone never determines a route: the manifest must reproduce the exact installed app ID.
        return candidates.FirstOrDefault(url => ChromiumAppId(url) == id);
    }

    internal static string ChromiumAppId(string manifestUrl)
    {
        byte[] hash = SHA256.HashData(SHA256.HashData(Encoding.UTF8.GetBytes(manifestUrl)));
        return string.Concat(hash.Take(16).SelectMany(value => new[] { (char)('a' + (value >> 4)), (char)('a' + (value & 15)) }));
    }

    private static string? Switch(string[] args, string name)
    {
        string? value = null;
        for (int i = 0; i < args.Length; i++)
        {
            string? found = args[i].StartsWith(name + "=", StringComparison.OrdinalIgnoreCase) ? args[i][(name.Length + 1)..] :
                args[i].Equals(name, StringComparison.OrdinalIgnoreCase) ? (i + 1 < args.Length ? args[++i] : "") : null;
            if (found is null) continue;
            if (value is not null || string.IsNullOrWhiteSpace(found)) throw new InvalidOperationException("Некорректные параметры веб-приложения в ярлыке.");
            value = found;
        }
        return value;
    }

    private static string[] ParseArguments(string arguments)
    {
        if (arguments.Length > 8192) throw new InvalidOperationException("Слишком длинные параметры ярлыка.");
        IntPtr argv = CommandLineToArgvW("shortcut.exe " + arguments, out int count);
        if (argv == IntPtr.Zero) throw new InvalidOperationException("Не удалось прочитать параметры ярлыка.");
        try { return Enumerable.Range(1, count - 1).Select(i => Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size)) ?? "").ToArray(); }
        finally { LocalFree(argv); }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
