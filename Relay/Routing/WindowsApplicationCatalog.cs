using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml;
using System.Xml.Linq;

namespace SerpiumVPN.Relay.Routing;

public sealed record ApplicationCatalogItem(ManualApplicationTarget Target, string Category, bool HasNetworkCapability = false)
{
    public string DisplayName => Target.DisplayName;
    public string Detail => Target.UnsupportedReason.Length > 0 ? Target.UnsupportedReason : Target.RequiresWebsiteAddress ? "Веб-приложение · укажите сайт" :
        Target.RequiresRunningApplication ? "Запустите приложение и выберите его в списке «Запущенные»" :
        Target.ApplicationId.Length > 0 && Target.PrimaryValue.Length == 0 ? "Microsoft Store · запустите приложение для определения процесса" :
        Target.IsWebApplication ? "Веб-приложение · " + Target.PrimaryValue : Category;
    public bool CanSelect => Target.UnsupportedReason.Length == 0 && !Target.RequiresRunningApplication && (Target.IsWebApplication || !string.IsNullOrWhiteSpace(Target.PrimaryValue));
}

/// <summary>Current-user Shell catalogue. Never launches entries or enumerates other users' packages.</summary>
public static class WindowsApplicationCatalog
{
    public static Task<IReadOnlyList<ApplicationCatalogItem>> ReadAsync(CancellationToken token = default) => OnSta(() => Read(token), token);

    internal static Task<T> OnSta<T>(Func<T> action, CancellationToken token)
    {
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try { token.ThrowIfCancellationRequested(); var result = action(); token.ThrowIfCancellationRequested(); completion.TrySetResult(result); }
            catch (OperationCanceledException) { completion.TrySetCanceled(token); }
            catch (Exception error) { completion.TrySetException(error); }
        }) { IsBackground = true, Name = "Serpium user app catalogue" };
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); return completion.Task;
    }

    internal static IReadOnlyList<ApplicationCatalogItem> Read(CancellationToken token)
    {
        var result = new List<ApplicationCatalogItem>();
        foreach (string folder in ShortcutDirectories())
        {
            if (!Directory.Exists(folder)) continue;
            try
            {
                var options = new EnumerationOptions { RecurseSubdirectories = !IsDesktop(folder), IgnoreInaccessible = true, MaxRecursionDepth = 8, AttributesToSkip = FileAttributes.ReparsePoint };
                foreach (string path in Directory.EnumerateFiles(folder, "*", options)
                    .Where(path => new[] { ".lnk", ".url", ".appref-ms" }.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase)).Take(4096))
                {
                    token.ThrowIfCancellationRequested();
                    try { result.Add(new(ManualApplicationResolver.Inspect(path), "Установленное приложение")); }
                    catch (Exception error) when (IsReadError(error)) { }
                }
            }
            catch (Exception error) when (IsReadError(error)) { }
        }
        ReadShell(result, token);
        return Deduplicate(result).OrderBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase).Take(4096).ToArray();
    }

    internal static IEnumerable<ApplicationCatalogItem> Deduplicate(IEnumerable<ApplicationCatalogItem> result) => result.Where(item => !string.IsNullOrWhiteSpace(item.DisplayName))
            .GroupBy(item => Identity(item.Target), StringComparer.OrdinalIgnoreCase)
            // A plain URL bookmark must not hide an installed browser app for the same site.
            .Select(group => group.OrderByDescending(item => item.Target.ApplicationId.Length > 0)
                .ThenByDescending(item => item.Target.IsWebApplication && Path.GetExtension(item.Target.SourcePath).Equals(".lnk", StringComparison.OrdinalIgnoreCase)).First())
            .GroupBy(item => !item.Target.IsWebApplication && item.Target.PrimaryValue.Length > 0 ? "exe:" + item.Target.PrimaryValue : Identity(item.Target), StringComparer.OrdinalIgnoreCase)
            .SelectMany(group => group.Select(item => item.Target.ApplicationId).Where(id => id.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1
                ? group.Select(item => item with { Target = item.Target with { UnsupportedReason = "Общий EXE нескольких приложений — раздельное переключение недоступно" } })
                : [group.OrderByDescending(item => item.Target.ApplicationId.Length > 0).First()]);

    internal static string Identity(ManualApplicationTarget target) => target.IsWebApplication
        ? "web:" + (target.RequiresWebsiteAddress ? target.SourcePath : target.PrimaryValue)
        : !string.IsNullOrWhiteSpace(target.ApplicationId) ? "app:" + target.ApplicationId
        : target.RequiresRunningApplication ? "launcher:" + target.SourcePath : "exe:" + target.PrimaryValue;

    internal static IEnumerable<string> ShortcutDirectories() => new[]
    {
        Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
    }.Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.OrdinalIgnoreCase);

    internal static bool IsDesktop(string path) => new[] { Environment.SpecialFolder.DesktopDirectory, Environment.SpecialFolder.CommonDesktopDirectory }
        .Any(folder => path.Equals(Environment.GetFolderPath(folder), StringComparison.OrdinalIgnoreCase));

    internal static ManualApplicationTarget? ResolveShortcut(string path, string arguments)
    {
        string id = "";
        var match = System.Text.RegularExpressions.Regex.Match(arguments, @"shell:AppsFolder\\(?<id>[^""\s]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (match.Success) id = match.Groups["id"].Value;
        if (!IsPackageIdentity(id))
        {
            object? shell = null, folder = null, item = null;
            try
            {
                shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application", true)!);
                folder = ((dynamic)shell!).NameSpace(Path.GetDirectoryName(path));
                item = ((dynamic)folder!).ParseName(Path.GetFileName(path));
                if (item is not null) id = Property(item, "System.AppUserModel.ID");
            }
            finally { Release(item); Release(folder); Release(shell); }
        }
        if (!IsPackageIdentity(id)) return null;
        var entries = new List<ApplicationCatalogItem>(); ReadShell(entries, CancellationToken.None);
        return entries.FirstOrDefault(entry => entry.Target.ApplicationId.Equals(id, StringComparison.OrdinalIgnoreCase))?.Target;
    }

    private static void ReadShell(List<ApplicationCatalogItem> result, CancellationToken token)
    {
        object? shell = null, folder = null, items = null;
        try
        {
            shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application", true)!);
            folder = ((dynamic)shell!).NameSpace("shell:AppsFolder");
            if (folder is null) return;
            items = ((dynamic)folder).Items();
            int count = Math.Min((int)((dynamic)items).Count, 4096);
            for (int i = 0; i < count; i++)
            {
                token.ThrowIfCancellationRequested(); object? item = null;
                try
                {
                    item = ((dynamic)items).Item(i);
                    string name = (string)((dynamic)item!).Name;
                    string id = Property(item!, "System.AppUserModel.ID");
                    string root = Property(item!, "System.AppUserModel.PackageInstallPath");
                    if (id.Contains('!') && !string.IsNullOrWhiteSpace(root))
                    {
                        var entry = ReadPackagedApplication(name, id, root);
                        if (entry is not null) result.Add(entry);
                    }
                    else
                    {
                        string target = Property(item!, "System.Link.TargetParsingPath");
                        if (target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(target))
                            result.Add(new(new(name, Path.GetFullPath(target), false), "Установленное приложение"));
                    }
                }
                catch (Exception error) when (IsReadError(error)) { }
                finally { Release(item); }
            }
        }
        catch (Exception error) when (IsReadError(error)) { }
        finally { Release(items); Release(folder); Release(shell); }
    }

    internal static ApplicationCatalogItem? ReadPackagedApplication(string name, string id, string root)
    {
        if (!IsPackageIdentity(id) || !Path.IsPathFullyQualified(root) || root.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        root = Path.GetFullPath(root);
        if (root.StartsWith(Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return null;
        string path = Path.Combine(root, "AppxManifest.xml");
        string[] paths = []; bool internet = false;
        try
        {
            if (File.Exists(path) && new FileInfo(path).Length <= 2 * 1024 * 1024)
            {
                using var reader = XmlReader.Create(path, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 2 * 1024 * 1024 });
                var document = XDocument.Load(reader);
                (paths, internet) = ReadManifest(document, id, root);
            }
        }
        catch (Exception error) when (IsReadError(error)) { }
        return new(new(name, paths.FirstOrDefault() ?? "", false) { ApplicationId = id, ExecutablePaths = paths }, "Microsoft Store / MSIX", internet);
    }

    internal static (string[] Paths, bool Internet) ReadManifest(XDocument document, string id, string root)
    {
        string appId = id[(id.IndexOf('!') + 1)..];
        var application = document.Root?.Elements().FirstOrDefault(node => node.Name.LocalName == "Applications")?
            .Elements().FirstOrDefault(node => node.Name.LocalName == "Application" && (string?)node.Attribute("Id") == appId);
        if (application is null) return ([], false);
        bool internet = document.Root?.Elements().Where(node => node.Name.LocalName == "Capabilities").Elements()
            .Any(node => (string?)node.Attribute("Name") is "internetClient" or "internetClientServer") == true;
        // Only executables declared for this specific application, never all files in the package.
        var paths = application.DescendantsAndSelf().Select(node => (string?)node.Attribute("Executable"))
            .OfType<string>().Select(value => ResolvePackageExecutable(root, value)).OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToArray();
        return (paths, internet);
    }

    internal static string? ResolvePackageExecutable(string root, string value)
    {
        if (Path.IsPathRooted(value) || value.Contains(':') || value.Contains('$') || value.Contains('%') || !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        string full = Path.GetFullPath(Path.Combine(root, value.Replace('/', '\\')));
        return full.StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && File.Exists(full) ? full : null;
    }

    internal static bool IsPackageIdentity(string value) => value.Length is > 3 and <= 260 &&
        System.Text.RegularExpressions.Regex.IsMatch(value, @"^[A-Za-z0-9.-]+_[A-Za-z0-9]+![A-Za-z0-9.-]+$");
    private static string Property(object item, string name) => ((dynamic)item).ExtendedProperty(name) as string ?? "";
    internal static bool IsReadError(Exception error) => error is IOException or UnauthorizedAccessException or ArgumentException or
        NotSupportedException or InvalidOperationException or COMException or XmlException or System.Security.SecurityException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException;
    private static void Release(object? value) { if (value is not null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value); }
}
