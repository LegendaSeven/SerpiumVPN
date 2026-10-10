using System.Diagnostics;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SerpiumVPN.Relay.Routing;

public sealed record DiscoveredApplication(string DisplayName, string ExecutablePath)
{
    public string ApplicationId { get; init; } = "";
    public string[] ExecutablePaths { get; init; } = [];
    public bool IsWebApplication { get; init; }
    public ManualApplicationTarget ToTarget() => new(DisplayName, ExecutablePath, IsWebApplication)
        { ApplicationId = ApplicationId, ExecutablePaths = ExecutablePaths };
}

/// <summary>Lists user-facing network apps, with cached registrations and passive process observation.</summary>
public sealed class InstalledApplicationDiscovery : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1,1);
    private readonly Dictionary<string, Metadata> _metadata = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string,string> _catalog = new(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyList<ApplicationCatalogItem> _catalogEntries = [];
    private HashSet<string> _services = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,DateTimeOffset> _observed = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _verifiedUserApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _visibleUserApps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string,DateTimeOffset> _engineObserved = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _historyPath;
    private readonly string _windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private DateTimeOffset _catalogExpires;
    private bool _historyLoaded;
    private bool _historyDirty;
    private DateTimeOffset _nextHistorySave;
    private readonly List<FileSystemWatcher> _catalogWatchers = [];
    private long _catalogChangeTicks;
    private long _appliedCatalogChangeTicks;
    private int _disposed;

    public InstalledApplicationDiscovery() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SerpiumVPN","network-applications.json")) { }

    internal InstalledApplicationDiscovery(string historyPath) : this(historyPath, WindowsApplicationCatalog.ShortcutDirectories()) { }

    internal InstalledApplicationDiscovery(string historyPath, IEnumerable<string> watchDirectories)
    {
        _historyPath = historyPath;
        foreach (string directory in watchDirectories.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var watcher = new FileSystemWatcher(directory)
                {
                    IncludeSubdirectories = !WindowsApplicationCatalog.IsDesktop(directory),
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite
                };
                watcher.Filters.Add("*.lnk"); watcher.Filters.Add("*.url"); watcher.Filters.Add("*.appref-ms");
                watcher.Created += CatalogChanged;
                watcher.Deleted += CatalogChanged;
                watcher.Changed += CatalogChanged;
                watcher.Renamed += CatalogChanged;
                watcher.Error += (_, _) => Interlocked.Exchange(ref _catalogChangeTicks, DateTimeOffset.UtcNow.UtcTicks);
                watcher.EnableRaisingEvents = true;
                _catalogWatchers.Add(watcher);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { }
        }
    }

    private void CatalogChanged(object sender, FileSystemEventArgs args) =>
        Interlocked.Exchange(ref _catalogChangeTicks, DateTimeOffset.UtcNow.UtcTicks);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        foreach (var watcher in _catalogWatchers) watcher.Dispose();
        _catalogWatchers.Clear();
    }
    internal int CatalogRefreshCount { get; private set; }

    public void ObserveInternetApplications(IEnumerable<string> paths)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (string path in paths.Take(2048))
            if (!string.IsNullOrWhiteSpace(path) && (_engineObserved.Count < 4096 || _engineObserved.ContainsKey(path))) _engineObserved[path] = now;
    }

    public async Task<IReadOnlyList<DiscoveredApplication>> DiscoverAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var completion = new TaskCompletionSource<IReadOnlyList<DiscoveredApplication>>(TaskCreationOptions.RunContinuationsAsynchronously);
            var thread = new Thread(() =>
            {
                try { completion.TrySetResult(Discover(cancellationToken)); }
                catch (OperationCanceledException) { completion.TrySetCanceled(cancellationToken); }
                catch (Exception error) { completion.TrySetException(error); }
            }) { IsBackground = true, Name = "Serpium application discovery" };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            return await completion.Task.ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private IReadOnlyList<DiscoveredApplication> Discover(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (!_historyLoaded) LoadHistory(now);
        long changeTicks = Interlocked.Read(ref _catalogChangeTicks);
        bool changed = changeTicks != _appliedCatalogChangeTicks && now.UtcTicks - changeTicks >= TimeSpan.FromSeconds(1).Ticks;
        if (now >= _catalogExpires || changed)
        {
            // Build a new snapshot first: cancellation never commits a partial catalogue.
            HashSet<string> services = ReadServiceExecutables(token);
            var entries = SanitizePackageExecutables(WindowsApplicationCatalog.Read(token), services);
            Dictionary<string,string> catalog = ReadCatalog(token, entries);
            _services = services;
            _catalog = catalog;
            _catalogEntries = entries;
            // A short fallback also covers App Paths registrations without a Start Menu shortcut.
            _catalogExpires = now.AddMinutes(1);
            _appliedCatalogChangeTicks = changeTicks;
            CatalogRefreshCount++;
            foreach (string stale in _metadata.Keys.Where(path => !catalog.ContainsKey(path) &&
                         !_visibleUserApps.Contains(path) && !_observed.ContainsKey(path)).ToArray())
                _metadata.Remove(stale);
        }
        // The TUN connection snapshot also supplies real UDP destinations when VPN is active.
        // A bound UDP socket alone is not proof of internet access. Ownership still comes from Windows.
        foreach (var stale in _engineObserved.Where(item => now - item.Value > TimeSpan.FromSeconds(15)))
            _engineObserved.TryRemove(stale.Key,out _);
        var processes = UserNetworkProcessSnapshot.Capture(token, _engineObserved.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase));
        _catalogEntries = SanitizePackageExecutables(MergePackageProcesses(_catalogEntries, processes), _services);
        var excludedPackagePaths = _catalogEntries.Where(item => !item.Target.IsWebApplication &&
                UserApplicationPolicy.IsAutomaticUtility(item.Target.PrimaryValue, item.Target.ApplicationId))
            .SelectMany(item => item.Target.ExecutablePaths.Append(item.Target.PrimaryValue)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        bool AutoAllowed(string path) => IsAllowed(path) && !excludedPackagePaths.Contains(path);
        foreach (var item in _catalogEntries.Where(item => item.Target.ApplicationId.Length > 0 && item.Target.PrimaryValue.Length > 0 && item.Target.UnsupportedReason.Length == 0))
            _catalog[item.Target.PrimaryValue] = item.DisplayName;
        var running = new HashSet<string>(processes.Select(item => item.Path),StringComparer.OrdinalIgnoreCase);
        foreach (var process in processes)
        {
            token.ThrowIfCancellationRequested();
            if (!AutoAllowed(process.Path)) continue;
            if (process.HasWindow && _visibleUserApps.Count < 2048) _visibleUserApps.Add(process.Path);
        }
        // Old history only proves network activity. It cannot stand in for a user
        // app registration/window; otherwise background components return forever.
        bool HasUserEntryPoint(string path) => _catalog.ContainsKey(path) || _visibleUserApps.Contains(path) || _verifiedUserApps.Contains(path);
        var internetPaths = processes.Where(process => process.UsesInternet &&
                UserApplicationPolicy.IsAllowedManualPath(process.Path, _windows, _services))
            .Select(process => process.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Attribute a declared package companion's real traffic to its app entry.
        // Manifest network permission by itself is deliberately not evidence.
        var observedPaths = internetPaths.Concat(_catalogEntries.Where(item => item.Target.ApplicationId.Length > 0 &&
                item.Target.UnsupportedReason.Length == 0 && item.Target.ExecutablePaths.Any(internetPaths.Contains))
            .Select(item => item.Target.PrimaryValue)).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (string path in observedPaths)
        {
            if (!AutoAllowed(path) || !HasUserEntryPoint(path)) continue;
            if (_verifiedUserApps.Add(path)) _historyDirty = true;
            if (!_observed.TryGetValue(path,out var previous) || now - previous > TimeSpan.FromDays(1))
            {
                _observed[path] = now;
                _historyDirty = true;
            }
        }
        var paths = _catalog.Keys.Concat(_visibleUserApps).Concat(_observed.Keys).Distinct(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<(DiscoveredApplication App, Metadata Info)>();
        foreach (string path in paths)
        {
            token.ThrowIfCancellationRequested();
            if (!AutoAllowed(path)) continue;
            Metadata info = ReadMetadata(path);
            var registered = _catalogEntries.FirstOrDefault(item => !item.Target.IsWebApplication && item.Target.PrimaryValue.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (registered?.Target.UnsupportedReason.Length > 0) continue;
            bool observed = _observed.TryGetValue(path,out var lastSeen) && now - lastSeen < TimeSpan.FromDays(90);
            if (!UserApplicationPolicy.ShouldInclude(true,HasUserEntryPoint(path),
                    UserApplicationPolicy.IsKnownNetworkClient(path,info.Product,info.Company),observed)) continue;
            string? label = _catalog.GetValueOrDefault(path);
            if (string.IsNullOrWhiteSpace(label)) label = info.Description;
            if (string.IsNullOrWhiteSpace(label)) label = Path.GetFileNameWithoutExtension(path);
            candidates.Add((new(label.Trim(),path) { ApplicationId = registered?.Target.ApplicationId ?? "", ExecutablePaths = registered?.Target.ExecutablePaths ?? [] },info));
        }
        var result = candidates.GroupBy(item => item.App.ApplicationId.Length > 0 ? item.App.ApplicationId : UserApplicationPolicy.Identity(item.App.ExecutablePath,item.Info.Product,item.Info.Company),StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(item => running.Contains(item.App.ExecutablePath))
                .ThenByDescending(item => item.Info.ModifiedUtc).ThenBy(item => item.App.ExecutablePath,StringComparer.OrdinalIgnoreCase).First().App)
            .Concat(_catalogEntries.Where(item => item.Target.IsWebApplication && !item.Target.RequiresWebsiteAddress && item.Target.PrimaryValue.Length > 0 &&
                    Path.GetExtension(item.Target.SourcePath).Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                .Select(item => new DiscoveredApplication(item.DisplayName, item.Target.PrimaryValue) { IsWebApplication = true }))
            .OrderBy(app => app.DisplayName,StringComparer.CurrentCultureIgnoreCase).ThenBy(app => app.ExecutablePath,StringComparer.OrdinalIgnoreCase)
            .Take(512).ToArray();
        foreach (string path in _observed.Keys.Where(path => AutoAllowed(path) && HasUserEntryPoint(path)))
            if (_verifiedUserApps.Add(path)) _historyDirty = true;
        foreach (string stale in _observed.Where(item => now - item.Value >= TimeSpan.FromDays(90) || !AutoAllowed(item.Key) || !HasUserEntryPoint(item.Key)).Select(item => item.Key).ToArray())
        { _observed.Remove(stale); _historyDirty = true; }
        _verifiedUserApps.RemoveWhere(path => !_observed.ContainsKey(path));
        _visibleUserApps.RemoveWhere(path => !AutoAllowed(path));
        SaveHistory(now);
        return result;
    }

    internal static void ValidateManualApplication(string path, CancellationToken token)
    {
        if (!File.Exists(path) || !UserApplicationPolicy.IsAllowedManualPath(path,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), ReadServiceExecutables(token)))
            throw new InvalidOperationException("Выберите EXE пользовательского приложения. Системные службы и компоненты VPN добавлять нельзя.");
    }

    internal static string[] FilterManualExecutables(IEnumerable<string> paths, CancellationToken token)
    {
        var services = ReadServiceExecutables(token);
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return paths.Where(path => File.Exists(path) && UserApplicationPolicy.IsAllowedManualPath(path, windows, services)).ToArray();
    }

    public static Task<IReadOnlyList<ApplicationCatalogItem>> SelectionCatalogAsync(bool running, CancellationToken token = default) =>
        WindowsApplicationCatalog.OnSta<IReadOnlyList<ApplicationCatalogItem>>(() =>
        {
            var services = ReadServiceExecutables(token);
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var processes = UserNetworkProcessSnapshot.Capture(token);
            var entries = SanitizePackageExecutables(MergePackageProcesses(WindowsApplicationCatalog.Read(token), processes), services);
            bool Allowed(string path) => File.Exists(path) && UserApplicationPolicy.IsAllowedManualPath(path, windows, services);
            if (!running)
                return entries.Where(item => item.Target.IsWebApplication || item.Target.RequiresRunningApplication ||
                    (item.Target.ApplicationId.Length > 0 && item.Target.PrimaryValue.Length == 0) || Allowed(item.Target.PrimaryValue)).ToArray();
            return processes.Where(process => Allowed(process.Path) && (process.HasWindow || process.UsesInternet))
                .GroupBy(process => process.Path, StringComparer.OrdinalIgnoreCase).Select(group =>
                {
                    var process = group.First();
                    var match = entries.FirstOrDefault(item => !item.Target.IsWebApplication &&
                        ((process.ApplicationId.Length > 0 && item.Target.ApplicationId == process.ApplicationId) || item.Target.PrimaryValue.Equals(process.Path, StringComparison.OrdinalIgnoreCase)));
                    if (match is not null) return match with { Category = "Запущено · " + match.Category };
                    string label = Path.GetFileNameWithoutExtension(process.Path);
                    try { var info = FileVersionInfo.GetVersionInfo(process.Path); label = info.ProductName ?? info.FileDescription ?? label; } catch (Exception error) when (WindowsApplicationCatalog.IsReadError(error)) { }
                    return new ApplicationCatalogItem(new(label, process.Path, false) { ApplicationId = process.ApplicationId }, "Запущенное приложение");
                }).OrderBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToArray();
        }, token);

    internal static IReadOnlyList<ApplicationCatalogItem> MergePackageProcesses(IReadOnlyList<ApplicationCatalogItem> entries, IReadOnlyList<UserNetworkProcess> processes) =>
        entries.Select(item =>
        {
            if (item.Target.ApplicationId.Length == 0) return item;
            string[] observed = processes.Where(process => process.ApplicationId.Equals(item.Target.ApplicationId, StringComparison.OrdinalIgnoreCase))
                .Select(process => process.Path).Where(path => File.Exists(path) && UserApplicationPolicy.IsAllowedManualPath(path,
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), new HashSet<string>())).ToArray();
            string[] paths = item.Target.ExecutablePaths.Concat(observed).Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToArray();
            string primary = File.Exists(item.Target.PrimaryValue) ? item.Target.PrimaryValue : paths.FirstOrDefault() ?? "";
            return item with { Target = item.Target with { PrimaryValue = primary, ExecutablePaths = paths } };
        }).ToArray();

    internal static IReadOnlyList<ApplicationCatalogItem> SanitizePackageExecutables(IReadOnlyList<ApplicationCatalogItem> entries, IReadOnlySet<string> services)
    {
        var owners = entries.Where(item => item.Target.ApplicationId.Length > 0).SelectMany(item => item.Target.ExecutablePaths.Append(item.Target.PrimaryValue)
            .Where(path => path.Length > 0).Select(path => (Path: path, Id: item.Target.ApplicationId)))
            .GroupBy(item => item.Path, StringComparer.OrdinalIgnoreCase).ToDictionary(group => group.Key,
                group => group.Select(item => item.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count(), StringComparer.OrdinalIgnoreCase);
        return entries.Select(item =>
        {
            if (item.Target.ApplicationId.Length == 0) return item;
            bool Allowed(string path) => File.Exists(path) && UserApplicationPolicy.IsAllowedManualPath(path,
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), services);
            string[] paths = item.Target.ExecutablePaths.Append(item.Target.PrimaryValue).Where(path => Allowed(path) && owners.GetValueOrDefault(path) <= 1)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            string primary = Allowed(item.Target.PrimaryValue) ? item.Target.PrimaryValue : paths.FirstOrDefault() ?? "";
            string reason = owners.GetValueOrDefault(primary) > 1 ? "Общий EXE нескольких приложений — раздельное переключение недоступно" : item.Target.UnsupportedReason;
            return item with { Target = item.Target with { PrimaryValue = primary, ExecutablePaths = paths, UnsupportedReason = reason } };
        }).ToArray();
    }

    private bool IsAllowed(string path)
    {
        try { return UserApplicationPolicy.IsAllowedPath(path,_windows,_services) && File.Exists(path); }
        catch (Exception error) when (error is ArgumentException or IOException or NotSupportedException or UnauthorizedAccessException) { return false; }
    }

    // Hard exclusions also apply to saved rows, so old entries cannot restore a service to the list.
    internal bool IsUserApplication(string path) => IsAllowed(path);

    private Metadata ReadMetadata(string path)
    {
        try
        {
            DateTime modified = File.GetLastWriteTimeUtc(path);
            if (_metadata.TryGetValue(path,out Metadata? cached) && cached.ModifiedUtc == modified) return cached;
            var info = FileVersionInfo.GetVersionInfo(path);
            return _metadata[path] = new(info.ProductName ?? "",info.CompanyName ?? "",info.FileDescription ?? "",modified);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { return _metadata[path] = new("","","",DateTime.MinValue); }
    }

    private static Dictionary<string,string> ReadCatalog(CancellationToken token, IReadOnlyList<ApplicationCatalogItem> entries)
    {
        var apps = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? target,string? label = null)
        {
            token.ThrowIfCancellationRequested();
            if (apps.Count >= 2048 || string.IsNullOrWhiteSpace(target)) return;
            try
            {
                string path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(target.Trim().Trim('"')));
                if (path.StartsWith(@"\\",StringComparison.Ordinal) || !path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) return;
                if (!apps.ContainsKey(path)) apps[path] = label ?? "";
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        }
        foreach (var entry in entries.Where(item => !item.Target.IsWebApplication && item.Target.UnsupportedReason.Length == 0))
            Add(entry.Target.PrimaryValue, entry.DisplayName);
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            token.ThrowIfCancellationRequested();
            try
            {
                using var registry = RegistryKey.OpenBaseKey(hive,view);
                using var paths = registry.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths");
                if (paths is null) continue;
                foreach (string name in paths.GetSubKeyNames())
                {
                    using var app = paths.OpenSubKey(name);
                    Add(app?.GetValue(null) as string);
                }
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        }
        return apps;
    }

    internal static string? ResolveShortcutTarget(string target,string arguments)
    {
        if (!Path.GetFileName(target).Equals("Update.exe",StringComparison.OrdinalIgnoreCase)) return target;
        var match = Regex.Match(arguments,"--processStart(?:AndWait)?\\s+[\"']?(?<exe>[^\"'\\s]+\\.exe)",RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        string name = match.Groups["exe"].Value;
        if (Path.GetFileName(name) != name) return null;
        string? root = Path.GetDirectoryName(target);
        if (root is null || !Directory.Exists(root)) return null;
        string direct = Path.Combine(root,name);
        if (File.Exists(direct)) return direct;
        var options = new EnumerationOptions { IgnoreInaccessible=true, AttributesToSkip=FileAttributes.ReparsePoint };
        return Directory.EnumerateDirectories(root,"app-*",options).Take(64)
            .Select(folder => Path.Combine(folder,name)).Where(File.Exists)
            .OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
    }

    private static HashSet<string> ReadServiceExecutables(CancellationToken token)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null) return paths;
        foreach (string name in services.GetSubKeyNames())
        {
            token.ThrowIfCancellationRequested();
            try
            {
                using var service = services.OpenSubKey(name);
                if (service?.GetValue("ImagePath") is not string command) continue;
                string? path = ParseServicePath(command);
                if (path is not null) paths.Add(path);
            }
            catch (Exception error) when (error is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        }
        return paths;
    }

    internal static string? ParseServicePath(string command)
    {
        command = Environment.ExpandEnvironmentVariables(command.Trim());
        var match = Regex.Match(command,"^(?:\"(?<path>[^\"]+\\.exe)\"|(?<path>.+?\\.exe)(?:\\s|$))",RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        string path = match.Groups["path"].Value;
        if (path.StartsWith(@"\??\",StringComparison.Ordinal)) path = path[4..];
        try { return Path.IsPathFullyQualified(path) ? Path.GetFullPath(path) : null; }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or IOException) { return null; }
    }

    private void LoadHistory(DateTimeOffset now)
    {
        _historyLoaded = true;
        try
        {
            if (!File.Exists(_historyPath) || new FileInfo(_historyPath).Length > 1_048_576) return;
            var history = JsonSerializer.Deserialize<HistoryEntry[]>(File.ReadAllText(_historyPath));
            foreach (var entry in (history ?? []).OfType<HistoryEntry>().Take(512))
                if (!string.IsNullOrWhiteSpace(entry.Path) && now - entry.LastSeenUtc < TimeSpan.FromDays(90) && entry.LastSeenUtc <= now)
                {
                    _observed[entry.Path] = entry.LastSeenUtc;
                    if (entry.UserEntryPointConfirmed) _verifiedUserApps.Add(entry.Path);
                }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { }
    }

    private void SaveHistory(DateTimeOffset now)
    {
        if (!_historyDirty || now < _nextHistorySave) return;
        string temporary = _historyPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_historyPath)!);
            var history = _observed.OrderByDescending(item => item.Value).Take(512).Select(item => new HistoryEntry(item.Key,item.Value,_verifiedUserApps.Contains(item.Key))).ToArray();
            File.WriteAllText(temporary,JsonSerializer.Serialize(history));
            File.Move(temporary,_historyPath,true);
            _historyDirty = false;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        finally
        {
            _nextHistorySave = now.AddMinutes(1);
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private sealed record Metadata(string Product,string Company,string Description,DateTime ModifiedUtc);
    private sealed record HistoryEntry(string Path,DateTimeOffset LastSeenUtc,bool UserEntryPointConfirmed = false);
}
