using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace SerpiumVPN.Relay.Routing;

public sealed record ApplicationBundleDiscoveryResult(
    string DisplayName,
    string PrimaryExecutablePath,
    IReadOnlyList<ApplicationBundleCandidate> Candidates);

public sealed record ApplicationBundleObservationProgress(
    int SecondsRemaining,
    int ObservedProcessCount,
    int CandidateCount,
    string StatusText);

/// <summary>
/// Discovers executable groups without reading process memory or changing applications.
/// Static discovery uses file metadata. Runtime discovery observes process creation and
/// parent/child relationships for a short, user-controlled window.
/// </summary>
public sealed class ApplicationBundleDiscoveryService
{
    private const uint Th32CsSnapProcess = 0x00000002;
    private const int MaxObservedCandidates = 64;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    private static readonly string[] BlockedFileTokens =
    {
        "unins", "uninstall", "setup", "installer", "repair",
        "crash", "report", "updater", "update", "patcher", "redist"
    };

    private static readonly string[] BlockedProcessNames =
    {
        "serpiumvpn", "serpiumupdater", "xray", "sing-box", "winws",
        "explorer", "dwm", "csrss", "services", "svchost", "lsass",
        "smss", "wininit", "winlogon", "system", "registry"
    };

    public ApplicationBundleDiscoveryResult CreateInitial(
        string executablePath,
        IEnumerable<string>? existingExecutables = null,
        string? existingDisplayName = null)
    {
        string requestedPrimaryPath = Path.GetFullPath(executablePath);
        EnsureAllowedPrimaryExecutable(requestedPrimaryPath);
        RoutingRegistryEntry staticEntry = ApplicationDependencyScanner.BuildEntry(requestedPrimaryPath);
        Dictionary<string, ApplicationBundleCandidate> candidates =
            new(StringComparer.OrdinalIgnoreCase);

        string primaryPath = Path.GetFullPath(staticEntry.PrimaryValue);
        AddOrMerge(
            candidates,
            new ApplicationBundleCandidate(
                primaryPath,
                isPrimary: true,
                isSelected: true,
                isRecommended: true,
                isObserved: false,
                sourceDescription: "Выбранный основной EXE"));

        foreach (string relatedPath in staticEntry.RelatedExecutables)
        {
            if (string.Equals(relatedPath, primaryPath, StringComparison.OrdinalIgnoreCase))
                continue;

            AddOrMerge(
                candidates,
                new ApplicationBundleCandidate(
                    relatedPath,
                    isPrimary: false,
                    isSelected: true,
                    isRecommended: true,
                    isObserved: false,
                    sourceDescription: "Статический поиск по папке и метаданным"));
        }

        if (existingExecutables is not null)
        {
            foreach (string path in existingExecutables)
            {
                if (string.IsNullOrWhiteSpace(path) ||
                    !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string fullPath;
                try
                {
                    fullPath = Path.GetFullPath(path);
                }
                catch
                {
                    continue;
                }

                AddOrMerge(
                    candidates,
                    new ApplicationBundleCandidate(
                        fullPath,
                        isPrimary: string.Equals(fullPath, primaryPath, StringComparison.OrdinalIgnoreCase),
                        isSelected: true,
                        isRecommended: true,
                        isObserved: false,
                        sourceDescription: "Ранее сохранено в группе"));
            }
        }

        string displayName = string.IsNullOrWhiteSpace(existingDisplayName)
            ? staticEntry.DisplayName
            : existingDisplayName.Trim();

        return new ApplicationBundleDiscoveryResult(
            displayName,
            primaryPath,
            candidates.Values
                .OrderByDescending(candidate => candidate.IsPrimary)
                .ThenByDescending(candidate => candidate.IsRecommended)
                .ThenBy(candidate => candidate.FileName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray());
    }

    public async Task<IReadOnlyList<ApplicationBundleCandidate>> ObserveLaunchAsync(
        string primaryExecutablePath,
        TimeSpan duration,
        IProgress<ApplicationBundleObservationProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string primaryPath = Path.GetFullPath(primaryExecutablePath);
        string trustRoot = ResolveTrustRoot(primaryPath);
        HashSet<int> baselinePids = CaptureProcessTree().Keys.ToHashSet();
        HashSet<int> trackedPids = new();
        Dictionary<string, ApplicationBundleCandidate> discovered =
            new(StringComparer.OrdinalIgnoreCase);

        DateTimeOffset started = DateTimeOffset.UtcNow;
        DateTimeOffset deadline = started + duration;
        int observedProcessCount = 0;

        while (DateTimeOffset.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            Dictionary<int, int> processTree = CaptureProcessTree();
            Dictionary<int, string> paths = new();

            foreach (int processId in processTree.Keys)
            {
                string? path = TryGetProcessPath(processId);
                if (string.IsNullOrWhiteSpace(path))
                    continue;

                paths[processId] = path;
                if (string.Equals(path, primaryPath, StringComparison.OrdinalIgnoreCase))
                    trackedPids.Add(processId);
            }

            foreach ((int processId, string path) in paths)
            {
                if (discovered.Count >= MaxObservedCandidates)
                    break;

                bool isNewProcess = !baselinePids.Contains(processId);
                bool isPrimary = string.Equals(path, primaryPath, StringComparison.OrdinalIgnoreCase);
                bool isDescendant = IsDescendantOfTrackedProcess(
                    processId,
                    processTree,
                    trackedPids);
                bool isInsideTrustRoot = IsInsideDirectory(path, trustRoot);
                bool metadataRelated = LooksMetadataRelated(primaryPath, path);

                if (!isPrimary && !isNewProcess)
                    continue;

                if (!isPrimary && !isDescendant && !(isInsideTrustRoot && metadataRelated))
                    continue;

                if (IsBlockedExecutable(path, primaryPath))
                    continue;

                bool recommended = isPrimary || isDescendant || metadataRelated;
                string source = isPrimary
                    ? "Основной EXE запущен во время наблюдения"
                    : isDescendant
                        ? "Запущен лаунчером или дочерним процессом"
                        : "Обнаружен в папке приложения во время запуска";

                AddOrMerge(
                    discovered,
                    new ApplicationBundleCandidate(
                        path,
                        isPrimary,
                        isSelected: recommended,
                        isRecommended: recommended,
                        isObserved: true,
                        sourceDescription: source));

                trackedPids.Add(processId);
                observedProcessCount++;
            }

            int secondsRemaining = Math.Max(
                0,
                (int)Math.Ceiling((deadline - DateTimeOffset.UtcNow).TotalSeconds));
            progress?.Report(new ApplicationBundleObservationProgress(
                secondsRemaining,
                observedProcessCount,
                discovered.Count,
                discovered.Count == 0
                    ? "Запустите приложение или игру — Serpium ждёт новые процессы."
                    : $"Обнаружено кандидатов: {discovered.Count}. Можно остановить наблюдение раньше."));

            try
            {
                await Task.Delay(400, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        progress?.Report(new ApplicationBundleObservationProgress(
            0,
            observedProcessCount,
            discovered.Count,
            discovered.Count == 0
                ? "Новые связанные EXE не обнаружены."
                : $"Наблюдение завершено. Найдено: {discovered.Count}."));

        return discovered.Values
            .OrderByDescending(candidate => candidate.IsPrimary)
            .ThenByDescending(candidate => candidate.IsRecommended)
            .ThenBy(candidate => candidate.FileName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private static void AddOrMerge(
        Dictionary<string, ApplicationBundleCandidate> candidates,
        ApplicationBundleCandidate incoming)
    {
        if (candidates.TryGetValue(incoming.ExecutablePath, out ApplicationBundleCandidate? existing))
        {
            existing.MergeEvidence(
                incoming.IsSelected,
                incoming.IsRecommended,
                incoming.IsObserved,
                incoming.SourceDescription);
            return;
        }

        candidates.Add(incoming.ExecutablePath, incoming);
    }

    private static string ResolveTrustRoot(string primaryPath)
    {
        string directory = Path.GetDirectoryName(primaryPath)
            ?? throw new InvalidOperationException("Не удалось определить папку приложения.");
        string leaf = Path.GetFileName(directory).ToLowerInvariant();

        if (leaf is "bin" or "binaries" or "launcher" or "client" or
            "game" or "games" or "win64" or "x64")
        {
            DirectoryInfo? parent = Directory.GetParent(directory);
            if (parent is not null)
                return parent.FullName;
        }

        return directory;
    }

    private static void EnsureAllowedPrimaryExecutable(string primaryPath)
    {
        string fileStem = Path.GetFileNameWithoutExtension(primaryPath).ToLowerInvariant();
        if (BlockedProcessNames.Contains(fileStem, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Служебные процессы Serpium и Windows нельзя добавлять в VPN-маршрутизацию.");

        string windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windowsDirectory) && IsInsideDirectory(primaryPath, windowsDirectory))
            throw new InvalidOperationException("Системные EXE Windows нельзя добавлять в VPN-маршрутизацию.");

        string serpiumDirectory = AppContext.BaseDirectory;
        if (!string.IsNullOrWhiteSpace(serpiumDirectory) && IsInsideDirectory(primaryPath, serpiumDirectory))
            throw new InvalidOperationException("Компоненты Serpium нельзя направлять через собственный VPN-шлюз.");
    }

    private static bool IsBlockedExecutable(string path, string primaryPath)
    {
        if (!File.Exists(path) ||
            !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (string.Equals(path, primaryPath, StringComparison.OrdinalIgnoreCase))
            return false;

        string fileStem = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        if (BlockedProcessNames.Contains(fileStem, StringComparer.OrdinalIgnoreCase) ||
            BlockedFileTokens.Any(token => fileStem.Contains(token, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        string windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windowsDirectory) && IsInsideDirectory(path, windowsDirectory))
            return true;

        string serpiumDirectory = AppContext.BaseDirectory;
        if (!string.IsNullOrWhiteSpace(serpiumDirectory) && IsInsideDirectory(path, serpiumDirectory))
            return true;

        return false;
    }

    private static bool LooksMetadataRelated(string primaryPath, string candidatePath)
    {
        if (string.Equals(primaryPath, candidatePath, StringComparison.OrdinalIgnoreCase))
            return true;

        try
        {
            FileVersionInfo primary = FileVersionInfo.GetVersionInfo(primaryPath);
            FileVersionInfo candidate = FileVersionInfo.GetVersionInfo(candidatePath);

            string primaryCompany = Normalize(primary.CompanyName);
            string candidateCompany = Normalize(candidate.CompanyName);
            string primaryProduct = Normalize(primary.ProductName);
            string candidateProduct = Normalize(candidate.ProductName);

            bool sameCompany = primaryCompany.Length >= 3 &&
                string.Equals(primaryCompany, candidateCompany, StringComparison.OrdinalIgnoreCase);
            bool sameProduct = primaryProduct.Length >= 3 &&
                string.Equals(primaryProduct, candidateProduct, StringComparison.OrdinalIgnoreCase);

            string primaryStem = NormalizeStem(primaryPath);
            string candidateStem = NormalizeStem(candidatePath);
            bool relatedName = primaryStem.Length >= 4 && candidateStem.Length >= 4 &&
                (candidateStem.Contains(primaryStem, StringComparison.OrdinalIgnoreCase) ||
                 primaryStem.Contains(candidateStem, StringComparison.OrdinalIgnoreCase));

            return sameProduct || (sameCompany && relatedName) || sameCompany;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsDescendantOfTrackedProcess(
        int processId,
        IReadOnlyDictionary<int, int> processTree,
        IReadOnlySet<int> trackedPids)
    {
        int current = processId;
        for (int depth = 0; depth < 16; depth++)
        {
            if (!processTree.TryGetValue(current, out int parentId) || parentId <= 0 || parentId == current)
                return false;

            if (trackedPids.Contains(parentId))
                return true;

            current = parentId;
        }

        return false;
    }

    private static string? TryGetProcessPath(int processId)
    {
        try
        {
            using Process process = Process.GetProcessById(processId);
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static Dictionary<int, int> CaptureProcessTree()
    {
        Dictionary<int, int> result = new();
        IntPtr snapshot = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == InvalidHandleValue)
            return result;

        try
        {
            ProcessEntry32 entry = new()
            {
                Size = (uint)Marshal.SizeOf<ProcessEntry32>()
            };

            if (!Process32First(snapshot, ref entry))
                return result;

            do
            {
                result[(int)entry.ProcessId] = (int)entry.ParentProcessId;
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            }
            while (Process32Next(snapshot, ref entry));

            return result;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    private static bool IsInsideDirectory(string path, string directory)
    {
        try
        {
            string fullPath = Path.GetFullPath(path);
            string fullDirectory = Path.GetFullPath(directory).TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

            return fullPath.StartsWith(fullDirectory, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static string NormalizeStem(string path)
    {
        string stem = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        return new string(stem.Where(char.IsLetterOrDigit).ToArray());
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int BasePriority;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExecutableFile;
    }
}
