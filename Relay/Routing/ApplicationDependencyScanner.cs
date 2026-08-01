using System.Diagnostics;
using System.IO;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Builds a conservative application group from a user-selected executable.
/// MVP7.1.1 does not claim full runtime dependency discovery: it only adds
/// nearby executables that share strong product/company/name signals.
/// Runtime child-process observation is intentionally reserved for MVP7.1.2.
/// </summary>
public static class ApplicationDependencyScanner
{
    private const int MaxCandidates = 24;

    private static readonly string[] ExcludedTokens =
    {
        "unins", "uninstall", "setup", "install", "repair", "crash",
        "report", "updater", "update", "patcher", "redist", "vc_redist"
    };

    public static RoutingRegistryEntry BuildEntry(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            throw new ArgumentException("Путь к приложению пуст.", nameof(executablePath));

        string primaryPath = Path.GetFullPath(executablePath.Trim());
        if (!File.Exists(primaryPath))
            throw new FileNotFoundException("Выбранный EXE-файл не найден.", primaryPath);

        if (!string.Equals(Path.GetExtension(primaryPath), ".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Можно добавить только исполняемый EXE-файл.");

        FileVersionInfo primaryInfo = FileVersionInfo.GetVersionInfo(primaryPath);
        string displayName = FirstNotEmpty(
            primaryInfo.ProductName,
            primaryInfo.FileDescription,
            Path.GetFileNameWithoutExtension(primaryPath));

        string primaryDirectory = Path.GetDirectoryName(primaryPath)
            ?? throw new InvalidOperationException("Не удалось определить папку приложения.");

        List<string> candidates = new() { primaryPath };
        foreach (string candidate in EnumerateNearbyExecutables(primaryDirectory))
        {
            if (candidates.Count >= MaxCandidates)
                break;

            string fullCandidate;
            try
            {
                fullCandidate = Path.GetFullPath(candidate);
            }
            catch
            {
                continue;
            }

            if (string.Equals(fullCandidate, primaryPath, StringComparison.OrdinalIgnoreCase) ||
                candidates.Contains(fullCandidate, StringComparer.OrdinalIgnoreCase) ||
                IsClearlyAuxiliary(fullCandidate))
            {
                continue;
            }

            if (LooksRelated(primaryPath, primaryInfo, fullCandidate))
                candidates.Add(fullCandidate);
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new RoutingRegistryEntry
        {
            Id = Guid.NewGuid(),
            Kind = RoutingTargetKind.Application,
            DisplayName = displayName.Trim(),
            PrimaryValue = primaryPath,
            RelatedExecutables = candidates
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(path => string.Equals(path, primaryPath, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            IncludeSubdomains = false,
            IsEnabled = true,
            CreatedUtc = now,
            UpdatedUtc = now
        };
    }

    private static IEnumerable<string> EnumerateNearbyExecutables(string directory)
    {
        IEnumerable<string> rootFiles;
        try
        {
            rootFiles = Directory.EnumerateFiles(directory, "*.exe", SearchOption.TopDirectoryOnly);
        }
        catch
        {
            yield break;
        }

        foreach (string file in rootFiles)
            yield return file;

        IEnumerable<string> childDirectories;
        try
        {
            childDirectories = Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly)
                .Take(20)
                .ToArray();
        }
        catch
        {
            yield break;
        }

        foreach (string childDirectory in childDirectories)
        {
            IEnumerable<string> childFiles;
            try
            {
                childFiles = Directory.EnumerateFiles(childDirectory, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                continue;
            }

            foreach (string file in childFiles)
                yield return file;
        }
    }

    private static bool LooksRelated(
        string primaryPath,
        FileVersionInfo primaryInfo,
        string candidatePath)
    {
        FileVersionInfo candidateInfo;
        try
        {
            candidateInfo = FileVersionInfo.GetVersionInfo(candidatePath);
        }
        catch
        {
            return false;
        }

        string primaryCompany = Normalize(primaryInfo.CompanyName);
        string candidateCompany = Normalize(candidateInfo.CompanyName);
        string primaryProduct = Normalize(primaryInfo.ProductName);
        string candidateProduct = Normalize(candidateInfo.ProductName);

        bool sameCompany = primaryCompany.Length >= 3 &&
                           string.Equals(primaryCompany, candidateCompany, StringComparison.OrdinalIgnoreCase);
        bool sameProduct = primaryProduct.Length >= 3 &&
                           string.Equals(primaryProduct, candidateProduct, StringComparison.OrdinalIgnoreCase);

        string primaryStem = NormalizeFileStem(primaryPath);
        string candidateStem = NormalizeFileStem(candidatePath);
        bool relatedName = primaryStem.Length >= 4 && candidateStem.Length >= 4 &&
                           (candidateStem.Contains(primaryStem, StringComparison.OrdinalIgnoreCase) ||
                            primaryStem.Contains(candidateStem, StringComparison.OrdinalIgnoreCase) ||
                            SharedPrefixLength(primaryStem, candidateStem) >= 5);

        string primaryDirectory = Path.GetDirectoryName(primaryPath) ?? string.Empty;
        string candidateDirectory = Path.GetDirectoryName(candidatePath) ?? string.Empty;
        bool sameDirectory = string.Equals(
            primaryDirectory,
            candidateDirectory,
            StringComparison.OrdinalIgnoreCase);

        return sameProduct || (sameCompany && (sameDirectory || relatedName)) ||
               (sameDirectory && relatedName);
    }

    private static bool IsClearlyAuxiliary(string path)
    {
        string fileName = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        return ExcludedTokens.Any(token => fileName.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeFileStem(string path)
    {
        string stem = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        char[] characters = stem.Where(char.IsLetterOrDigit).ToArray();
        return new string(characters);
    }

    private static int SharedPrefixLength(string left, string right)
    {
        int limit = Math.Min(left.Length, right.Length);
        int index = 0;
        while (index < limit && char.ToLowerInvariant(left[index]) == char.ToLowerInvariant(right[index]))
            index++;

        return index;
    }

    private static string Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static string FirstNotEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "Приложение";
}
