using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN.Relay.Components;

public enum RelayComponentKind
{
    SingBox,
    XrayCore
}

public enum RelayComponentHealth
{
    Healthy,
    Warning,
    Missing,
    Failed
}

public sealed record RelayComponentSnapshot(
    RelayComponentKind Kind,
    string DisplayName,
    string ExecutablePath,
    string SafePath,
    string? InstalledVersion,
    string Sha256,
    long SizeBytes,
    RelayComponentHealth Health,
    string HealthMessage,
    bool ManagedRuntimeCopyExists,
    bool ManagedRuntimeCopyMatches);

public sealed record RelayComponentReleaseAsset(
    string Name,
    string DownloadUrl,
    long SizeBytes,
    string Sha256)
{
    public bool HasVerifiedSha256 =>
        Sha256.Length == 64 &&
        Sha256.All(Uri.IsHexDigit);
}

public sealed record RelayComponentReleaseInfo(
    RelayComponentKind Kind,
    string TagName,
    string NormalizedVersion,
    string ReleaseName,
    DateTimeOffset? PublishedAtUtc,
    string ReleasePageUrl,
    string Repository,
    RelayComponentReleaseAsset? WindowsAmd64Asset);

public sealed record RelayComponentDownloadProgress(
    RelayComponentKind Kind,
    string Stage,
    long BytesReceived,
    long? TotalBytes,
    int Percent,
    string Message);

public sealed record RelayComponentStagingSnapshot(
    RelayComponentKind Kind,
    bool Exists,
    bool Ready,
    string? TagName,
    string? NormalizedVersion,
    string SafeDirectory,
    string? ArchiveSha256,
    string? ExecutableSha256,
    DateTimeOffset? StagedAtUtc,
    string Message);

public sealed record RelayComponentBackupSnapshot(
    RelayComponentKind Kind,
    bool Exists,
    bool Ready,
    string? PreviousVersion,
    string? PreviousExecutableSha256,
    string SafeDirectory,
    DateTimeOffset? CreatedAtUtc,
    bool RuntimeCopyBackedUp,
    string Message);

public sealed record RelayComponentInstallProgress(
    RelayComponentKind Kind,
    string Stage,
    string Message);

public sealed record RelayComponentInstallResult(
    RelayComponentKind Kind,
    bool Succeeded,
    bool RolledBack,
    string? InstalledVersion,
    string? PreviousVersion,
    bool BackupAvailable,
    string Message);

/// <summary>
/// Inspects Relay runtime binaries, verifies official stable GitHub releases,
/// stages update assets and installs them with a persistent rollback point.
/// Compatibility checks read saved profiles in memory and never contact their servers.
/// Installation requires idle components and keeps a verified rollback point.
/// </summary>
public sealed class RelayComponentManager : IDisposable
{
    private const string SingBoxLatestReleaseApi =
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest";

    private const string XrayLatestReleaseApi =
        "https://api.github.com/repos/XTLS/Xray-core/releases/latest";

    private const long MaximumArchiveBytes = 256L * 1024 * 1024;
    private const long MaximumExtractedBytes = 384L * 1024 * 1024;
    private const int MaximumArchiveEntries = 2048;
    private const int StagingManifestSchema = 1;
    private const int BackupManifestSchema = 1;

    private const string ArchiveFileName = "release-asset.zip";
    private const string ManifestFileName = "staging-manifest.json";
    private const string BackupManifestFileName = "backup-manifest.json";
    private const string RuntimeBackupFileName = "managed-runtime-xray-key-client.exe";

    private static readonly Regex ProductVersionRegex = new(
        @"(?im)^\s*(?:sing-box|xray)\s+v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex FallbackVersionRegex = new(
        @"(?i)\bv?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.-]+)?)\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = false
    };

    private readonly string _baseDirectory;
    private readonly string _relayDirectory;
    private readonly string _localAppDataDirectory;
    private readonly string _stagingRoot;
    private readonly string _backupRoot;
    private readonly HttpClient _httpClient;
    private readonly Func<RelayComponentKind,string,CancellationToken,Task> _compatibilityCheck;
    // A writable staging manifest is not an independent source of trusted hashes.
    private readonly ConcurrentDictionary<RelayComponentKind,(string Archive,string Executable)> _verifiedDownloads = new();
    private readonly SemaphoreSlim _stagingGate = new(1, 1);
    private bool _disposed;

    public RelayComponentManager() : this(AppContext.BaseDirectory,
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),null,null) { }

    internal RelayComponentManager(string baseDirectory,string localAppDataDirectory,HttpClient? httpClient,
        Func<RelayComponentKind,string,CancellationToken,Task>? compatibilityCheck)
    {
        _compatibilityCheck = compatibilityCheck ?? new RelayComponentCompatibilityChecker().ValidateAsync;
        _baseDirectory = Path.GetFullPath(baseDirectory)
            .TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar);

        _relayDirectory = Path.Combine(
            _baseDirectory,
            "bin_files",
            "relay");

        _localAppDataDirectory = Path.GetFullPath(localAppDataDirectory);

        _stagingRoot = Path.Combine(
            _localAppDataDirectory,
            "SerpiumVPN",
            "Updates",
            "Relay",
            "Staging");

        _backupRoot = Path.Combine(
            _localAppDataDirectory,
            "SerpiumVPN",
            "Updates",
            "Relay",
            "Backups");

        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            AutomaticDecompression =
                System.Net.DecompressionMethods.GZip |
                System.Net.DecompressionMethods.Deflate
        };

        _httpClient = httpClient ?? new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMinutes(10)
        };
        if (httpClient is not null) handler.Dispose();

        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(
            "SerpiumVPN-Relay-Component-Manager/1.1");

        _httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/vnd.github+json"));

        _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(
            "X-GitHub-Api-Version",
            "2022-11-28");
    }

    public async Task<
        IReadOnlyDictionary<RelayComponentKind, RelayComponentSnapshot>>
        InspectAllAsync(
            CancellationToken cancellationToken = default)
    {
        Task<RelayComponentSnapshot> singBoxTask = InspectAsync(
            RelayComponentKind.SingBox,
            cancellationToken);

        Task<RelayComponentSnapshot> xrayTask = InspectAsync(
            RelayComponentKind.XrayCore,
            cancellationToken);

        await Task.WhenAll(singBoxTask, xrayTask).ConfigureAwait(false);

        return new Dictionary<
            RelayComponentKind,
            RelayComponentSnapshot>
        {
            [RelayComponentKind.SingBox] =
                await singBoxTask.ConfigureAwait(false),

            [RelayComponentKind.XrayCore] =
                await xrayTask.ConfigureAwait(false)
        };
    }

    public Task<RelayComponentSnapshot> InspectAsync(
        RelayComponentKind kind,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return kind switch
        {
            RelayComponentKind.SingBox =>
                InspectSingBoxAsync(cancellationToken),

            RelayComponentKind.XrayCore =>
                InspectXrayAsync(cancellationToken),

            _ => throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                null)
        };
    }

    public async Task<
        IReadOnlyDictionary<RelayComponentKind, RelayComponentReleaseInfo>>
        CheckLatestStableReleasesAsync(
            CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Task<RelayComponentReleaseInfo> singBoxTask =
            GetLatestReleaseAsync(
                RelayComponentKind.SingBox,
                SingBoxLatestReleaseApi,
                "SagerNet/sing-box",
                cancellationToken);

        Task<RelayComponentReleaseInfo> xrayTask =
            GetLatestReleaseAsync(
                RelayComponentKind.XrayCore,
                XrayLatestReleaseApi,
                "XTLS/Xray-core",
                cancellationToken);

        await Task.WhenAll(singBoxTask, xrayTask).ConfigureAwait(false);

        return new Dictionary<
            RelayComponentKind,
            RelayComponentReleaseInfo>
        {
            [RelayComponentKind.SingBox] =
                await singBoxTask.ConfigureAwait(false),

            [RelayComponentKind.XrayCore] =
                await xrayTask.ConfigureAwait(false)
        };
    }

    public async Task<
        IReadOnlyDictionary<RelayComponentKind, RelayComponentStagingSnapshot>>
        InspectAllStagingAsync(
            CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Task<RelayComponentStagingSnapshot> singBoxTask =
            InspectStagingAsync(
                RelayComponentKind.SingBox,
                cancellationToken);

        Task<RelayComponentStagingSnapshot> xrayTask =
            InspectStagingAsync(
                RelayComponentKind.XrayCore,
                cancellationToken);

        await Task.WhenAll(singBoxTask, xrayTask).ConfigureAwait(false);

        return new Dictionary<
            RelayComponentKind,
            RelayComponentStagingSnapshot>
        {
            [RelayComponentKind.SingBox] =
                await singBoxTask.ConfigureAwait(false),

            [RelayComponentKind.XrayCore] =
                await xrayTask.ConfigureAwait(false)
        };
    }

    public async Task<RelayComponentStagingSnapshot> InspectStagingAsync(
        RelayComponentKind kind,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        string componentRoot = GetComponentStagingRoot(kind);

        if (!Directory.Exists(componentRoot))
            return CreateEmptyStagingSnapshot(kind);

        try
        {
            string[] versionDirectories = Directory.GetDirectories(
                componentRoot,
                "*",
                SearchOption.TopDirectoryOnly);

            if (versionDirectories.Length == 0)
                return CreateEmptyStagingSnapshot(kind);

            if (versionDirectories.Length != 1)
            {
                return new RelayComponentStagingSnapshot(
                    kind,
                    Exists: true,
                    Ready: false,
                    TagName: null,
                    NormalizedVersion: null,
                    ToSafePath(componentRoot),
                    ArchiveSha256: null,
                    ExecutableSha256: null,
                    StagedAtUtc: null,
                    "В staging найдено несколько версий. Удалите загруженные данные и повторите подготовку.");
            }

            return await ValidateStagingDirectoryAsync(
                kind,
                versionDirectories[0],
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new RelayComponentStagingSnapshot(
                kind,
                Exists: true,
                Ready: false,
                TagName: null,
                NormalizedVersion: null,
                ToSafePath(componentRoot),
                ArchiveSha256: null,
                ExecutableSha256: null,
                StagedAtUtc: null,
                $"Не удалось проверить staging: {ex.Message}");
        }
    }

    public async Task<
        IReadOnlyDictionary<RelayComponentKind, RelayComponentBackupSnapshot>>
        InspectAllBackupsAsync(
            CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Task<RelayComponentBackupSnapshot> singBoxTask =
            InspectBackupAsync(
                RelayComponentKind.SingBox,
                cancellationToken);

        Task<RelayComponentBackupSnapshot> xrayTask =
            InspectBackupAsync(
                RelayComponentKind.XrayCore,
                cancellationToken);

        await Task.WhenAll(singBoxTask, xrayTask).ConfigureAwait(false);

        return new Dictionary<
            RelayComponentKind,
            RelayComponentBackupSnapshot>
        {
            [RelayComponentKind.SingBox] =
                await singBoxTask.ConfigureAwait(false),

            [RelayComponentKind.XrayCore] =
                await xrayTask.ConfigureAwait(false)
        };
    }

    public async Task<RelayComponentBackupSnapshot> InspectBackupAsync(
        RelayComponentKind kind,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        string backupDirectory = GetComponentBackupDirectory(kind);

        if (!Directory.Exists(backupDirectory))
            return CreateEmptyBackupSnapshot(kind);

        try
        {
            return await ValidateBackupDirectoryAsync(
                kind,
                backupDirectory,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new RelayComponentBackupSnapshot(
                kind,
                Exists: true,
                Ready: false,
                PreviousVersion: null,
                PreviousExecutableSha256: null,
                ToSafePath(backupDirectory),
                CreatedAtUtc: null,
                RuntimeCopyBackedUp: false,
                $"Не удалось проверить rollback backup: {ex.Message}");
        }
    }

    public async Task<RelayComponentStagingSnapshot> StageReleaseAsync(
        RelayComponentKind kind,
        RelayComponentReleaseInfo release,
        IProgress<RelayComponentDownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(release);

        if (release.Kind != kind)
        {
            throw new InvalidOperationException(
                "Релиз относится к другому компоненту.");
        }

        RelayComponentReleaseAsset asset =
            release.WindowsAmd64Asset
            ?? throw new InvalidOperationException(
                "Официальный Windows AMD64 asset не найден.");

        if (!asset.HasVerifiedSha256)
        {
            throw new InvalidDataException(
                "GitHub release asset не содержит пригодный SHA-256 digest.");
        }

        ValidateAsset(kind, release, asset);

        await _stagingGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        string? workRoot = null;
        string? oldRoot = null;

        try
        {
            EnsurePrivateDirectory(_stagingRoot);
            CleanupStaleStagingArtifacts(kind);

            string componentRoot = GetComponentStagingRoot(kind);
            string safeVersion = SanitizePathSegment(
                release.NormalizedVersion);

            workRoot = Path.Combine(
                _stagingRoot,
                "." + GetComponentFolderName(kind) +
                "." + Guid.NewGuid().ToString("N") + ".tmp");

            string workVersionDirectory = Path.Combine(
                workRoot,
                safeVersion);

            EnsurePrivateDirectory(workRoot);
            EnsurePrivateDirectory(workVersionDirectory);

            string archivePath = Path.Combine(
                workVersionDirectory,
                ArchiveFileName);

            string executableName = GetExpectedExecutableName(kind);
            string executablePath = Path.Combine(
                workVersionDirectory,
                executableName);

            ReportProgress(
                progress,
                kind,
                "download",
                0,
                asset.SizeBytes,
                "Скачиваю официальный release asset...");

            string downloadedSha256 = await DownloadAssetAsync(
                kind,
                asset,
                archivePath,
                progress,
                cancellationToken).ConfigureAwait(false);

            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(downloadedSha256),
                    Convert.FromHexString(asset.Sha256)))
            {
                throw new CryptographicException(
                    "SHA-256 скачанного архива не совпадает с digest из GitHub Releases API.");
            }

            ReportProgress(
                progress,
                kind,
                "archive-check",
                asset.SizeBytes,
                asset.SizeBytes,
                "SHA-256 подтверждён. Проверяю структуру ZIP...");

            await ExtractExpectedExecutableAsync(
                kind,
                archivePath,
                executablePath,
                cancellationToken).ConfigureAwait(false);

            string executableSha256 = await ComputeSha256Async(
                executablePath,
                cancellationToken).ConfigureAwait(false);

            _verifiedDownloads[kind] = (downloadedSha256,executableSha256);

            ReportProgress(
                progress,
                kind,
                "version-check",
                asset.SizeBytes,
                asset.SizeBytes,
                "Запускаю безопасную проверку версии...");

            VersionProbeResult probe = await ProbeVersionAsync(
                executablePath,
                cancellationToken).ConfigureAwait(false);

            if (!probe.Started)
            {
                throw new InvalidDataException(
                    "Загруженный компонент не удалось запустить.");
            }

            if (probe.TimedOut)
            {
                throw new TimeoutException(
                    "Проверка версии загруженного компонента превысила тайм-аут.");
            }

            if (probe.ExitCode != 0)
            {
                throw new InvalidDataException(
                    $"Команда version завершилась с кодом {probe.ExitCode}.");
            }

            if (string.IsNullOrWhiteSpace(probe.Version) ||
                !AreEquivalentVersions(
                    probe.Version,
                    release.NormalizedVersion))
            {
                throw new InvalidDataException(
                    "Версия внутри архива не совпадает с версией официального релиза.");
            }

            DateTimeOffset stagedAtUtc = DateTimeOffset.UtcNow;

            StagingManifest manifest = new()
            {
                SchemaVersion = StagingManifestSchema,
                Component = kind.ToString(),
                Repository = release.Repository,
                TagName = release.TagName,
                NormalizedVersion = release.NormalizedVersion,
                ReleasePageUrl = release.ReleasePageUrl,
                AssetName = asset.Name,
                AssetDownloadUrl = asset.DownloadUrl,
                ExpectedArchiveSha256 = asset.Sha256,
                ArchiveSha256 = downloadedSha256,
                ExecutableFileName = executableName,
                ExecutableSha256 = executableSha256,
                ArchiveSizeBytes = new FileInfo(archivePath).Length,
                ExecutableSizeBytes = new FileInfo(executablePath).Length,
                StagedAtUtc = stagedAtUtc
            };

            byte[] manifestBytes = JsonSerializer.SerializeToUtf8Bytes(
                manifest,
                JsonOptions);

            string manifestPath = Path.Combine(
                workVersionDirectory,
                ManifestFileName);

            await File.WriteAllBytesAsync(
                manifestPath,
                manifestBytes,
                cancellationToken).ConfigureAwait(false);

            string persistedManifestSha = await ComputeSha256Async(
                manifestPath,
                cancellationToken).ConfigureAwait(false);

            if (persistedManifestSha.Length != 64)
            {
                throw new IOException(
                    "Не удалось подтвердить staging manifest.");
            }

            oldRoot = componentRoot + "." +
                Guid.NewGuid().ToString("N") + ".old";

            if (Directory.Exists(componentRoot))
            {
                await MoveDirectoryWithRetryAsync(
                    componentRoot,
                    oldRoot,
                    cancellationToken).ConfigureAwait(false);
            }

            await MoveDirectoryWithRetryAsync(
                workRoot,
                componentRoot,
                cancellationToken).ConfigureAwait(false);
            workRoot = null;

            RelayComponentStagingSnapshot snapshot =
                await InspectStagingAsync(
                    kind,
                    cancellationToken).ConfigureAwait(false);

            if (!snapshot.Ready)
            {
                TryDeleteDirectory(componentRoot);

                if (!string.IsNullOrWhiteSpace(oldRoot) &&
                    Directory.Exists(oldRoot))
                {
                    await MoveDirectoryWithRetryAsync(
                        oldRoot,
                        componentRoot,
                        cancellationToken).ConfigureAwait(false);

                    oldRoot = null;
                }

                throw new InvalidDataException(
                    "Финальная проверка staging не пройдена: " +
                    snapshot.Message);
            }

            TryDeleteDirectory(oldRoot);
            oldRoot = null;

            ReportProgress(
                progress,
                kind,
                "ready",
                asset.SizeBytes,
                asset.SizeBytes,
                "Обновление проверено и подготовлено.");

            return snapshot;
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(oldRoot) &&
                Directory.Exists(oldRoot))
            {
                string componentRoot = GetComponentStagingRoot(kind);

                if (!Directory.Exists(componentRoot))
                {
                    await MoveDirectoryWithRetryAsync(
                        oldRoot,
                        componentRoot,
                        cancellationToken).ConfigureAwait(false);
                }

                oldRoot = null;
            }

            throw;
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(workRoot))
                TryDeleteDirectory(workRoot);

            if (!string.IsNullOrWhiteSpace(oldRoot))
                TryDeleteDirectory(oldRoot);

            _stagingGate.Release();
        }
    }

    public void DeleteStagedUpdate(RelayComponentKind kind)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        string componentRoot = GetComponentStagingRoot(kind);

        if (!Directory.Exists(componentRoot))
            return;

        string deleteRoot = componentRoot + "." +
            Guid.NewGuid().ToString("N") + ".delete";

        Directory.Move(componentRoot, deleteRoot);
        TryDeleteDirectory(deleteRoot);
    }

    public async Task<RelayComponentInstallResult> InstallStagedUpdateAsync(
        RelayComponentKind kind,
        IProgress<RelayComponentInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _stagingGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            ValidatedStagingPackage staged =
                await LoadValidatedStagingPackageAsync(
                    kind,
                    cancellationToken).ConfigureAwait(false);

            string targetPath = GetPackagedExecutablePath(kind);

            if (!File.Exists(targetPath))
            {
                throw new FileNotFoundException(
                    "Рабочий бинарник компонента не найден; безопасный backup создать невозможно.",
                    targetPath);
            }

            VersionProbeResult currentProbe = await ProbeVersionAsync(
                targetPath,
                cancellationToken).ConfigureAwait(false);

            if (!currentProbe.Started ||
                currentProbe.TimedOut ||
                currentProbe.ExitCode != 0 ||
                string.IsNullOrWhiteSpace(currentProbe.Version))
            {
                throw new InvalidOperationException(
                    "Текущий рабочий компонент не прошёл version-check; установка заблокирована.");
            }

            if (AreEquivalentVersions(
                    currentProbe.Version,
                    staged.Manifest.NormalizedVersion))
            {
                return new RelayComponentInstallResult(
                    kind,
                    Succeeded: true,
                    RolledBack: false,
                    staged.Manifest.NormalizedVersion,
                    currentProbe.Version,
                    BackupAvailable: Directory.Exists(
                        GetComponentBackupDirectory(kind)),
                    "Подготовленная версия уже установлена.");
            }

            if (!IsUpdateAvailable(currentProbe.Version,staged.Manifest.NormalizedVersion))
                throw new InvalidOperationException("Подготовлена более старая версия. Для возврата используйте резервную копию.");
            EnsureComponentsIdle();
            ReportInstallProgress(
                progress,
                kind,
                "compatibility",
                "Проверяю совместимость с профилями и маршрутизацией Serpium...");
            try
            {
                await _compatibilityCheck(kind,staged.ExecutablePath,cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception)
            {
                return new RelayComponentInstallResult(kind,false,false,currentProbe.Version,currentProbe.Version,
                    Directory.Exists(GetComponentBackupDirectory(kind)),
                    "Обновление не прошло проверку совместимости. Сохранена рабочая версия " + currentProbe.Version + ".");
            }
            EnsureComponentsIdle();

            ReportInstallProgress(
                progress,
                kind,
                "backup",
                "Создаю проверенную резервную копию текущей версии...");

            RelayComponentBackupSnapshot backup = await CreateBackupAsync(
                kind,
                staged.Manifest.NormalizedVersion,
                cancellationToken).ConfigureAwait(false);

            if (!backup.Ready)
            {
                throw new InvalidOperationException(
                    "Rollback backup не прошёл финальную проверку: " +
                    backup.Message);
            }

            EnsureComponentsIdle();
            try
            {
                ReportInstallProgress(
                    progress,
                    kind,
                    "replace",
                    "Атомарно заменяю рабочий бинарник...");

                await ReplaceFromVerifiedSourceAsync(
                    staged.ExecutablePath,
                    targetPath,
                    staged.Manifest.ExecutableSha256,
                    cancellationToken).ConfigureAwait(false);

                await SynchronizeManagedRuntimeCopyAsync(
                    kind,
                    targetPath,
                    staged.Manifest.ExecutableSha256,
                    cancellationToken).ConfigureAwait(false);

                ReportInstallProgress(
                    progress,
                    kind,
                    "health-check",
                    "Проверяю SHA-256, version и runtime-копию...");

                await VerifyInstalledComponentAsync(
                    kind,
                    staged.Manifest.NormalizedVersion,
                    staged.Manifest.ExecutableSha256,
                    cancellationToken).ConfigureAwait(false);

                await _compatibilityCheck(kind,targetPath,cancellationToken).ConfigureAwait(false);

                TryDeleteDirectory(GetComponentStagingRoot(kind));

                return new RelayComponentInstallResult(
                    kind,
                    Succeeded: true,
                    RolledBack: false,
                    staged.Manifest.NormalizedVersion,
                    backup.PreviousVersion,
                    BackupAvailable: true,
                    "Обновление установлено, проверка запуска пройдена, rollback доступен.");
            }
            catch (Exception installError)
            {
                Exception? rollbackError = null;

                try
                {
                    ReportInstallProgress(
                        progress,
                        kind,
                        "automatic-rollback",
                        "Проверка установки не пройдена. Возвращаю предыдущую версию...");

                    ValidatedBackupPackage validatedBackup =
                        await LoadValidatedBackupPackageAsync(
                            kind,
                            CancellationToken.None).ConfigureAwait(false);

                    await RestoreBackupCoreAsync(
                        validatedBackup,
                        CancellationToken.None).ConfigureAwait(false);

                    TryDeleteDirectory(GetComponentBackupDirectory(kind));
                }
                catch (Exception ex)
                {
                    rollbackError = ex;
                }

                if (rollbackError is null)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new InvalidOperationException(
                        "Установка не завершена; автоматический rollback успешно вернул предыдущую версию. " +
                        "Причина: " + installError.Message,
                        installError);
                }

                throw new InvalidOperationException(
                    "Установка не завершена, и автоматический rollback также завершился ошибкой. " +
                    "Установка: " + installError.Message +
                    " Rollback: " + rollbackError.Message,
                    new AggregateException(installError, rollbackError));
            }
        }
        finally
        {
            _stagingGate.Release();
        }
    }

    public async Task<RelayComponentInstallResult> RollbackInstalledUpdateAsync(
        RelayComponentKind kind,
        IProgress<RelayComponentInstallProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _stagingGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        string? targetGuardPath = null;
        string? runtimeGuardPath = null;

        try
        {
            ValidatedBackupPackage backup =
                await LoadValidatedBackupPackageAsync(
                    kind,
                    cancellationToken).ConfigureAwait(false);

            string targetPath = GetPackagedExecutablePath(kind);
            string? runtimePath = GetManagedRuntimeExecutablePath(kind);

            if (!File.Exists(targetPath))
            {
                throw new FileNotFoundException(
                    "Текущий рабочий бинарник не найден; rollback guard создать невозможно.",
                    targetPath);
            }

            ReportInstallProgress(
                progress,
                kind,
                "stop",
                "Останавливаю только процессы компонента, принадлежащие Serpium...");

            await StopManagedComponentProcessesAsync(
                kind,
                cancellationToken).ConfigureAwait(false);

            targetGuardPath = BuildSiblingTemporaryPath(
                targetPath,
                "rollback-guard");

            await CopyFileAsync(
                targetPath,
                targetGuardPath,
                cancellationToken).ConfigureAwait(false);

            string targetGuardSha = await ComputeSha256Async(
                targetGuardPath,
                cancellationToken).ConfigureAwait(false);

            string? runtimeGuardSha = null;
            bool runtimeExistedBeforeRollback =
                !string.IsNullOrWhiteSpace(runtimePath) &&
                File.Exists(runtimePath);

            if (runtimeExistedBeforeRollback && runtimePath is not null)
            {
                runtimeGuardPath = BuildSiblingTemporaryPath(
                    runtimePath,
                    "rollback-guard");

                await CopyFileAsync(
                    runtimePath,
                    runtimeGuardPath,
                    cancellationToken).ConfigureAwait(false);

                runtimeGuardSha = await ComputeSha256Async(
                    runtimeGuardPath,
                    cancellationToken).ConfigureAwait(false);
            }

            try
            {
                ReportInstallProgress(
                    progress,
                    kind,
                    "rollback",
                    $"Возвращаю версию {backup.Manifest.PreviousVersion}...");

                await RestoreBackupCoreAsync(
                    backup,
                    cancellationToken).ConfigureAwait(false);

                TryDeleteDirectory(GetComponentBackupDirectory(kind));

                return new RelayComponentInstallResult(
                    kind,
                    Succeeded: true,
                    RolledBack: true,
                    backup.Manifest.PreviousVersion,
                    PreviousVersion: null,
                    BackupAvailable: false,
                    "Предыдущая версия восстановлена и повторно проверена.");
            }
            catch (Exception rollbackError)
            {
                Exception? guardRestoreError = null;

                try
                {
                    ReportInstallProgress(
                        progress,
                        kind,
                        "rollback-guard",
                        "Rollback не прошёл. Возвращаю версию, установленную до нажатия кнопки...");

                    await ReplaceFromVerifiedSourceAsync(
                        targetGuardPath,
                        targetPath,
                        targetGuardSha,
                        CancellationToken.None).ConfigureAwait(false);

                    if (runtimePath is not null)
                    {
                        if (runtimeExistedBeforeRollback &&
                            runtimeGuardPath is not null &&
                            runtimeGuardSha is not null)
                        {
                            await ReplaceFromVerifiedSourceAsync(
                                runtimeGuardPath,
                                runtimePath,
                                runtimeGuardSha,
                                CancellationToken.None).ConfigureAwait(false);
                        }
                        else
                        {
                            TryDeleteFile(runtimePath);
                        }
                    }
                }
                catch (Exception ex)
                {
                    guardRestoreError = ex;
                }

                if (guardRestoreError is null)
                {
                    throw new InvalidOperationException(
                        "Rollback не выполнен; текущая версия восстановлена rollback-guard. " +
                        "Причина: " + rollbackError.Message,
                        rollbackError);
                }

                throw new InvalidOperationException(
                    "Rollback и возврат rollback-guard завершились ошибкой. " +
                    "Rollback: " + rollbackError.Message +
                    " Guard: " + guardRestoreError.Message,
                    new AggregateException(rollbackError, guardRestoreError));
            }
        }
        finally
        {
            TryDeleteFile(targetGuardPath);
            TryDeleteFile(runtimeGuardPath);
            _stagingGate.Release();
        }
    }

    public static bool AreVersionsEquivalent(
        string? left,
        string? right) =>
        AreEquivalentVersions(left, right);

    public static bool IsUpdateAvailable(
        string? installedVersion,
        string? latestVersion)
    {
        if (!TryParseComparableVersion(
                installedVersion,
                out Version? installed) ||
            !TryParseComparableVersion(
                latestVersion,
                out Version? latest) ||
            installed is null ||
            latest is null)
        {
            return false;
        }

        return installed.CompareTo(latest) < 0;
    }

    public static bool IsInstalledVersionNewer(
        string? installedVersion,
        string? latestVersion)
    {
        if (!TryParseComparableVersion(
                installedVersion,
                out Version? installed) ||
            !TryParseComparableVersion(
                latestVersion,
                out Version? latest) ||
            installed is null ||
            latest is null)
        {
            return false;
        }

        return installed.CompareTo(latest) > 0;
    }

    public static string NormalizeVersionLabel(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return "не определена";

        Match match = FallbackVersionRegex.Match(version.Trim());

        return match.Success
            ? match.Groups[1].Value
            : version.Trim().TrimStart('v', 'V');
    }

    private async Task<RelayComponentSnapshot> InspectSingBoxAsync(
        CancellationToken cancellationToken)
    {
        string path = Path.Combine(
            _relayDirectory,
            "sing-box.exe");

        return await InspectBinaryAsync(
            RelayComponentKind.SingBox,
            "sing-box",
            path,
            managedRuntimePath: null,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<RelayComponentSnapshot> InspectXrayAsync(
        CancellationToken cancellationToken)
    {
        string packagedPath = Path.Combine(
            _relayDirectory,
            "xray.exe");

        string runtimePath = Path.Combine(
            _localAppDataDirectory,
            "SerpiumVPN",
            "Runtime",
            "key-client",
            "xray-key-client.exe");

        string primaryPath = File.Exists(packagedPath)
            ? packagedPath
            : runtimePath;

        return await InspectBinaryAsync(
            RelayComponentKind.XrayCore,
            "Xray Core",
            primaryPath,
            runtimePath,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<RelayComponentSnapshot> InspectBinaryAsync(
        RelayComponentKind kind,
        string displayName,
        string executablePath,
        string? managedRuntimePath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(executablePath))
        {
            return new RelayComponentSnapshot(
                kind,
                displayName,
                executablePath,
                ToSafePath(executablePath),
                InstalledVersion: null,
                Sha256: string.Empty,
                SizeBytes: 0,
                RelayComponentHealth.Missing,
                "Основной исполняемый файл не найден.",
                ManagedRuntimeCopyExists: false,
                ManagedRuntimeCopyMatches: false);
        }

        string sha256 = await ComputeSha256Async(
            executablePath,
            cancellationToken).ConfigureAwait(false);

        FileInfo fileInfo = new(executablePath);

        VersionProbeResult versionProbe = await ProbeVersionAsync(
            executablePath,
            cancellationToken).ConfigureAwait(false);

        bool runtimeExists =
            !string.IsNullOrWhiteSpace(managedRuntimePath) &&
            File.Exists(managedRuntimePath);

        bool runtimeMatches = false;
        string runtimeMessage = string.Empty;

        if (runtimeExists && managedRuntimePath is not null)
        {
            string runtimeSha = await ComputeSha256Async(
                managedRuntimePath,
                cancellationToken).ConfigureAwait(false);

            runtimeMatches =
                CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(sha256),
                    Convert.FromHexString(runtimeSha));

            runtimeMessage = runtimeMatches
                ? " Управляемая runtime-копия Xray совпадает с упакованным бинарником."
                : " Управляемая runtime-копия Xray отличается от упакованного бинарника.";
        }
        else if (kind == RelayComponentKind.XrayCore)
        {
            runtimeMessage =
                " Runtime-копия будет создана Serpium при запуске Xray-профиля.";
        }

        RelayComponentHealth health;
        string healthMessage;

        if (!versionProbe.Started)
        {
            health = RelayComponentHealth.Failed;
            healthMessage =
                "Не удалось запустить безопасную команду проверки версии.";
        }
        else if (versionProbe.TimedOut)
        {
            health = RelayComponentHealth.Failed;
            healthMessage =
                "Проверка версии превысила безопасный тайм-аут.";
        }
        else if (versionProbe.ExitCode != 0)
        {
            health = RelayComponentHealth.Failed;
            healthMessage =
                $"Команда версии завершилась с кодом {versionProbe.ExitCode}.";
        }
        else if (string.IsNullOrWhiteSpace(versionProbe.Version))
        {
            health = RelayComponentHealth.Warning;
            healthMessage =
                "Файл запускается, но версия не распознана.";
        }
        else if (
            kind == RelayComponentKind.XrayCore &&
            runtimeExists &&
            !runtimeMatches)
        {
            health = RelayComponentHealth.Warning;
            healthMessage =
                "Основной Xray исправен, но runtime-копия отличается.";
        }
        else
        {
            health = RelayComponentHealth.Healthy;
            healthMessage =
                "Компонент запускается и отвечает на локальную проверку версии.";
        }

        healthMessage += runtimeMessage;

        return new RelayComponentSnapshot(
            kind,
            displayName,
            executablePath,
            ToSafePath(executablePath),
            versionProbe.Version,
            sha256,
            fileInfo.Length,
            health,
            healthMessage.Trim(),
            runtimeExists,
            runtimeMatches);
    }

    private async Task<RelayComponentReleaseInfo> GetLatestReleaseAsync(
        RelayComponentKind kind,
        string apiUrl,
        string repository,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);

        timeout.CancelAfter(TimeSpan.FromSeconds(25));

        using HttpResponseMessage response =
            await SendOfficialGetAsync(apiUrl,timeout.Token).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        await using Stream stream =
            await response.Content.ReadAsStreamAsync(
                timeout.Token).ConfigureAwait(false);

        using var metadata = new MemoryStream();
        byte[] metadataBuffer = new byte[16384];
        int metadataRead;
        while ((metadataRead = await stream.ReadAsync(metadataBuffer,timeout.Token)) > 0)
        {
            if (metadata.Length + metadataRead > 4 * 1024 * 1024)
                throw new InvalidDataException("Метаданные обновления слишком велики.");
            metadata.Write(metadataBuffer,0,metadataRead);
        }
        using JsonDocument document = JsonDocument.Parse(metadata.ToArray());

        JsonElement root = document.RootElement;

        if (ReadOptionalBoolean(root, "draft") == true ||
            ReadOptionalBoolean(root, "prerelease") == true)
        {
            throw new InvalidDataException(
                "GitHub latest endpoint вернул draft или prerelease.");
        }

        string tagName = ReadRequiredString(root, "tag_name");
        string normalizedVersion = NormalizeVersionLabel(tagName);
        string releaseName =
            ReadOptionalString(root, "name") ?? tagName;
        string releasePage =
            ReadRequiredString(root, "html_url");

        DateTimeOffset? publishedAt = null;

        if (root.TryGetProperty(
                "published_at",
                out JsonElement publishedElement) &&
            publishedElement.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(
                publishedElement.GetString(),
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out DateTimeOffset parsedPublishedAt))
        {
            publishedAt = parsedPublishedAt.ToUniversalTime();
        }

        RelayComponentReleaseAsset? asset =
            SelectWindowsAmd64Asset(
                kind,
                normalizedVersion,
                repository,
                root);

        return new RelayComponentReleaseInfo(
            kind,
            tagName,
            normalizedVersion,
            releaseName,
            publishedAt,
            releasePage,
            repository,
            asset);
    }

    private static RelayComponentReleaseAsset? SelectWindowsAmd64Asset(
        RelayComponentKind kind,
        string normalizedVersion,
        string repository,
        JsonElement releaseRoot)
    {
        if (!releaseRoot.TryGetProperty(
                "assets",
                out JsonElement assets) ||
            assets.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        string expectedName = kind switch
        {
            RelayComponentKind.XrayCore =>
                "Xray-windows-64.zip",

            RelayComponentKind.SingBox =>
                $"sing-box-{normalizedVersion}-windows-amd64.zip",

            _ => throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                null)
        };

        foreach (JsonElement asset in assets.EnumerateArray())
        {
            string? name = ReadOptionalString(asset, "name");

            if (!string.Equals(
                    name,
                    expectedName,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string? state = ReadOptionalString(asset, "state");

            if (!string.Equals(
                    state,
                    "uploaded",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string downloadUrl =
                ReadRequiredString(
                    asset,
                    "browser_download_url");

            ValidateOfficialDownloadUrl(
                repository,
                downloadUrl);

            long sizeBytes = 0;

            if (asset.TryGetProperty(
                    "size",
                    out JsonElement sizeElement) &&
                sizeElement.ValueKind == JsonValueKind.Number)
            {
                sizeElement.TryGetInt64(out sizeBytes);
            }

            string digest =
                ReadOptionalString(asset, "digest")
                ?? string.Empty;

            string sha256 = NormalizeGithubDigest(digest);

            return new RelayComponentReleaseAsset(
                name!,
                downloadUrl,
                sizeBytes,
                sha256);
        }

        return null;
    }

    private static string NormalizeGithubDigest(string digest)
    {
        if (!digest.StartsWith(
                "sha256:",
                StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        string value = digest["sha256:".Length..].Trim();

        return value.Length == 64 &&
               value.All(Uri.IsHexDigit)
            ? value.ToUpperInvariant()
            : string.Empty;
    }

    private static void ValidateAsset(
        RelayComponentKind kind,
        RelayComponentReleaseInfo release,
        RelayComponentReleaseAsset asset)
    {
        string expectedRepository = kind == RelayComponentKind.SingBox ? "SagerNet/sing-box" : "XTLS/Xray-core";
        if (!string.Equals(release.Repository,expectedRepository,StringComparison.Ordinal) ||
            release.TagName.Contains('-') || release.NormalizedVersion.Contains('-'))
            throw new InvalidDataException("Разрешены только стабильные релизы официального репозитория.");
        if (asset.SizeBytes <= 0 ||
            asset.SizeBytes > MaximumArchiveBytes)
        {
            throw new InvalidDataException(
                "Размер release asset находится вне безопасного диапазона.");
        }

        string expectedName = kind switch
        {
            RelayComponentKind.XrayCore =>
                "Xray-windows-64.zip",

            RelayComponentKind.SingBox =>
                $"sing-box-{release.NormalizedVersion}-windows-amd64.zip",

            _ => throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                null)
        };

        if (!string.Equals(
                asset.Name,
                expectedName,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Имя официального Windows AMD64 asset не совпадает с ожидаемым.");
        }

        ValidateOfficialDownloadUrl(
            release.Repository,
            asset.DownloadUrl);
    }

    private static void ValidateOfficialDownloadUrl(
        string repository,
        string downloadUrl)
    {
        if (!Uri.TryCreate(
                downloadUrl,
                UriKind.Absolute,
                out Uri? uri) ||
            !string.Equals(
                uri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !uri.IsDefaultPort ||
            !string.Equals(
                uri.Host,
                "github.com",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Release asset имеет недоверенный URL.");
        }

        string expectedPrefix =
            "/" + repository + "/releases/download/";

        if (!uri.AbsolutePath.StartsWith(
                expectedPrefix,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Release asset расположен вне официального репозитория.");
        }
    }

    private async Task<string> DownloadAssetAsync(
        RelayComponentKind kind,
        RelayComponentReleaseAsset asset,
        string destinationPath,
        IProgress<RelayComponentDownloadProgress>? progress,
        CancellationToken cancellationToken)
    {
        string temporaryPath =
            destinationPath + "." +
            Guid.NewGuid().ToString("N") + ".download";

        try
        {
            using HttpResponseMessage response =
                await SendOfficialGetAsync(asset.DownloadUrl,cancellationToken).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();

            long? responseLength =
                response.Content.Headers.ContentLength;

            if (responseLength.HasValue &&
                responseLength.Value != asset.SizeBytes)
            {
                throw new InvalidDataException(
                    "Размер HTTP-ответа не совпадает с GitHub release metadata.");
            }

            string sha256;
            long received = 0;

            using (IncrementalHash hash =
                IncrementalHash.CreateHash(
                    HashAlgorithmName.SHA256))
            {
                byte[] buffer = new byte[128 * 1024];

                try
                {
                    await using (
                        Stream input =
                            await response.Content.ReadAsStreamAsync(
                                cancellationToken).ConfigureAwait(false))
                    await using (
                        FileStream output = new(
                            temporaryPath,
                            FileMode.CreateNew,
                            FileAccess.Write,
                            FileShare.None,
                            bufferSize: 128 * 1024,
                            FileOptions.Asynchronous |
                            FileOptions.SequentialScan |
                            FileOptions.WriteThrough))
                    {
                        while (true)
                        {
                            int read = await input.ReadAsync(
                                buffer.AsMemory(),
                                cancellationToken).ConfigureAwait(false);

                            if (read == 0)
                                break;

                            received += read;

                            if (received > MaximumArchiveBytes ||
                                received > asset.SizeBytes)
                            {
                                throw new InvalidDataException(
                                    "Скачанный asset превысил заявленный безопасный размер.");
                            }

                            hash.AppendData(buffer, 0, read);

                            await output.WriteAsync(
                                buffer.AsMemory(0, read),
                                cancellationToken).ConfigureAwait(false);

                            int percent = asset.SizeBytes > 0
                                ? (int)Math.Clamp(
                                    received * 100L / asset.SizeBytes,
                                    0,
                                    100)
                                : 0;

                            ReportProgress(
                                progress,
                                kind,
                                "download",
                                received,
                                asset.SizeBytes,
                                $"Скачивание: {percent}%");
                        }

                        await output.FlushAsync(
                            cancellationToken).ConfigureAwait(false);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer);
                }

                if (received != asset.SizeBytes)
                {
                    throw new InvalidDataException(
                        "Фактический размер скачанного asset не совпадает с GitHub metadata.");
                }

                sha256 =
                    Convert.ToHexString(
                        hash.GetHashAndReset());
            }

            await MoveFileWithRetryAsync(
                temporaryPath,
                destinationPath,
                cancellationToken).ConfigureAwait(false);

            return sha256;
        }
        finally
        {
            TryDeleteFile(temporaryPath);
        }
    }

    private async Task ExtractExpectedExecutableAsync(
        RelayComponentKind kind,
        string archivePath,
        string executablePath,
        CancellationToken cancellationToken)
    {
        string expectedExecutable =
            GetExpectedExecutableName(kind);

        string temporaryPath =
            executablePath + "." +
            Guid.NewGuid().ToString("N") + ".extract";

        try
        {
            await using (
                FileStream archiveStream = new(
                    archivePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 128 * 1024,
                    useAsync: true))
            using (
                ZipArchive archive = new(
                    archiveStream,
                    ZipArchiveMode.Read,
                    leaveOpen: false))
            {
                if (archive.Entries.Count == 0 ||
                    archive.Entries.Count > MaximumArchiveEntries)
                {
                    throw new InvalidDataException(
                        "ZIP содержит недопустимое количество записей.");
                }

                long totalUncompressedBytes = 0;
                int ignoredEntryCount = 0;
                List<ZipArchiveEntry> executableCandidates = new();

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    ValidateArchiveEntryPath(entry.FullName);

                    totalUncompressedBytes += entry.Length;

                    if (totalUncompressedBytes > MaximumExtractedBytes)
                    {
                        throw new InvalidDataException(
                            "Суммарный распакованный размер ZIP превышает безопасный лимит.");
                    }

                    string leafName =
                        Path.GetFileName(
                            entry.FullName.Replace(
                                '/',
                                Path.DirectorySeparatorChar));

                    if (string.IsNullOrWhiteSpace(leafName))
                        continue;

                    if (string.Equals(
                            leafName,
                            expectedExecutable,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        executableCandidates.Add(entry);
                        continue;
                    }

                    // The complete archive is already pinned by:
                    // official repository + exact asset name + GitHub SHA-256.
                    // Every other entry remains inside the ZIP and is never
                    // extracted, loaded or executed by Serpium.
                    ignoredEntryCount++;
                }

                if (executableCandidates.Count != 1)
                {
                    throw new InvalidDataException(
                        $"В ZIP ожидался ровно один {expectedExecutable}; найдено: {executableCandidates.Count}.");
                }

                if (ignoredEntryCount < 0)
                {
                    throw new InvalidDataException(
                        "Внутренняя ошибка инвентаризации ZIP.");
                }

                ZipArchiveEntry executableEntry =
                    executableCandidates[0];

                if (executableEntry.Length <= 0 ||
                    executableEntry.Length > MaximumExtractedBytes)
                {
                    throw new InvalidDataException(
                        "Размер исполняемого файла находится вне безопасного диапазона.");
                }

                await using (
                    Stream input =
                        executableEntry.Open())
                await using (
                    FileStream output = new(
                        temporaryPath,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.None,
                        bufferSize: 128 * 1024,
                        FileOptions.Asynchronous |
                        FileOptions.SequentialScan |
                        FileOptions.WriteThrough))
                {
                    await input.CopyToAsync(
                        output,
                        128 * 1024,
                        cancellationToken).ConfigureAwait(false);

                    await output.FlushAsync(
                        cancellationToken).ConfigureAwait(false);
                }
            }

            await MoveFileWithRetryAsync(
                temporaryPath,
                executablePath,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TryDeleteFile(temporaryPath);
        }
    }

    private async Task<ValidatedStagingPackage>
        LoadValidatedStagingPackageAsync(
            RelayComponentKind kind,
            CancellationToken cancellationToken)
    {
        string componentRoot = GetComponentStagingRoot(kind);

        if (!Directory.Exists(componentRoot))
            throw new DirectoryNotFoundException("Staging для компонента отсутствует.");

        string[] versionDirectories = Directory.GetDirectories(
            componentRoot,
            "*",
            SearchOption.TopDirectoryOnly);

        if (versionDirectories.Length != 1)
        {
            throw new InvalidDataException(
                "Для установки в staging должна находиться ровно одна версия.");
        }

        RelayComponentStagingSnapshot snapshot =
            await ValidateStagingDirectoryAsync(
                kind,
                versionDirectories[0],
                cancellationToken).ConfigureAwait(false);

        if (!snapshot.Ready)
        {
            throw new InvalidDataException(
                "Staging не прошёл повторную проверку: " + snapshot.Message);
        }

        string manifestPath = Path.Combine(
            versionDirectories[0],
            ManifestFileName);

        StagingManifest manifest = await ReadJsonFileAsync<StagingManifest>(
            manifestPath,
            cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Staging manifest пуст.");

        string executablePath = Path.Combine(
            versionDirectories[0],
            GetExpectedExecutableName(kind));

        return new ValidatedStagingPackage(
            versionDirectories[0],
            executablePath,
            manifest);
    }

    private async Task<RelayComponentBackupSnapshot> CreateBackupAsync(
        RelayComponentKind kind,
        string installingVersion,
        CancellationToken cancellationToken)
    {
        EnsurePrivateDirectory(_backupRoot);
        CleanupStaleBackupArtifacts(kind);

        string targetPath = GetPackagedExecutablePath(kind);
        string? runtimePath = GetManagedRuntimeExecutablePath(kind);
        string componentDirectory = GetComponentBackupDirectory(kind);
        string workDirectory = Path.Combine(
            _backupRoot,
            "." + GetComponentFolderName(kind) + "." +
            Guid.NewGuid().ToString("N") + ".tmp");
        string? oldDirectory = null;

        try
        {
            EnsurePrivateDirectory(workDirectory);

            VersionProbeResult probe = await ProbeVersionAsync(
                targetPath,
                cancellationToken).ConfigureAwait(false);

            if (!probe.Started ||
                probe.TimedOut ||
                probe.ExitCode != 0 ||
                string.IsNullOrWhiteSpace(probe.Version))
            {
                throw new InvalidOperationException(
                    "Текущий компонент не прошёл version-check перед backup.");
            }

            string executableSha = await ComputeSha256Async(
                targetPath,
                cancellationToken).ConfigureAwait(false);

            string backupExecutablePath = Path.Combine(
                workDirectory,
                GetExpectedExecutableName(kind));

            await CopyFileAsync(
                targetPath,
                backupExecutablePath,
                cancellationToken).ConfigureAwait(false);

            string copiedExecutableSha = await ComputeSha256Async(
                backupExecutablePath,
                cancellationToken).ConfigureAwait(false);

            if (!FixedHexEquals(executableSha, copiedExecutableSha))
            {
                throw new CryptographicException(
                    "SHA-256 backup-копии рабочего бинарника не совпадает с исходником.");
            }

            bool runtimeBackedUp = false;
            string runtimeSha = string.Empty;

            if (!string.IsNullOrWhiteSpace(runtimePath) &&
                File.Exists(runtimePath))
            {
                string runtimeBackupPath = Path.Combine(
                    workDirectory,
                    RuntimeBackupFileName);

                runtimeSha = await ComputeSha256Async(
                    runtimePath,
                    cancellationToken).ConfigureAwait(false);

                await CopyFileAsync(
                    runtimePath,
                    runtimeBackupPath,
                    cancellationToken).ConfigureAwait(false);

                string copiedRuntimeSha = await ComputeSha256Async(
                    runtimeBackupPath,
                    cancellationToken).ConfigureAwait(false);

                if (!FixedHexEquals(runtimeSha, copiedRuntimeSha))
                {
                    throw new CryptographicException(
                        "SHA-256 backup-копии Xray runtime не совпадает с исходником.");
                }

                runtimeBackedUp = true;
            }

            BackupManifest manifest = new()
            {
                SchemaVersion = BackupManifestSchema,
                Component = kind.ToString(),
                PreviousVersion = probe.Version,
                PreviousExecutableFileName = GetExpectedExecutableName(kind),
                PreviousExecutableSha256 = executableSha,
                PreviousExecutableSizeBytes = new FileInfo(targetPath).Length,
                RuntimeCopyBackedUp = runtimeBackedUp,
                RuntimeCopySha256 = runtimeSha,
                InstallingVersion = installingVersion,
                CreatedAtUtc = DateTimeOffset.UtcNow
            };

            string manifestPath = Path.Combine(
                workDirectory,
                BackupManifestFileName);

            await WriteJsonFileAsync(
                manifestPath,
                manifest,
                cancellationToken).ConfigureAwait(false);

            oldDirectory = componentDirectory + "." +
                Guid.NewGuid().ToString("N") + ".old";

            if (Directory.Exists(componentDirectory))
            {
                await MoveDirectoryWithRetryAsync(
                    componentDirectory,
                    oldDirectory,
                    cancellationToken).ConfigureAwait(false);
            }

            await MoveDirectoryWithRetryAsync(
                workDirectory,
                componentDirectory,
                cancellationToken).ConfigureAwait(false);

            RelayComponentBackupSnapshot snapshot =
                await ValidateBackupDirectoryAsync(
                    kind,
                    componentDirectory,
                    cancellationToken).ConfigureAwait(false);

            if (!snapshot.Ready)
            {
                TryDeleteDirectory(componentDirectory);

                if (!string.IsNullOrWhiteSpace(oldDirectory) &&
                    Directory.Exists(oldDirectory))
                {
                    await MoveDirectoryWithRetryAsync(
                        oldDirectory,
                        componentDirectory,
                        cancellationToken).ConfigureAwait(false);

                    oldDirectory = null;
                }

                throw new InvalidDataException(
                    "Финальная проверка rollback backup не пройдена: " +
                    snapshot.Message);
            }

            TryDeleteDirectory(oldDirectory);
            oldDirectory = null;
            return snapshot;
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(oldDirectory) &&
                Directory.Exists(oldDirectory) &&
                !Directory.Exists(componentDirectory))
            {
                await MoveDirectoryWithRetryAsync(
                    oldDirectory,
                    componentDirectory,
                    CancellationToken.None).ConfigureAwait(false);

                oldDirectory = null;
            }

            throw;
        }
        finally
        {
            TryDeleteDirectory(workDirectory);
        }
    }

    private async Task<ValidatedBackupPackage>
        LoadValidatedBackupPackageAsync(
            RelayComponentKind kind,
            CancellationToken cancellationToken)
    {
        string directory = GetComponentBackupDirectory(kind);

        RelayComponentBackupSnapshot snapshot =
            await ValidateBackupDirectoryAsync(
                kind,
                directory,
                cancellationToken).ConfigureAwait(false);

        if (!snapshot.Ready)
        {
            throw new InvalidDataException(
                "Rollback backup не прошёл повторную проверку: " +
                snapshot.Message);
        }

        BackupManifest manifest =
            await ReadJsonFileAsync<BackupManifest>(
                Path.Combine(directory, BackupManifestFileName),
                cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Rollback manifest пуст.");

        return new ValidatedBackupPackage(
            directory,
            Path.Combine(
                directory,
                GetExpectedExecutableName(kind)),
            manifest.RuntimeCopyBackedUp
                ? Path.Combine(directory, RuntimeBackupFileName)
                : null,
            manifest);
    }

    private async Task<RelayComponentBackupSnapshot>
        ValidateBackupDirectoryAsync(
            RelayComponentKind kind,
            string directory,
            CancellationToken cancellationToken)
    {
        if (!Directory.Exists(directory))
            return CreateEmptyBackupSnapshot(kind);

        string manifestPath = Path.Combine(
            directory,
            BackupManifestFileName);

        if (!File.Exists(manifestPath))
        {
            return InvalidBackup(
                kind,
                directory,
                "Rollback manifest отсутствует.");
        }

        BackupManifest? manifest = await ReadJsonFileAsync<BackupManifest>(
            manifestPath,
            cancellationToken).ConfigureAwait(false);

        if (manifest is null ||
            manifest.SchemaVersion != BackupManifestSchema ||
            !string.Equals(
                manifest.Component,
                kind.ToString(),
                StringComparison.Ordinal) ||
            !string.Equals(
                manifest.PreviousExecutableFileName,
                GetExpectedExecutableName(kind),
                StringComparison.OrdinalIgnoreCase))
        {
            return InvalidBackup(
                kind,
                directory,
                "Rollback manifest имеет неверную структуру.");
        }

        string executablePath = Path.Combine(
            directory,
            GetExpectedExecutableName(kind));

        if (!File.Exists(executablePath))
        {
            return InvalidBackup(
                kind,
                directory,
                "Backup рабочего бинарника отсутствует.");
        }

        string executableSha = await ComputeSha256Async(
            executablePath,
            cancellationToken).ConfigureAwait(false);

        if (!FixedHexEquals(
                executableSha,
                manifest.PreviousExecutableSha256))
        {
            return InvalidBackup(
                kind,
                directory,
                "SHA-256 backup рабочего бинарника не прошёл проверку.");
        }

        VersionProbeResult probe = await ProbeVersionAsync(
            executablePath,
            cancellationToken).ConfigureAwait(false);

        if (!probe.Started ||
            probe.TimedOut ||
            probe.ExitCode != 0 ||
            string.IsNullOrWhiteSpace(probe.Version) ||
            !AreEquivalentVersions(
                probe.Version,
                manifest.PreviousVersion))
        {
            return InvalidBackup(
                kind,
                directory,
                "Backup рабочего бинарника не прошёл version-check.");
        }

        if (manifest.RuntimeCopyBackedUp)
        {
            string runtimeBackupPath = Path.Combine(
                directory,
                RuntimeBackupFileName);

            if (!File.Exists(runtimeBackupPath))
            {
                return InvalidBackup(
                    kind,
                    directory,
                    "Backup Xray runtime отсутствует.");
            }

            string runtimeSha = await ComputeSha256Async(
                runtimeBackupPath,
                cancellationToken).ConfigureAwait(false);

            if (!FixedHexEquals(
                    runtimeSha,
                    manifest.RuntimeCopySha256))
            {
                return InvalidBackup(
                    kind,
                    directory,
                    "SHA-256 backup Xray runtime не прошёл проверку.");
            }
        }

        return new RelayComponentBackupSnapshot(
            kind,
            Exists: true,
            Ready: true,
            manifest.PreviousVersion,
            executableSha,
            ToSafePath(directory),
            manifest.CreatedAtUtc,
            manifest.RuntimeCopyBackedUp,
            "Rollback backup, SHA-256 и version подтверждены.");
    }

    private async Task RestoreBackupCoreAsync(
        ValidatedBackupPackage backup,
        CancellationToken cancellationToken)
    {
        RelayComponentKind kind = backup.Kind;
        string targetPath = GetPackagedExecutablePath(kind);

        await StopManagedComponentProcessesAsync(
            kind,
            cancellationToken).ConfigureAwait(false);

        await ReplaceFromVerifiedSourceAsync(
            backup.ExecutablePath,
            targetPath,
            backup.Manifest.PreviousExecutableSha256,
            cancellationToken).ConfigureAwait(false);

        string? runtimePath = GetManagedRuntimeExecutablePath(kind);

        if (runtimePath is not null)
        {
            if (backup.Manifest.RuntimeCopyBackedUp &&
                backup.RuntimeExecutablePath is not null)
            {
                EnsurePrivateDirectory(
                    Path.GetDirectoryName(runtimePath)
                    ?? throw new InvalidOperationException(
                        "Не удалось определить runtime-каталог Xray."));

                await ReplaceFromVerifiedSourceAsync(
                    backup.RuntimeExecutablePath,
                    runtimePath,
                    backup.Manifest.RuntimeCopySha256,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                TryDeleteFile(runtimePath);
            }
        }

        await VerifyInstalledComponentAsync(
            kind,
            backup.Manifest.PreviousVersion,
            backup.Manifest.PreviousExecutableSha256,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task SynchronizeManagedRuntimeCopyAsync(
        RelayComponentKind kind,
        string packagedPath,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        string? runtimePath = GetManagedRuntimeExecutablePath(kind);

        if (runtimePath is null || !File.Exists(runtimePath))
            return;

        await ReplaceFromVerifiedSourceAsync(
            packagedPath,
            runtimePath,
            expectedSha256,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task VerifyInstalledComponentAsync(
        RelayComponentKind kind,
        string expectedVersion,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        string targetPath = GetPackagedExecutablePath(kind);
        string actualSha = await ComputeSha256Async(
            targetPath,
            cancellationToken).ConfigureAwait(false);

        if (!FixedHexEquals(actualSha, expectedSha256))
        {
            throw new CryptographicException(
                "SHA-256 установленного рабочего бинарника не совпадает с ожидаемым.");
        }

        VersionProbeResult probe = await ProbeVersionAsync(
            targetPath,
            cancellationToken).ConfigureAwait(false);

        if (!probe.Started ||
            probe.TimedOut ||
            probe.ExitCode != 0 ||
            string.IsNullOrWhiteSpace(probe.Version) ||
            !AreEquivalentVersions(probe.Version, expectedVersion))
        {
            throw new InvalidDataException(
                "Установленный рабочий компонент не прошёл version-check.");
        }

        string? runtimePath = GetManagedRuntimeExecutablePath(kind);

        if (runtimePath is not null && File.Exists(runtimePath))
        {
            string runtimeSha = await ComputeSha256Async(
                runtimePath,
                cancellationToken).ConfigureAwait(false);

            if (!FixedHexEquals(runtimeSha, expectedSha256))
            {
                throw new CryptographicException(
                    "Управляемая runtime-копия Xray не совпадает с установленным бинарником.");
            }
        }
    }

    private async Task ReplaceFromVerifiedSourceAsync(
        string sourcePath,
        string destinationPath,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        string destinationDirectory =
            Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException(
                "Не удалось определить каталог назначения компонента.");

        Directory.CreateDirectory(destinationDirectory);

        string temporaryPath = BuildSiblingTemporaryPath(
            destinationPath,
            "install");

        try
        {
            await CopyFileAsync(
                sourcePath,
                temporaryPath,
                cancellationToken).ConfigureAwait(false);

            string temporarySha = await ComputeSha256Async(
                temporaryPath,
                cancellationToken).ConfigureAwait(false);

            if (!FixedHexEquals(temporarySha, expectedSha256))
            {
                throw new CryptographicException(
                    "SHA-256 временной install-копии не совпадает с проверенным источником.");
            }

            await ReplaceFileWithRetryAsync(
                temporaryPath,
                destinationPath,
                cancellationToken).ConfigureAwait(false);

            string installedSha = await ComputeSha256Async(
                destinationPath,
                cancellationToken).ConfigureAwait(false);

            if (!FixedHexEquals(installedSha, expectedSha256))
            {
                throw new CryptographicException(
                    "SHA-256 файла после атомарной замены не совпадает с ожидаемым.");
            }
        }
        finally
        {
            TryDeleteFile(temporaryPath);
        }
    }

    private static async Task CopyFileAsync(
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        await using FileStream input = new(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous |
            FileOptions.SequentialScan);

        await using FileStream output = new(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous |
            FileOptions.SequentialScan |
            FileOptions.WriteThrough);

        await input.CopyToAsync(
            output,
            128 * 1024,
            cancellationToken).ConfigureAwait(false);

        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private void EnsureComponentsIdle()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kind in new[] { RelayComponentKind.SingBox,RelayComponentKind.XrayCore })
        {
            paths.Add(Path.GetFullPath(GetPackagedExecutablePath(kind)));
            string? runtime = GetManagedRuntimeExecutablePath(kind);
            if (runtime is not null) paths.Add(Path.GetFullPath(runtime));
        }
        foreach (string name in paths.Select(Path.GetFileNameWithoutExtension).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase))
        foreach (Process process in Process.GetProcessesByName(name))
        {
            bool owned = false;
            using (process)
            {
                try { owned = !process.HasExited && process.MainModule?.FileName is string path && paths.Contains(Path.GetFullPath(path)); }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception)
                { throw new InvalidOperationException("Не удалось подтвердить, что компонент остановлен. Обновление отложено."); }
            }
            if (owned) throw new InvalidOperationException("Сначала отключите VPN. Рабочие компоненты сейчас используются.");
        }
    }

    private async Task<HttpResponseMessage> SendOfficialGetAsync(string url,CancellationToken token)
    {
        var uri = new Uri(url);
        for (int redirect=0;redirect<=5;redirect++)
        {
            if (uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort || !string.IsNullOrEmpty(uri.UserInfo) ||
                !(uri.Host is "api.github.com" or "github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com"))
                throw new InvalidDataException("Обновление перенаправлено на недоверенный адрес.");
            using var request = new HttpRequestMessage(HttpMethod.Get,uri);
            var response = await _httpClient.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,token).ConfigureAwait(false);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308)) return response;
            var location = response.Headers.Location;
            response.Dispose();
            if (redirect==5 || location is null) throw new InvalidDataException("Слишком много перенаправлений при загрузке обновления.");
            uri = location.IsAbsoluteUri ? location : new Uri(uri,location);
        }
        throw new InvalidDataException("Не удалось получить обновление.");
    }

    private async Task StopManagedComponentProcessesAsync(
        RelayComponentKind kind,
        CancellationToken cancellationToken)
    {
        HashSet<string> ownedPaths = new(
            StringComparer.OrdinalIgnoreCase)
        {
            Path.GetFullPath(GetPackagedExecutablePath(kind))
        };

        string? runtimePath = GetManagedRuntimeExecutablePath(kind);
        if (runtimePath is not null)
            ownedPaths.Add(Path.GetFullPath(runtimePath));

        for (int attempt = 0; attempt < 30; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool foundOwnedProcess = false;

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == Environment.ProcessId || process.HasExited)
                        continue;

                    string? processPath = process.MainModule?.FileName;

                    if (string.IsNullOrWhiteSpace(processPath) ||
                        !ownedPaths.Contains(Path.GetFullPath(processPath)))
                    {
                        continue;
                    }

                    foundOwnedProcess = true;
                    process.Kill(entireProcessTree: true);

                    using CancellationTokenSource timeout =
                        CancellationTokenSource.CreateLinkedTokenSource(
                            cancellationToken);
                    timeout.CancelAfter(TimeSpan.FromSeconds(5));

                    try
                    {
                        await process.WaitForExitAsync(timeout.Token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                        when (!cancellationToken.IsCancellationRequested)
                    {
                        // The next sweep retries the exact same owned path.
                    }
                }
                catch (InvalidOperationException)
                {
                    // Process exited between enumeration and inspection.
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Inaccessible unrelated processes are ignored. Exact
                    // component ownership is rechecked on the next sweep.
                }
                finally
                {
                    process.Dispose();
                }
            }

            if (!foundOwnedProcess)
                return;

            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        }

        throw new InvalidOperationException(
            "Serpium-owned component process did not stop within the safe timeout.");
    }

    private static string BuildSiblingTemporaryPath(
        string destinationPath,
        string purpose)
    {
        string directory = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException(
                "Не удалось определить каталог временного файла.");

        return Path.Combine(
            directory,
            "." + Path.GetFileName(destinationPath) + "." +
            purpose + "." + Guid.NewGuid().ToString("N") + ".tmp");
    }

    private static async Task<T?> ReadJsonFileAsync<T>(
        string path,
        CancellationToken cancellationToken)
    {
        byte[] bytes = await File.ReadAllBytesAsync(
            path,
            cancellationToken).ConfigureAwait(false);

        try
        {
            return JsonSerializer.Deserialize<T>(bytes, JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static async Task WriteJsonFileAsync<T>(
        string path,
        T value,
        CancellationToken cancellationToken)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(
            value,
            JsonOptions);

        try
        {
            await File.WriteAllBytesAsync(
                path,
                bytes,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<RelayComponentStagingSnapshot>
        ValidateStagingDirectoryAsync(
            RelayComponentKind kind,
            string versionDirectory,
            CancellationToken cancellationToken)
    {
        string manifestPath = Path.Combine(
            versionDirectory,
            ManifestFileName);

        string archivePath = Path.Combine(
            versionDirectory,
            ArchiveFileName);

        if (!File.Exists(manifestPath) ||
            !File.Exists(archivePath))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "Staging неполон: отсутствует manifest или архив.");
        }

        byte[] manifestBytes =
            await File.ReadAllBytesAsync(
                manifestPath,
                cancellationToken).ConfigureAwait(false);

        StagingManifest? manifest;

        try
        {
            manifest = JsonSerializer.Deserialize<StagingManifest>(
                manifestBytes,
                JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
        }

        if (manifest is null ||
            manifest.SchemaVersion != StagingManifestSchema ||
            !string.Equals(
                manifest.Component,
                kind.ToString(),
                StringComparison.Ordinal))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "Staging manifest имеет неверную структуру.");
        }

        string expectedExecutable =
            GetExpectedExecutableName(kind);

        if (!string.Equals(
                manifest.ExecutableFileName,
                expectedExecutable,
                StringComparison.OrdinalIgnoreCase))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "Staging manifest ссылается на неожиданный исполняемый файл.");
        }

        string executablePath = Path.Combine(
            versionDirectory,
            expectedExecutable);

        if (!File.Exists(executablePath))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "Подготовленный исполняемый файл отсутствует.");
        }

        string archiveSha = await ComputeSha256Async(
            archivePath,
            cancellationToken).ConfigureAwait(false);

        string executableSha = await ComputeSha256Async(
            executablePath,
            cancellationToken).ConfigureAwait(false);

        if (!FixedHexEquals(
                archiveSha,
                manifest.ArchiveSha256) ||
            !FixedHexEquals(
                archiveSha,
                manifest.ExpectedArchiveSha256))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "SHA-256 подготовленного архива не прошёл проверку.");
        }

        if (!FixedHexEquals(
                executableSha,
                manifest.ExecutableSha256))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "SHA-256 подготовленного исполняемого файла не прошёл проверку.");
        }

        if (!_verifiedDownloads.TryGetValue(kind,out var verified) ||
            !FixedHexEquals(archiveSha,verified.Archive) || !FixedHexEquals(executableSha,verified.Executable))
            return InvalidStaging(kind,versionDirectory,"Файлы не подтверждены текущей проверкой официальной загрузки. Повторите подготовку обновления.");

        VersionProbeResult probe = await ProbeVersionAsync(
            executablePath,
            cancellationToken).ConfigureAwait(false);

        if (!probe.Started ||
            probe.TimedOut ||
            probe.ExitCode != 0 ||
            string.IsNullOrWhiteSpace(probe.Version) ||
            !AreEquivalentVersions(
                probe.Version,
                manifest.NormalizedVersion))
        {
            return InvalidStaging(
                kind,
                versionDirectory,
                "Подготовленный компонент не прошёл повторную проверку version.");
        }

        return new RelayComponentStagingSnapshot(
            kind,
            Exists: true,
            Ready: true,
            manifest.TagName,
            manifest.NormalizedVersion,
            ToSafePath(versionDirectory),
            archiveSha,
            executableSha,
            manifest.StagedAtUtc,
            "Архив, SHA-256, структура ZIP и версия компонента подтверждены.");
    }

    private RelayComponentStagingSnapshot InvalidStaging(
        RelayComponentKind kind,
        string directory,
        string message)
    {
        return new RelayComponentStagingSnapshot(
            kind,
            Exists: true,
            Ready: false,
            TagName: null,
            NormalizedVersion: null,
            ToSafePath(directory),
            ArchiveSha256: null,
            ExecutableSha256: null,
            StagedAtUtc: null,
            message);
    }

    private RelayComponentBackupSnapshot InvalidBackup(
        RelayComponentKind kind,
        string directory,
        string message)
    {
        return new RelayComponentBackupSnapshot(
            kind,
            Exists: true,
            Ready: false,
            PreviousVersion: null,
            PreviousExecutableSha256: null,
            ToSafePath(directory),
            CreatedAtUtc: null,
            RuntimeCopyBackedUp: false,
            message);
    }

    private RelayComponentBackupSnapshot CreateEmptyBackupSnapshot(
        RelayComponentKind kind)
    {
        return new RelayComponentBackupSnapshot(
            kind,
            Exists: false,
            Ready: false,
            PreviousVersion: null,
            PreviousExecutableSha256: null,
            ToSafePath(GetComponentBackupDirectory(kind)),
            CreatedAtUtc: null,
            RuntimeCopyBackedUp: false,
            "Rollback backup ещё не создан.");
    }

    private RelayComponentStagingSnapshot CreateEmptyStagingSnapshot(
        RelayComponentKind kind)
    {
        return new RelayComponentStagingSnapshot(
            kind,
            Exists: false,
            Ready: false,
            TagName: null,
            NormalizedVersion: null,
            ToSafePath(GetComponentStagingRoot(kind)),
            ArchiveSha256: null,
            ExecutableSha256: null,
            StagedAtUtc: null,
            "Обновление ещё не загружено.");
    }

    private async Task<VersionProbeResult> ProbeVersionAsync(
        string executablePath,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = executablePath,
            WorkingDirectory =
                Path.GetDirectoryName(executablePath)
                ?? _baseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        startInfo.ArgumentList.Add("version");

        using Process process = new()
        {
            StartInfo = startInfo
        };

        try
        {
            if (!process.Start())
            {
                return new VersionProbeResult(
                    Started: false,
                    TimedOut: false,
                    ExitCode: -1,
                    Version: null);
            }

            Task<string> stdoutTask =
                process.StandardOutput.ReadToEndAsync();

            Task<string> stderrTask =
                process.StandardError.ReadToEndAsync();

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);

            timeout.CancelAfter(TimeSpan.FromSeconds(8));

            try
            {
                await process.WaitForExitAsync(
                    timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (!cancellationToken.IsCancellationRequested)
            {
                TryKill(process);

                return new VersionProbeResult(
                    Started: true,
                    TimedOut: true,
                    ExitCode: -1,
                    Version: null);
            }

            string stdout =
                await stdoutTask.ConfigureAwait(false);

            string stderr =
                await stderrTask.ConfigureAwait(false);

            string output =
                stdout +
                Environment.NewLine +
                stderr;

            string? version = ParseVersion(output);

            return new VersionProbeResult(
                Started: true,
                TimedOut: false,
                process.ExitCode,
                version);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        catch
        {
            TryKill(process);

            return new VersionProbeResult(
                Started: false,
                TimedOut: false,
                ExitCode: -1,
                Version: null);
        }
    }

    private static async Task<string> ComputeSha256Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            useAsync: true);

        using SHA256 sha256 = SHA256.Create();

        byte[] digest = await sha256.ComputeHashAsync(
            stream,
            cancellationToken).ConfigureAwait(false);

        return Convert.ToHexString(digest);
    }

    private string GetComponentStagingRoot(
        RelayComponentKind kind)
    {
        return Path.Combine(
            _stagingRoot,
            GetComponentFolderName(kind));
    }

    private string GetComponentBackupDirectory(
        RelayComponentKind kind)
    {
        return Path.Combine(
            _backupRoot,
            GetComponentFolderName(kind));
    }

    private string GetPackagedExecutablePath(
        RelayComponentKind kind)
    {
        return Path.Combine(
            _relayDirectory,
            GetExpectedExecutableName(kind));
    }

    private string? GetManagedRuntimeExecutablePath(
        RelayComponentKind kind)
    {
        return kind == RelayComponentKind.XrayCore
            ? Path.Combine(
                _localAppDataDirectory,
                "SerpiumVPN",
                "Runtime",
                "key-client",
                "xray-key-client.exe")
            : null;
    }

    private static string GetComponentFolderName(
        RelayComponentKind kind)
    {
        return kind switch
        {
            RelayComponentKind.SingBox => "sing-box",
            RelayComponentKind.XrayCore => "xray-core",
            _ => throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                null)
        };
    }

    private static string GetExpectedExecutableName(
        RelayComponentKind kind)
    {
        return kind switch
        {
            RelayComponentKind.SingBox => "sing-box.exe",
            RelayComponentKind.XrayCore => "xray.exe",
            _ => throw new ArgumentOutOfRangeException(
                nameof(kind),
                kind,
                null)
        };
    }

    private void EnsurePrivateDirectory(string path)
    {
        Directory.CreateDirectory(path);

        SecurityIdentifier currentUser =
            WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "Не удалось определить SID текущего пользователя.");

        SecurityIdentifier system = new(
            WellKnownSidType.LocalSystemSid,
            domainSid: null);

        SecurityIdentifier administrators = new(
            WellKnownSidType.BuiltinAdministratorsSid,
            domainSid: null);

        DirectorySecurity security = new();

        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);

        security.SetOwner(currentUser);

        InheritanceFlags inheritance =
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit;

        foreach (SecurityIdentifier sid in new[]
        {
            currentUser,
            system,
            administrators
        })
        {
            security.AddAccessRule(
                new FileSystemAccessRule(
                    sid,
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));
        }

        new DirectoryInfo(path).SetAccessControl(security);
    }

    private string ToSafePath(string path)
    {
        string fullPath = Path.GetFullPath(path);

        if (IsWithin(fullPath, _baseDirectory))
        {
            return Path.Combine(
                "<APP>",
                Path.GetRelativePath(
                    _baseDirectory,
                    fullPath));
        }

        if (!string.IsNullOrWhiteSpace(
                _localAppDataDirectory) &&
            IsWithin(
                fullPath,
                _localAppDataDirectory))
        {
            return Path.Combine(
                "%LOCALAPPDATA%",
                Path.GetRelativePath(
                    _localAppDataDirectory,
                    fullPath));
        }

        return Path.GetFileName(fullPath);
    }

    private static bool IsWithin(
        string path,
        string root)
    {
        string normalizedRoot = Path.GetFullPath(root)
            .TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar);

        string normalizedPath = Path.GetFullPath(path);

        return normalizedPath.Equals(
                   normalizedRoot,
                   StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.StartsWith(
                   normalizedRoot +
                   Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateArchiveEntryPath(
        string entryPath)
    {
        if (string.IsNullOrWhiteSpace(entryPath))
            return;

        string normalized = entryPath.Replace('\\', '/');

        if (normalized.StartsWith(
                "/",
                StringComparison.Ordinal) ||
            normalized.Contains(
                "../",
                StringComparison.Ordinal) ||
            normalized.Contains(
                ":",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "ZIP содержит небезопасный путь.");
        }
    }

    private static bool FixedHexEquals(
        string left,
        string right)
    {
        try
        {
            byte[] leftBytes =
                Convert.FromHexString(left);

            byte[] rightBytes =
                Convert.FromHexString(right);

            try
            {
                return CryptographicOperations.FixedTimeEquals(
                    leftBytes,
                    rightBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(leftBytes);
                CryptographicOperations.ZeroMemory(rightBytes);
            }
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool AreEquivalentVersions(
        string? left,
        string? right)
    {
        if (TryParseComparableVersion(
                left,
                out Version? leftVersion) &&
            TryParseComparableVersion(
                right,
                out Version? rightVersion) &&
            leftVersion is not null &&
            rightVersion is not null)
        {
            return leftVersion.Equals(rightVersion);
        }

        return string.Equals(
            NormalizeVersionLabel(left),
            NormalizeVersionLabel(right),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string? ParseVersion(string output)
    {
        Match productMatch =
            ProductVersionRegex.Match(output);

        if (productMatch.Success)
            return productMatch.Groups[1].Value;

        Match fallbackMatch =
            FallbackVersionRegex.Match(output);

        return fallbackMatch.Success
            ? fallbackMatch.Groups[1].Value
            : null;
    }

    private static bool TryParseComparableVersion(
        string? value,
        out Version? version)
    {
        version = null;

        string normalized =
            NormalizeVersionLabel(value);

        Match numericMatch = Regex.Match(
            normalized,
            @"^(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?",
            RegexOptions.CultureInvariant);

        if (!numericMatch.Success)
            return false;

        int[] parts = new int[4];

        for (int index = 1; index <= 4; index++)
        {
            if (numericMatch.Groups[index].Success &&
                !int.TryParse(
                    numericMatch.Groups[index].Value,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out parts[index - 1]))
            {
                return false;
            }
        }

        version = new Version(
            parts[0],
            parts[1],
            parts[2],
            parts[3]);

        return true;
    }

    private static string SanitizePathSegment(string value)
    {
        string normalized =
            NormalizeVersionLabel(value);

        char[] invalid =
            Path.GetInvalidFileNameChars();

        string sanitized = new(
            normalized
                .Select(character =>
                    invalid.Contains(character)
                        ? '_'
                        : character)
                .ToArray());

        if (string.IsNullOrWhiteSpace(sanitized))
        {
            throw new InvalidDataException(
                "Версия не может быть использована как staging path.");
        }

        return sanitized;
    }

    private static string ReadRequiredString(
        JsonElement element,
        string name)
    {
        string? value =
            ReadOptionalString(element, name);

        return !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException(
                $"GitHub release не содержит обязательное поле {name}.");
    }

    private static string? ReadOptionalString(
        JsonElement element,
        string name)
    {
        return element.TryGetProperty(
                   name,
                   out JsonElement property) &&
               property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

    private static bool? ReadOptionalBoolean(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out JsonElement property))
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static void ReportProgress(
        IProgress<RelayComponentDownloadProgress>? progress,
        RelayComponentKind kind,
        string stage,
        long bytesReceived,
        long? totalBytes,
        string message)
    {
        if (progress is null)
            return;

        int percent =
            totalBytes.GetValueOrDefault() > 0
                ? (int)Math.Clamp(
                    bytesReceived * 100L /
                    totalBytes.GetValueOrDefault(),
                    0,
                    100)
                : 0;

        progress.Report(
            new RelayComponentDownloadProgress(
                kind,
                stage,
                bytesReceived,
                totalBytes,
                percent,
                message));
    }

    private static async Task MoveFileWithRetryAsync(
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (int attempt = 1; attempt <= 12; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                File.Move(
                    sourcePath,
                    destinationPath,
                    overwrite: true);

                return;
            }
            catch (IOException ex)
            {
                lastError = ex;
            }
            catch (UnauthorizedAccessException ex)
            {
                lastError = ex;
            }

            await Task.Delay(
                TimeSpan.FromMilliseconds(
                    Math.Min(120 * attempt, 900)),
                cancellationToken).ConfigureAwait(false);
        }

        throw new IOException(
            "Не удалось завершить безопасное перемещение файла после закрытия потоков. " +
            "Возможна кратковременная блокировка Защитником Windows.",
            lastError);
    }

    private static async Task ReplaceFileWithRetryAsync(
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (int attempt = 1; attempt <= 16; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                if (File.Exists(destinationPath))
                {
                    File.SetAttributes(
                        destinationPath,
                        FileAttributes.Normal);

                    File.Replace(
                        sourcePath,
                        destinationPath,
                        destinationBackupFileName: null,
                        ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(sourcePath, destinationPath);
                }

                return;
            }
            catch (IOException ex)
            {
                lastError = ex;
            }
            catch (UnauthorizedAccessException ex)
            {
                lastError = ex;
            }
            catch (PlatformNotSupportedException ex)
            {
                lastError = ex;

                try
                {
                    File.Move(
                        sourcePath,
                        destinationPath,
                        overwrite: true);
                    return;
                }
                catch (Exception fallbackEx)
                {
                    lastError = new AggregateException(ex, fallbackEx);
                }
            }

            await Task.Delay(
                TimeSpan.FromMilliseconds(
                    Math.Min(140 * attempt, 1100)),
                cancellationToken).ConfigureAwait(false);
        }

        throw new IOException(
            "Не удалось атомарно заменить компонент. " +
            "Файл может кратковременно проверяться Защитником Windows.",
            lastError);
    }

    private static async Task MoveDirectoryWithRetryAsync(
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (int attempt = 1; attempt <= 12; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                Directory.Move(
                    sourcePath,
                    destinationPath);

                return;
            }
            catch (IOException ex)
            {
                lastError = ex;
            }
            catch (UnauthorizedAccessException ex)
            {
                lastError = ex;
            }

            await Task.Delay(
                TimeSpan.FromMilliseconds(
                    Math.Min(150 * attempt, 1000)),
                cancellationToken).ConfigureAwait(false);
        }

        throw new IOException(
            "Не удалось опубликовать staging после закрытия файлов. " +
            "Возможна кратковременная блокировка антивирусом.",
            lastError);
    }

    private void CleanupStaleStagingArtifacts(
        RelayComponentKind kind)
    {
        if (!Directory.Exists(_stagingRoot))
            return;

        string componentName =
            GetComponentFolderName(kind);

        string[] patterns =
        {
            "." + componentName + ".*.tmp",
            componentName + ".*.old",
            componentName + ".*.delete"
        };

        foreach (string pattern in patterns)
        {
            foreach (string directory in Directory.EnumerateDirectories(
                _stagingRoot,
                pattern,
                SearchOption.TopDirectoryOnly))
            {
                TryDeleteDirectory(directory);
            }
        }
    }

    private void CleanupStaleBackupArtifacts(
        RelayComponentKind kind)
    {
        if (!Directory.Exists(_backupRoot))
            return;

        string componentName = GetComponentFolderName(kind);
        string[] patterns =
        {
            "." + componentName + ".*.tmp",
            componentName + ".*.old",
            componentName + ".*.delete"
        };

        foreach (string pattern in patterns)
        {
            foreach (string directory in Directory.EnumerateDirectories(
                _backupRoot,
                pattern,
                SearchOption.TopDirectoryOnly))
            {
                TryDeleteDirectory(directory);
            }
        }
    }

    private static void ReportInstallProgress(
        IProgress<RelayComponentInstallProgress>? progress,
        RelayComponentKind kind,
        string stage,
        string message)
    {
        progress?.Report(
            new RelayComponentInstallProgress(
                kind,
                stage,
                message));
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Best effort. The process was started only for version probing.
        }
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        try
        {
            if (File.Exists(path))
            {
                File.SetAttributes(
                    path,
                    FileAttributes.Normal);

                File.Delete(path);
            }
        }
        catch
        {
            // Cleanup is best effort. Final validation never trusts leftovers.
        }
    }

    private static void TryDeleteDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        try
        {
            if (!Directory.Exists(path))
                return;

            foreach (string file in Directory.EnumerateFiles(
                path,
                "*",
                SearchOption.AllDirectories))
            {
                try
                {
                    File.SetAttributes(
                        file,
                        FileAttributes.Normal);
                }
                catch
                {
                }
            }

            Directory.Delete(
                path,
                recursive: true);
        }
        catch
        {
            // Cleanup is best effort. The next operation can remove leftovers.
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _stagingGate.Dispose();
        _httpClient.Dispose();
    }

    private sealed record ValidatedStagingPackage(
        string DirectoryPath,
        string ExecutablePath,
        StagingManifest Manifest);

    private sealed record ValidatedBackupPackage(
        string DirectoryPath,
        string ExecutablePath,
        string? RuntimeExecutablePath,
        BackupManifest Manifest)
    {
        public RelayComponentKind Kind =>
            Enum.Parse<RelayComponentKind>(Manifest.Component);
    }

    private sealed record VersionProbeResult(
        bool Started,
        bool TimedOut,
        int ExitCode,
        string? Version);

    private sealed class StagingManifest
    {
        public int SchemaVersion { get; set; }
        public string Component { get; set; } = string.Empty;
        public string Repository { get; set; } = string.Empty;
        public string TagName { get; set; } = string.Empty;
        public string NormalizedVersion { get; set; } = string.Empty;
        public string ReleasePageUrl { get; set; } = string.Empty;
        public string AssetName { get; set; } = string.Empty;
        public string AssetDownloadUrl { get; set; } = string.Empty;
        public string ExpectedArchiveSha256 { get; set; } = string.Empty;
        public string ArchiveSha256 { get; set; } = string.Empty;
        public string ExecutableFileName { get; set; } = string.Empty;
        public string ExecutableSha256 { get; set; } = string.Empty;
        public long ArchiveSizeBytes { get; set; }
        public long ExecutableSizeBytes { get; set; }
        public DateTimeOffset StagedAtUtc { get; set; }
    }


    private sealed class BackupManifest
    {
        public int SchemaVersion { get; set; }
        public string Component { get; set; } = string.Empty;
        public string PreviousVersion { get; set; } = string.Empty;
        public string PreviousExecutableFileName { get; set; } = string.Empty;
        public string PreviousExecutableSha256 { get; set; } = string.Empty;
        public long PreviousExecutableSizeBytes { get; set; }
        public bool RuntimeCopyBackedUp { get; set; }
        public string RuntimeCopySha256 { get; set; } = string.Empty;
        public string InstallingVersion { get; set; } = string.Empty;
        public DateTimeOffset CreatedAtUtc { get; set; }
    }
}
