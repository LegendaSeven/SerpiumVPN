using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN
{
    public sealed class AppUpdateManager
    {
        private const string LatestReleaseApiUrl = "https://api.github.com/repos/LegendaSeven/SerpiumVPN/releases/latest";
        private const string UpdaterExeName = "SerpiumUpdater.exe";

        private readonly HttpClient _httpClient;
        private PendingAppUpdate? _pendingUpdate;

        public AppUpdateManager()
        {
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("SerpiumVPN-Updater");
        }

        public string CurrentVersion =>
            Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ??
            Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ??
            "0.0.0";

        public async Task<AppUpdateCheckResult> CheckDownloadAndApplyAsync(
            IProgress<int>? downloadProgress,
            CancellationToken cancellationToken = default)
        {
            GithubReleaseInfo release = await GetLatestReleaseAsync(cancellationToken);
            GithubUpdateManifest manifest = await ResolveManifestAsync(release, cancellationToken);

            if (!IsNewerVersion(manifest.Version, CurrentVersion))
                return AppUpdateCheckResult.NoUpdates(CurrentVersion);

            string archivePath = Path.Combine(
                Path.GetTempPath(),
                $"SerpiumVPN-{manifest.Version}-{Guid.NewGuid():N}.zip"
            );

            await DownloadFileAsync(manifest.ZipUrl, archivePath, downloadProgress, cancellationToken);

            if (!string.IsNullOrWhiteSpace(manifest.Sha256))
                VerifySha256(archivePath, manifest.Sha256);

            _pendingUpdate = new PendingAppUpdate(manifest.Version, archivePath);
            return AppUpdateCheckResult.ReadyToRestart(manifest.Version);
        }

        public void RestartAndApply()
        {
            if (_pendingUpdate is null)
                throw new InvalidOperationException("Обновление скачано, но путь к архиву не сохранён.");

            string baseDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
            string updaterPath = Path.Combine(baseDir, UpdaterExeName);
            string exePath = Environment.ProcessPath ?? Path.Combine(baseDir, "SerpiumVPN.exe");

            if (!File.Exists(updaterPath))
                throw new FileNotFoundException($"SerpiumUpdater.exe не найден: {updaterPath}");

            string updaterRunPath = Path.Combine(
                Path.GetTempPath(),
                $"SerpiumUpdater_{Guid.NewGuid():N}.exe"
            );

            File.Copy(updaterPath, updaterRunPath, overwrite: true);

            int currentPid = Environment.ProcessId;
            string bootstrapLogPath = Path.Combine(Path.GetTempPath(), "SerpiumUpdater_bootstrap.log");

            File.WriteAllText(
                bootstrapLogPath,
                $"{DateTime.Now:O} Starting updater{Environment.NewLine}" +
                $"Updater: {updaterRunPath}{Environment.NewLine}" +
                $"PID: {currentPid}{Environment.NewLine}" +
                $"Target: {baseDir}{Environment.NewLine}" +
                $"ZIP: {_pendingUpdate.ArchivePath}{Environment.NewLine}" +
                $"EXE: {exePath}{Environment.NewLine}"
            );

            ProcessStartInfo startInfo = new()
            {
                FileName = updaterRunPath,
                UseShellExecute = false,
                WorkingDirectory = Path.GetTempPath(),
                CreateNoWindow = true
            };

            startInfo.ArgumentList.Add("--pid");
            startInfo.ArgumentList.Add(currentPid.ToString());
            startInfo.ArgumentList.Add("--target");
            startInfo.ArgumentList.Add(baseDir);
            startInfo.ArgumentList.Add("--zip");
            startInfo.ArgumentList.Add(_pendingUpdate.ArchivePath);
            startInfo.ArgumentList.Add("--exe");
            startInfo.ArgumentList.Add(exePath);

            File.AppendAllText(
                bootstrapLogPath,
                $"{DateTime.Now:O} Starting Process.Start with ArgumentList{Environment.NewLine}"
            );

            Process? updaterProcess = Process.Start(startInfo);
            if (updaterProcess is null)
                throw new InvalidOperationException("Не удалось запустить SerpiumUpdater.exe.");

            File.AppendAllText(
                bootstrapLogPath,
                $"{DateTime.Now:O} Updater started, PID: {updaterProcess.Id}{Environment.NewLine}"
            );

            Thread.Sleep(350);

            if (updaterProcess.HasExited)
            {
                throw new InvalidOperationException(
                    $"SerpiumUpdater завершился сразу после запуска. Код: {updaterProcess.ExitCode}. " +
                    $"Проверьте лог: {Path.Combine(Path.GetTempPath(), "SerpiumUpdater_error.log")}"
                );
            }

            System.Windows.Application.Current.Shutdown();
        }


        private async Task<GithubReleaseInfo> GetLatestReleaseAsync(CancellationToken cancellationToken)
        {
            using HttpResponseMessage response = await _httpClient.GetAsync(LatestReleaseApiUrl, cancellationToken);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException(
                    "GitHub не вернул последний релиз. Проверьте, что репозиторий LegendaSeven/SerpiumVPN публичный " +
                    "и в нём опубликован хотя бы один Release с файлами update.json и SerpiumVPN-*.zip."
                );
            }

            response.EnsureSuccessStatusCode();

            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            JsonElement root = document.RootElement;

            string tagName = root.GetProperty("tag_name").GetString() ?? "";
            string body = root.TryGetProperty("body", out JsonElement bodyElement) ? bodyElement.GetString() ?? "" : "";
            JsonElement assetsElement = root.GetProperty("assets");
            List<GithubReleaseAsset> assets = new List<GithubReleaseAsset>();

            foreach (JsonElement asset in assetsElement.EnumerateArray())
            {
                assets.Add(new GithubReleaseAsset(
                    asset.GetProperty("name").GetString() ?? "",
                    asset.GetProperty("browser_download_url").GetString() ?? ""
                ));
            }

            return new GithubReleaseInfo(NormalizeVersion(tagName), body, assets);
        }

        private async Task<GithubUpdateManifest> ResolveManifestAsync(
            GithubReleaseInfo release,
            CancellationToken cancellationToken)
        {
            GithubReleaseAsset? manifestAsset = release.FindAsset("update.json");
            if (manifestAsset != null)
            {
                string json = await GetStringOrExplain404Async(
                    manifestAsset.DownloadUrl,
                    "update.json найден в Release, но GitHub не дал его скачать. Перезагрузите asset update.json в релиз."
                );
                GithubUpdateManifest? manifest = JsonSerializer.Deserialize<GithubUpdateManifest>(
                    json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                if (manifest != null && !string.IsNullOrWhiteSpace(manifest.ZipUrl))
                    return manifest;
            }

            GithubReleaseAsset? zipAsset = release.Assets.FirstOrDefault(asset =>
                asset.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                asset.Name.Contains("SerpiumVPN", StringComparison.OrdinalIgnoreCase)
            );

            if (zipAsset == null)
                throw new InvalidOperationException("В последнем GitHub Release не найден архив обновления SerpiumVPN-*.zip.");

            return new GithubUpdateManifest
            {
                Version = release.Version,
                ZipUrl = zipAsset.DownloadUrl,
                Notes = release.Notes
            };
        }

        private async Task DownloadFileAsync(
            string url,
            string destinationPath,
            IProgress<int>? progress,
            CancellationToken cancellationToken)
        {
            using HttpResponseMessage response = await _httpClient.GetAsync(
                url,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken
            );

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException(
                    "Архив обновления не найден на GitHub: " + url + "\n\n" +
                    "Проверьте, что в Release загружен файл с точно таким же именем, как указано в update.json."
                );
            }

            response.EnsureSuccessStatusCode();

            long? totalBytes = response.Content.Headers.ContentLength;
            long downloadedBytes = 0;

            await using Stream source = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using FileStream destination = File.Create(destinationPath);

            byte[] buffer = new byte[128 * 1024];
            while (true)
            {
                int read = await source.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                    break;

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                downloadedBytes += read;

                if (totalBytes.HasValue && totalBytes.Value > 0)
                    progress?.Report((int)(downloadedBytes * 100 / totalBytes.Value));
            }

            progress?.Report(100);
        }

        private static void VerifySha256(string filePath, string expectedHash)
        {
            using FileStream stream = File.OpenRead(filePath);
            byte[] hashBytes = SHA256.HashData(stream);
            string actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();

            if (!string.Equals(actualHash, expectedHash.Trim().ToLowerInvariant(), StringComparison.Ordinal))
                throw new InvalidOperationException("Хэш скачанного обновления не совпал. Установка отменена.");
        }

        private static bool IsNewerVersion(string candidate, string current)
        {
            if (!Version.TryParse(NormalizeVersion(candidate), out Version? candidateVersion))
                return false;

            if (!Version.TryParse(NormalizeVersion(current), out Version? currentVersion))
                return true;

            return candidateVersion > currentVersion;
        }

        private static string NormalizeVersion(string value)
        {
            string normalized = value.Trim();
            if (normalized.StartsWith("v", StringComparison.OrdinalIgnoreCase))
                normalized = normalized[1..];

            int suffixIndex = normalized.IndexOf('-', StringComparison.Ordinal);
            if (suffixIndex >= 0)
                normalized = normalized[..suffixIndex];

            int metadataIndex = normalized.IndexOf('+', StringComparison.Ordinal);
            if (metadataIndex >= 0)
                normalized = normalized[..metadataIndex];

            return normalized;
        }

        private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

        private async Task<string> GetStringOrExplain404Async(string url, string notFoundMessage)
        {
            using HttpResponseMessage response = await _httpClient.GetAsync(url);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                throw new InvalidOperationException(notFoundMessage + "\n\nURL: " + url);

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
    }

    public sealed record AppUpdateCheckResult(
        AppUpdateCheckStatus Status,
        string Version,
        string Details = "")
    {
        public static AppUpdateCheckResult NoUpdates(string version) =>
            new(AppUpdateCheckStatus.NoUpdates, version);

        public static AppUpdateCheckResult ReadyToRestart(string version) =>
            new(AppUpdateCheckStatus.ReadyToRestart, version);
    }

    public enum AppUpdateCheckStatus
    {
        NoUpdates,
        ReadyToRestart
    }

    public sealed class GithubUpdateManifest
    {
        public string Version { get; set; } = "";
        public string ZipUrl { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    internal sealed record GithubReleaseInfo(
        string Version,
        string Notes,
        List<GithubReleaseAsset> Assets)
    {
        public GithubReleaseAsset? FindAsset(string name) =>
            Assets.FirstOrDefault(asset => string.Equals(asset.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    internal sealed record GithubReleaseAsset(string Name, string DownloadUrl);

    internal sealed record PendingAppUpdate(string Version, string ArchivePath);
}
