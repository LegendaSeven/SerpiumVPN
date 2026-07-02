using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN
{
    public sealed class VendorUpdateManager
    {
        private const string ZapretRepo = "Flowseal/zapret-discord-youtube";
        private const string TgWsRepo = "Flowseal/tg-ws-proxy";

        private readonly string _basePath = AppDomain.CurrentDomain.BaseDirectory;
        private readonly string _binFilesPath;
        private readonly string _metadataPath;

        public VendorUpdateManager()
        {
            _binFilesPath = Path.Combine(_basePath, "bin_files");
            _metadataPath = Path.Combine(_binFilesPath, "vendor_versions.json");
        }

        public async Task<VendorUpdateSummary> CheckAndUpdateAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        {
            Directory.CreateDirectory(_binFilesPath);

            VendorVersionMetadata metadata = LoadMetadata();
            List<VendorUpdateItem> items = new List<VendorUpdateItem>();

            using HttpClient client = CreateHttpClient();

            GitHubRelease zapretRelease = await GetLatestReleaseAsync(client, ZapretRepo, cancellationToken);
            bool zapretUpdated = false;
            List<string> skippedFiles = new List<string>();

            if (!string.Equals(metadata.ZapretTag, zapretRelease.TagName, StringComparison.OrdinalIgnoreCase))
            {
                progress?.Report($"Обновляем zapret до {zapretRelease.TagName}...");
                GitHubAsset asset = SelectZapretAsset(zapretRelease);
                IReadOnlyList<string> currentSkippedFiles = await UpdateZapretAsync(client, asset, cancellationToken);
                skippedFiles.AddRange(currentSkippedFiles);

                if (currentSkippedFiles.Count == 0)
                {
                    metadata.ZapretTag = zapretRelease.TagName;
                    metadata.ZapretAssetName = asset.Name;
                }

                zapretUpdated = true;
            }

            items.Add(new VendorUpdateItem("zapret-discord-youtube", zapretRelease.TagName, zapretUpdated));

            GitHubRelease tgRelease = await GetLatestReleaseAsync(client, TgWsRepo, cancellationToken);
            bool tgUpdated = false;

            if (!string.Equals(metadata.TgWsTag, tgRelease.TagName, StringComparison.OrdinalIgnoreCase))
            {
                progress?.Report($"Обновляем TG WS Proxy до {tgRelease.TagName}...");
                GitHubAsset asset = SelectTgWsAsset(tgRelease);
                IReadOnlyList<string> currentSkippedFiles = await UpdateTgWsAsync(client, asset, cancellationToken);
                skippedFiles.AddRange(currentSkippedFiles);

                if (currentSkippedFiles.Count == 0)
                {
                    metadata.TgWsTag = tgRelease.TagName;
                    metadata.TgWsAssetName = asset.Name;
                }

                tgUpdated = true;
            }

            items.Add(new VendorUpdateItem("tg-ws-proxy", tgRelease.TagName, tgUpdated));

            if (zapretUpdated || tgUpdated)
            {
                metadata.UpdatedAtUtc = DateTimeOffset.UtcNow;
                SaveMetadata(metadata);
            }

            return new VendorUpdateSummary(items, skippedFiles);
        }

        private async Task<IReadOnlyList<string>> UpdateZapretAsync(HttpClient client, GitHubAsset asset, CancellationToken cancellationToken)
        {
            string tempZipPath = Path.Combine(Path.GetTempPath(), $"serpium_zapret_{Guid.NewGuid():N}.zip");
            List<string> skippedFiles = new List<string>();

            try
            {
                await DownloadFileAsync(client, asset.BrowserDownloadUrl, tempZipPath, cancellationToken);

                using ZipArchive archive = ZipFile.OpenRead(tempZipPath);

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string? destination = ResolveZapretDestination(entry);

                    if (destination == null)
                        continue;

                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

                    if (IsOptionalLockedRuntimeFile(destination) && IsFileLocked(destination))
                    {
                        skippedFiles.Add(Path.GetFileName(destination));
                        continue;
                    }

                    try
                    {
                        ExtractEntryReplacingFile(entry, destination);
                    }
                    catch (IOException) when (IsOptionalLockedRuntimeFile(destination))
                    {
                        skippedFiles.Add(Path.GetFileName(destination));
                    }
                    catch (UnauthorizedAccessException) when (IsOptionalLockedRuntimeFile(destination))
                    {
                        skippedFiles.Add(Path.GetFileName(destination));
                    }
                }
            }
            finally
            {
                TryDelete(tempZipPath);
            }

            return skippedFiles;
        }

        private async Task<IReadOnlyList<string>> UpdateTgWsAsync(HttpClient client, GitHubAsset asset, CancellationToken cancellationToken)
        {
            string tgwsPath = Path.Combine(_binFilesPath, "tgws");
            Directory.CreateDirectory(tgwsPath);

            string destination = Path.Combine(tgwsPath, "TgWsProxy_windows.exe");
            string tempPath = Path.Combine(tgwsPath, $"TgWsProxy_windows.exe.{Guid.NewGuid():N}.tmp");
            List<string> skippedFiles = new List<string>();

            try
            {
                await DownloadFileAsync(client, asset.BrowserDownloadUrl, tempPath, cancellationToken);

                if (IsFileLocked(destination))
                {
                    skippedFiles.Add(Path.GetFileName(destination));
                    return skippedFiles;
                }

                if (File.Exists(destination))
                    File.Delete(destination);

                File.Move(tempPath, destination);
            }
            finally
            {
                TryDelete(tempPath);
            }

            return skippedFiles;
        }

        private static void ExtractEntryReplacingFile(ZipArchiveEntry entry, string destination)
        {
            string tempPath = Path.Combine(
                Path.GetDirectoryName(destination)!,
                $"{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp"
            );

            try
            {
                entry.ExtractToFile(tempPath, overwrite: true);

                if (File.Exists(destination))
                    File.Delete(destination);

                File.Move(tempPath, destination);
            }
            finally
            {
                TryDelete(tempPath);
            }
        }

        private string? ResolveZapretDestination(ZipArchiveEntry entry)
        {
            if (string.IsNullOrEmpty(entry.Name))
                return null;

            string relative = NormalizeArchivePath(entry.FullName);
            string fileName = Path.GetFileName(relative);

            if (IsUserOwnedFile(fileName))
                return null;

            if (TryGetSubPath(relative, "bin", out string binSubPath))
                return ResolveSafeDestination(Path.Combine(_binFilesPath, "bin"), binSubPath);

            if (TryGetSubPath(relative, "lists", out string listsSubPath))
                return ResolveSafeDestination(Path.Combine(_binFilesPath, "lists"), listsSubPath);

            if (fileName.Equals("service.bat", StringComparison.OrdinalIgnoreCase) ||
                (fileName.StartsWith("general", StringComparison.OrdinalIgnoreCase) &&
                 fileName.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)))
            {
                return ResolveSafeDestination(Path.Combine(_binFilesPath, "bats"), fileName);
            }

            return null;
        }

        private static string? ResolveSafeDestination(string root, string relativePath)
        {
            string rootFullPath = Path.GetFullPath(root);
            string destination = Path.GetFullPath(Path.Combine(rootFullPath, relativePath));
            string rootWithSeparator = rootFullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

            if (!destination.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
                return null;

            return destination;
        }

        private static bool IsUserOwnedFile(string fileName)
        {
            return fileName.Equals("list-general-user.txt", StringComparison.OrdinalIgnoreCase) ||
                   fileName.Equals("list-exclude-user.txt", StringComparison.OrdinalIgnoreCase) ||
                   fileName.Equals("ipset-exclude-user.txt", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsOptionalLockedRuntimeFile(string path)
        {
            string fileName = Path.GetFileName(path);

            return fileName.Equals("WinDivert64.sys", StringComparison.OrdinalIgnoreCase) ||
                   fileName.Equals("WinDivert.dll", StringComparison.OrdinalIgnoreCase) ||
                   fileName.Equals("winws.exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsFileLocked(string path)
        {
            if (!File.Exists(path))
                return false;

            try
            {
                using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                return false;
            }
            catch (IOException)
            {
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return true;
            }
        }

        private static string NormalizeArchivePath(string path)
        {
            return path.Replace('\\', '/').TrimStart('/');
        }

        private static bool TryGetSubPath(string relative, string folderName, out string subPath)
        {
            string[] parts = relative.Split('/', StringSplitOptions.RemoveEmptyEntries);

            for (int i = 0; i < parts.Length - 1; i++)
            {
                if (!parts[i].Equals(folderName, StringComparison.OrdinalIgnoreCase))
                    continue;

                subPath = Path.Combine(parts.Skip(i + 1).ToArray());
                return !string.IsNullOrWhiteSpace(subPath);
            }

            subPath = string.Empty;
            return false;
        }

        private static GitHubAsset SelectZapretAsset(GitHubRelease release)
        {
            GitHubAsset? asset = release.Assets
                .Where(asset => asset.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(asset => asset.Name.Contains("zapret", StringComparison.OrdinalIgnoreCase))
                .ThenBy(asset => asset.Name)
                .FirstOrDefault();

            return asset ?? throw new InvalidOperationException("В последнем релизе zapret не найден ZIP-архив для обновления.");
        }

        private static GitHubAsset SelectTgWsAsset(GitHubRelease release)
        {
            GitHubAsset? asset = release.Assets.FirstOrDefault(asset =>
                asset.Name.Equals("TgWsProxy_windows.exe", StringComparison.OrdinalIgnoreCase));

            return asset ?? throw new InvalidOperationException("В последнем релизе TG WS Proxy не найден TgWsProxy_windows.exe.");
        }

        private static async Task<GitHubRelease> GetLatestReleaseAsync(HttpClient client, string repo, CancellationToken cancellationToken)
        {
            using HttpResponseMessage response = await client.GetAsync(
                $"https://api.github.com/repos/{repo}/releases/latest",
                cancellationToken
            );

            response.EnsureSuccessStatusCode();

            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            GitHubRelease? release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, cancellationToken: cancellationToken);

            if (release == null || string.IsNullOrWhiteSpace(release.TagName))
                throw new InvalidOperationException($"GitHub вернул пустой latest release для {repo}.");

            return release;
        }

        private static async Task DownloadFileAsync(HttpClient client, string url, string destination, CancellationToken cancellationToken)
        {
            using HttpResponseMessage response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();

            await using Stream source = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using FileStream target = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
            await source.CopyToAsync(target, cancellationToken);
        }

        private static HttpClient CreateHttpClient()
        {
            HttpClient client = new HttpClient
            {
                Timeout = TimeSpan.FromMinutes(5)
            };

            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SerpiumVPN", "1.0"));
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");

            return client;
        }

        private VendorVersionMetadata LoadMetadata()
        {
            try
            {
                if (!File.Exists(_metadataPath))
                    return new VendorVersionMetadata();

                VendorVersionMetadata? metadata = JsonSerializer.Deserialize<VendorVersionMetadata>(
                    File.ReadAllText(_metadataPath)
                );

                return metadata ?? new VendorVersionMetadata();
            }
            catch
            {
                return new VendorVersionMetadata();
            }
        }

        private void SaveMetadata(VendorVersionMetadata metadata)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_metadataPath)!);

            JsonSerializerOptions options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            File.WriteAllText(_metadataPath, JsonSerializer.Serialize(metadata, options));
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
                // temp cleanup best effort
            }
        }
    }

    public sealed record VendorUpdateItem(string Name, string LatestVersion, bool Updated);

    public sealed class VendorUpdateSummary
    {
        public VendorUpdateSummary(IReadOnlyList<VendorUpdateItem> items, IReadOnlyList<string> skippedFiles)
        {
            Items = items;
            SkippedFiles = skippedFiles;
        }

        public IReadOnlyList<VendorUpdateItem> Items { get; }

        public IReadOnlyList<string> SkippedFiles { get; }

        public bool HasUpdates => Items.Any(item => item.Updated);
    }

    internal sealed class VendorVersionMetadata
    {
        [JsonPropertyName("zapret_tag")]
        public string? ZapretTag { get; set; }

        [JsonPropertyName("zapret_asset_name")]
        public string? ZapretAssetName { get; set; }

        [JsonPropertyName("tg_ws_tag")]
        public string? TgWsTag { get; set; }

        [JsonPropertyName("tg_ws_asset_name")]
        public string? TgWsAssetName { get; set; }

        [JsonPropertyName("updated_at_utc")]
        public DateTimeOffset? UpdatedAtUtc { get; set; }
    }

    internal sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")]
        public string TagName { get; set; } = string.Empty;

        [JsonPropertyName("assets")]
        public List<GitHubAsset> Assets { get; set; } = new List<GitHubAsset>();
    }

    internal sealed class GitHubAsset
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("browser_download_url")]
        public string BrowserDownloadUrl { get; set; } = string.Empty;
    }
}
