using System;
using System.Collections.Generic;
using System.IO;
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

            List<string> skippedFiles = new List<string>();

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

            if (tgUpdated)
            {
                metadata.UpdatedAtUtc = DateTimeOffset.UtcNow;
                SaveMetadata(metadata);
            }

            return new VendorUpdateSummary(items, skippedFiles);
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
