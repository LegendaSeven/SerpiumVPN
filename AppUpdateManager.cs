using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using SerpiumVPN.Updates;

namespace SerpiumVPN;

public sealed class AppUpdateManager : IDisposable
{
    public const string RepositoryUrl = "https://github.com/LegendaSeven/SerpiumVPN";
    private const string LatestReleaseApiUrl = "https://api.github.com/repos/LegendaSeven/SerpiumVPN/releases/latest";
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _cacheRoot;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _pendingDirectory;
    private bool _handedOff;
    public AppUpdateInfo? AvailableUpdate { get; private set; }
    public string? PendingArchivePath { get; private set; }
    public bool IsReady => PendingArchivePath is not null && File.Exists(PendingArchivePath);
    public string CurrentVersion { get; }

    public AppUpdateManager(HttpClient? client = null, string? currentVersion = null, string? cacheRoot = null)
    {
        _http = client ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        _ownsClient = client is null;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("SerpiumVPN-Updater");
        CurrentVersion = currentVersion ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0.0";
        _cacheRoot = cacheRoot ?? Path.GetTempPath();
    }

    public async Task<AppUpdateInfo?> CheckAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            // Keep a verified download visible until the user installs or closes the application.
            if (IsReady) return AvailableUpdate;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(30));
            using var release = await ReadJsonAsync(LatestReleaseApiUrl, deadline.Token);
            var root = release.RootElement;
            if (root.GetProperty("draft").GetBoolean() || root.GetProperty("prerelease").GetBoolean())
                throw new InvalidDataException("GitHub не вернул стабильный выпуск.");
            string tag = root.GetProperty("tag_name").GetString() ?? "";
            string version = tag.StartsWith('v') ? tag[1..] : tag;
            if (!TryVersion(version, out var next) || !TryVersion(CurrentVersion.Split('+')[0], out var current))
                throw new InvalidDataException("Не удалось определить версию обновления.");
            if (next <= current) { AvailableUpdate = null; return null; }
            string zipName = $"SerpiumVPN-{version}.zip";
            var assets = root.GetProperty("assets").EnumerateArray().ToArray();
            JsonElement FindAsset(string name)
            {
                var matches = assets.Where(a => a.GetProperty("name").GetString() == name).ToArray();
                if (matches.Length != 1) throw new InvalidDataException("В выпуске отсутствуют необходимые файлы обновления.");
                return matches[0];
            }
            string AssetUrl(JsonElement asset, string name)
            {
                string url = asset.GetProperty("browser_download_url").GetString() ?? "";
                if (url != $"{RepositoryUrl}/releases/download/{tag}/{name}")
                    throw new InvalidDataException("Обновление ссылается на посторонний источник.");
                return url;
            }
            var zip = FindAsset(zipName);
            string zipUrl = AssetUrl(zip, zipName);
            long size = zip.GetProperty("size").GetInt64();
            if (size <= 0 || size > UpdatePackage.MaxArchiveBytes) throw new InvalidDataException("Недопустимый размер обновления.");
            using var manifest = await ReadJsonAsync(AssetUrl(FindAsset("update.json"), "update.json"), deadline.Token);
            var metadata = manifest.RootElement;
            string hash = metadata.GetProperty("sha256").GetString() ?? "";
            if (metadata.GetProperty("version").GetString() != version || metadata.GetProperty("zipUrl").GetString() != zipUrl || !UpdatePackage.IsSha256(hash))
                throw new InvalidDataException("Описание обновления не соответствует выпуску. Установка отменена.");
            if (zip.TryGetProperty("digest", out var digest) && digest.ValueKind == JsonValueKind.String &&
                !string.Equals(digest.GetString(), "sha256:" + hash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Контрольные суммы выпуска не совпадают.");
            AvailableUpdate = new(version, zipUrl, hash, size);
            return AvailableUpdate;
        }
        finally { _gate.Release(); }
    }

    public async Task DownloadAsync(IProgress<int>? progress, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        string? downloadDirectory = null;
        try
        {
            if (IsReady) return;
            var update = AvailableUpdate ?? throw new InvalidOperationException("Сначала проверьте наличие новой версии.");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromMinutes(15));
            var token = deadline.Token;
            downloadDirectory = UpdatePackage.CreatePrivateDirectory(_cacheRoot, "Serpium-download-");
            string archive = Path.Combine(downloadDirectory, "update.zip");
            using var response = await _http.GetAsync(update.ZipUrl, HttpCompletionOption.ResponseHeadersRead, token);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long length && length != update.Size)
                throw new InvalidDataException("Размер скачиваемого обновления изменился. Повторите проверку.");
            await using (var input = await response.Content.ReadAsStreamAsync(token))
            await using (var output = new FileStream(archive, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true))
            {
                byte[] buffer = new byte[131072]; long total = 0; int previous = -1;
                while (true)
                {
                    int read = await input.ReadAsync(buffer, token);
                    if (read == 0) break;
                    total += read;
                    if (total > update.Size) throw new InvalidDataException("Размер обновления превышает ожидаемый.");
                    await output.WriteAsync(buffer.AsMemory(0, read), token);
                    int percent = (int)(total * 100 / update.Size);
                    if (percent != previous) { progress?.Report(percent); previous = percent; }
                }
                if (total != update.Size) throw new InvalidDataException("Обновление скачано не полностью. Повторите загрузку.");
            }
            await Task.Run(() => UpdatePackage.Verify(archive, update.Sha256), token);
            token.ThrowIfCancellationRequested();
            _pendingDirectory = downloadDirectory;
            PendingArchivePath = archive;
            downloadDirectory = null;
            progress?.Report(100);
        }
        finally
        {
            if (downloadDirectory is not null) DeleteOwnedDirectory(downloadDirectory);
            _gate.Release();
        }
    }

    public async Task<Process> StartUpdaterAsync()
    {
        if (!IsReady || AvailableUpdate is null) throw new InvalidOperationException("Сначала скачайте обновление.");
        string archive = PendingArchivePath!;
        await Task.Run(() => UpdatePackage.Verify(archive, AvailableUpdate.Sha256));
        string target = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        string source = Path.Combine(target, "SerpiumUpdater.exe");
        if (!File.Exists(source)) throw new FileNotFoundException("Не найден модуль обновления. Установите полную версию Serpium.");
        string updater = Path.Combine(_pendingDirectory!, "SerpiumUpdater.exe");
        File.Copy(source, updater, true);
        var start = new ProcessStartInfo(updater) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = _pendingDirectory! };
        foreach (var value in new[] { "--pid", Environment.ProcessId.ToString(), "--target", target, "--zip", archive,
            "--sha256", AvailableUpdate.Sha256, "--exe", Path.Combine(target, "SerpiumVPN.exe") }) start.ArgumentList.Add(value);
        var process = Process.Start(start) ?? throw new IOException("Не удалось запустить обновление.");
        await Task.Delay(350);
        if (process.HasExited) { process.Dispose(); throw new IOException("Модуль обновления не запустился. Повторите попытку."); }
        _handedOff = true;
        return process;
    }

    private async Task<JsonDocument> ReadJsonAsync(string url, CancellationToken token)
    {
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > 1024 * 1024) throw new InvalidDataException("Слишком большой ответ сервера обновлений.");
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream(); byte[] buffer = new byte[16384];
        while (true)
        {
            int read = await input.ReadAsync(buffer, token);
            if (read == 0) break;
            if (output.Length + read > 1024 * 1024) throw new InvalidDataException("Слишком большой ответ сервера обновлений.");
            output.Write(buffer, 0, read);
        }
        return JsonDocument.Parse(output.ToArray());
    }

    private static bool TryVersion(string value, out Version version)
    {
        version = new(0, 0, 0, 0);
        if (value.Any(c => !char.IsAsciiDigit(c) && c != '.') || !Version.TryParse(value, out var parsed)) return false;
        version = new(parsed.Major, parsed.Minor, Math.Max(0, parsed.Build), Math.Max(0, parsed.Revision));
        return true;
    }
    private static void DeleteOwnedDirectory(string path) { try { Directory.Delete(path, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    public void Dispose()
    {
        if (!_handedOff && _pendingDirectory is not null) DeleteOwnedDirectory(_pendingDirectory);
        if (_ownsClient) _http.Dispose();
    }
}

public sealed record AppUpdateInfo(string Version, string ZipUrl, string Sha256, long Size);
