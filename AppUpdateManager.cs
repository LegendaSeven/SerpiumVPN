using System;
using System.Threading;
using System.Threading.Tasks;
using Velopack;
using Velopack.Sources;

namespace SerpiumVPN
{
    public sealed class AppUpdateManager
    {
        private const string ReleasesUrl = "https://github.com/LegendaSeven/SerpiumVPN";

        private readonly UpdateManager _updateManager;
        private VelopackAsset? _readyToApplyUpdate;

        public AppUpdateManager()
        {
            _updateManager = new UpdateManager(
                new GithubSource(ReleasesUrl, accessToken: null, prerelease: false, downloader: null)
            );
        }

        public bool IsInstalled => _updateManager.IsInstalled || _updateManager.IsPortable;

        public string CurrentVersion => _updateManager.CurrentVersion?.ToString() ?? "dev";

        public string InstallDiagnostics =>
            $"Velopack: Installed={_updateManager.IsInstalled}, Portable={_updateManager.IsPortable}, Version={CurrentVersion}\n" +
            $"EXE: {Environment.ProcessPath ?? "unknown"}\n" +
            $"Папка запуска: {AppContext.BaseDirectory}";

        public async Task<AppUpdateCheckResult> CheckDownloadAndApplyAsync(
            IProgress<int>? downloadProgress,
            CancellationToken cancellationToken = default)
        {
            if (!IsInstalled)
                return AppUpdateCheckResult.NotInstalled(CurrentVersion, InstallDiagnostics);

            VelopackAsset? pendingUpdate = _updateManager.UpdatePendingRestart;

            if (pendingUpdate is not null)
            {
                _readyToApplyUpdate = pendingUpdate;
                return AppUpdateCheckResult.ReadyToRestart(pendingUpdate.Version.ToString());
            }

            UpdateInfo? updateInfo = await _updateManager.CheckForUpdatesAsync();

            if (updateInfo is null)
                return AppUpdateCheckResult.NoUpdates(CurrentVersion);

            await _updateManager.DownloadUpdatesAsync(
                updateInfo,
                progress => downloadProgress?.Report(progress),
                cancellationToken
            );

            _readyToApplyUpdate = updateInfo.TargetFullRelease;
            return AppUpdateCheckResult.ReadyToRestart(updateInfo.TargetFullRelease.Version.ToString());
        }

        public void RestartAndApply()
        {
            VelopackAsset? update = _readyToApplyUpdate ?? _updateManager.UpdatePendingRestart;

            if (update is null)
                throw new InvalidOperationException("Обновление скачано, но Velopack не видит пакет для перезапуска.");

            _updateManager.ApplyUpdatesAndRestart(update);
        }
    }

    public sealed record AppUpdateCheckResult(
        AppUpdateCheckStatus Status,
        string Version,
        string Details = "")
    {
        public static AppUpdateCheckResult NotInstalled(string version, string details) =>
            new(AppUpdateCheckStatus.NotInstalled, version, details);

        public static AppUpdateCheckResult NoUpdates(string version) =>
            new(AppUpdateCheckStatus.NoUpdates, version);

        public static AppUpdateCheckResult ReadyToRestart(string version) =>
            new(AppUpdateCheckStatus.ReadyToRestart, version);
    }

    public enum AppUpdateCheckStatus
    {
        NotInstalled,
        NoUpdates,
        ReadyToRestart
    }
}
