using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using InputKey = System.Windows.Input.Key;
using InputKeyEventArgs = System.Windows.Input.KeyEventArgs;
using MediaBrush = System.Windows.Media.Brush;
using MediaBrushConverter = System.Windows.Media.BrushConverter;
using MediaBrushes = System.Windows.Media.Brushes;
using WpfButton = System.Windows.Controls.Button;

namespace SerpiumVPN.Relay.Components;

public partial class RelayComponentSettingsWindow : Window
{
    private readonly RelayComponentManager _componentManager;
    private readonly UserRuntimeSettings _settings;
    private readonly Action<string>? _summaryChanged;
    private readonly Func<Task>? _stopRelayTransportsAsync;
    private readonly Dictionary<RelayComponentKind, RelayComponentSnapshot> _snapshots = new();
    private readonly Dictionary<RelayComponentKind, RelayComponentReleaseInfo> _releases = new();
    private readonly Dictionary<RelayComponentKind, RelayComponentStagingSnapshot> _staging = new();
    private readonly Dictionary<RelayComponentKind, RelayComponentBackupSnapshot> _backups = new();
    private CancellationTokenSource? _operationCancellation;
    private bool _loadingSettings;
    private bool _busy;

    public RelayComponentSettingsWindow(
        RelayComponentManager componentManager,
        UserRuntimeSettings settings,
        Action<string>? summaryChanged = null,
        Func<Task>? stopRelayTransportsAsync = null)
    {
        _componentManager = componentManager ?? throw new ArgumentNullException(nameof(componentManager));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _summaryChanged = summaryChanged;
        _stopRelayTransportsAsync = stopRelayTransportsAsync;

        InitializeComponent();
        Loaded += Window_LoadedAsync;
        Closed += (_, _) => CancelCurrentOperation();
    }

    private async void Window_LoadedAsync(object sender, RoutedEventArgs e)
    {
        _loadingSettings = true;
        try
        {
            AutoCheckRelayComponentsCheckBox.IsChecked =
                _settings.AutoCheckRelayComponents;
            ApplyLastCheckText();
            ApplyCachedReleaseLabels();
        }
        finally
        {
            _loadingSettings = false;
        }

        await RefreshLocalAsync();

        if (_settings.AutoCheckRelayComponents)
            await CheckUpdatesAsync(manual: false);
    }

    private async void RefreshLocal_ClickAsync(object sender, RoutedEventArgs e) =>
        await RefreshLocalAsync();

    private async void CheckUpdates_ClickAsync(object sender, RoutedEventArgs e) =>
        await CheckUpdatesAsync(manual: true);

    private async void CheckSingBox_ClickAsync(object sender, RoutedEventArgs e) =>
        await RefreshSingleAsync(RelayComponentKind.SingBox);

    private async void CheckXray_ClickAsync(object sender, RoutedEventArgs e) =>
        await RefreshSingleAsync(RelayComponentKind.XrayCore);

    private async void StageSingBox_ClickAsync(object sender, RoutedEventArgs e) =>
        await StageAsync(RelayComponentKind.SingBox);

    private async void StageXray_ClickAsync(object sender, RoutedEventArgs e) =>
        await StageAsync(RelayComponentKind.XrayCore);

    private async void DeleteSingBoxStage_ClickAsync(object sender, RoutedEventArgs e) =>
        await DeleteStagedAsync(RelayComponentKind.SingBox);

    private async void DeleteXrayStage_ClickAsync(object sender, RoutedEventArgs e) =>
        await DeleteStagedAsync(RelayComponentKind.XrayCore);

    private async void InstallSingBox_ClickAsync(object sender, RoutedEventArgs e) =>
        await InstallAsync(RelayComponentKind.SingBox);

    private async void InstallXray_ClickAsync(object sender, RoutedEventArgs e) =>
        await InstallAsync(RelayComponentKind.XrayCore);

    private async void RollbackSingBox_ClickAsync(object sender, RoutedEventArgs e) =>
        await RollbackAsync(RelayComponentKind.SingBox);

    private async void RollbackXray_ClickAsync(object sender, RoutedEventArgs e) =>
        await RollbackAsync(RelayComponentKind.XrayCore);

    private async Task RefreshLocalAsync()
    {
        if (!TryBeginOperation("Проверяю локальные компоненты..."))
            return;

        try
        {
            Task<IReadOnlyDictionary<RelayComponentKind, RelayComponentSnapshot>>
                snapshotsTask = _componentManager.InspectAllAsync(
                    _operationCancellation!.Token);

            Task<IReadOnlyDictionary<RelayComponentKind, RelayComponentStagingSnapshot>>
                stagingTask = _componentManager.InspectAllStagingAsync(
                    _operationCancellation.Token);

            Task<IReadOnlyDictionary<RelayComponentKind, RelayComponentBackupSnapshot>>
                backupsTask = _componentManager.InspectAllBackupsAsync(
                    _operationCancellation.Token);

            await Task.WhenAll(snapshotsTask, stagingTask, backupsTask);

            IReadOnlyDictionary<RelayComponentKind, RelayComponentSnapshot> snapshots =
                await snapshotsTask;

            IReadOnlyDictionary<RelayComponentKind, RelayComponentStagingSnapshot> staging =
                await stagingTask;

            IReadOnlyDictionary<RelayComponentKind, RelayComponentBackupSnapshot> backups =
                await backupsTask;

            foreach ((RelayComponentKind kind, RelayComponentSnapshot snapshot) in snapshots)
                _snapshots[kind] = snapshot;

            foreach ((RelayComponentKind kind, RelayComponentStagingSnapshot snapshot) in staging)
                _staging[kind] = snapshot;

            foreach ((RelayComponentKind kind, RelayComponentBackupSnapshot snapshot) in backups)
                _backups[kind] = snapshot;

            RenderAll();
            SetOverallStatus(BuildSummaryText(), BuildSummaryBrush());
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus("Проверка компонентов отменена.", MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            SetOverallStatus(
                $"Не удалось проверить локальные компоненты: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task RefreshSingleAsync(RelayComponentKind kind)
    {
        if (!TryBeginOperation($"Проверяю {GetDisplayName(kind)}..."))
            return;

        try
        {
            await RefreshComponentStateCoreAsync(
                kind,
                _operationCancellation!.Token);
            RenderCard(kind);
            SetOverallStatus(
                BuildComponentStatusText(kind),
                BuildComponentStatusBrush(kind));
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus("Проверка компонента отменена.", MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            SetOverallStatus(
                $"Не удалось проверить компонент: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task CheckUpdatesAsync(bool manual)
    {
        if (!manual &&
            _settings.LastRelayComponentCheckUtc is DateTimeOffset lastCheck &&
            DateTimeOffset.UtcNow - lastCheck < TimeSpan.FromHours(12) &&
            !string.IsNullOrWhiteSpace(_settings.LastKnownSingBoxRelease) &&
            !string.IsNullOrWhiteSpace(_settings.LastKnownXrayRelease))
        {
            ApplyCachedReleaseLabels();
            RenderAll();
            SetOverallStatus(BuildSummaryText(), BuildSummaryBrush());
            return;
        }

        if (!TryBeginOperation("Проверяю официальные стабильные релизы..."))
            return;

        try
        {
            IReadOnlyDictionary<RelayComponentKind, RelayComponentReleaseInfo> releases =
                await _componentManager.CheckLatestStableReleasesAsync(
                    _operationCancellation!.Token);

            foreach ((RelayComponentKind kind, RelayComponentReleaseInfo release) in releases)
                _releases[kind] = release;

            _settings.LastRelayComponentCheckUtc = DateTimeOffset.UtcNow;
            _settings.LastKnownSingBoxRelease =
                releases[RelayComponentKind.SingBox].TagName;
            _settings.LastKnownXrayRelease =
                releases[RelayComponentKind.XrayCore].TagName;
            _settings.Save();

            ApplyLastCheckText();
            RenderAll();
            SetOverallStatus(BuildSummaryText(), BuildSummaryBrush());
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus("Проверка обновлений отменена.", MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            SetOverallStatus(
                $"Не удалось проверить официальные релизы: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private void ApplyCachedReleaseLabels()
    {
        AddCachedRelease(
            RelayComponentKind.SingBox,
            _settings.LastKnownSingBoxRelease,
            "SagerNet/sing-box");
        AddCachedRelease(
            RelayComponentKind.XrayCore,
            _settings.LastKnownXrayRelease,
            "XTLS/Xray-core");
    }

    private void AddCachedRelease(
        RelayComponentKind kind,
        string? tag,
        string repository)
    {
        if (string.IsNullOrWhiteSpace(tag) || _releases.ContainsKey(kind))
            return;

        _releases[kind] = new RelayComponentReleaseInfo(
            kind,
            tag,
            RelayComponentManager.NormalizeVersionLabel(tag),
            $"Кэшированная проверка {repository}",
            PublishedAtUtc: null,
            ReleasePageUrl: string.Empty,
            Repository: repository,
            WindowsAmd64Asset: null);
    }

    private void RenderAll()
    {
        RenderCard(RelayComponentKind.SingBox);
        RenderCard(RelayComponentKind.XrayCore);
    }

    private void RenderCard(RelayComponentKind kind)
    {
        if (!_snapshots.TryGetValue(kind, out RelayComponentSnapshot? snapshot))
            return;

        _releases.TryGetValue(kind, out RelayComponentReleaseInfo? release);

        TextBlock installedText = kind == RelayComponentKind.SingBox
            ? SingBoxInstalledVersionText
            : XrayInstalledVersionText;
        TextBlock latestText = kind == RelayComponentKind.SingBox
            ? SingBoxLatestVersionText
            : XrayLatestVersionText;
        TextBlock pathText = kind == RelayComponentKind.SingBox
            ? SingBoxPathText
            : XrayPathText;
        TextBlock hashText = kind == RelayComponentKind.SingBox
            ? SingBoxHashText
            : XrayHashText;
        TextBlock healthText = kind == RelayComponentKind.SingBox
            ? SingBoxHealthText
            : XrayHealthText;
        Border statusChip = kind == RelayComponentKind.SingBox
            ? SingBoxStatusChip
            : XrayStatusChip;
        TextBlock statusChipText = kind == RelayComponentKind.SingBox
            ? SingBoxStatusChipText
            : XrayStatusChipText;

        installedText.Text = snapshot.InstalledVersion ?? "не определена";
        latestText.Text = release?.TagName ?? "не проверялся";
        pathText.Text = snapshot.SafePath;
        hashText.Text = string.IsNullOrWhiteSpace(snapshot.Sha256)
            ? "—"
            : snapshot.Sha256;
        healthText.Text = snapshot.HealthMessage;

        string chipText;
        MediaBrush chipForeground;
        MediaBrush chipBackground;
        MediaBrush chipBorder;

        if (snapshot.Health is RelayComponentHealth.Missing or RelayComponentHealth.Failed)
        {
            chipText = snapshot.Health == RelayComponentHealth.Missing
                ? "Не найден"
                : "Ошибка";
            chipForeground = BrushFromHex("#FF8A94");
            chipBackground = BrushFromHex("#382127");
            chipBorder = BrushFromHex("#8C3E49");
        }
        else if (release is not null && RelayComponentManager.IsUpdateAvailable(
                     snapshot.InstalledVersion,
                     release.NormalizedVersion))
        {
            chipText = "Есть релиз";
            chipForeground = BrushFromHex("#FFD17A");
            chipBackground = BrushFromHex("#392F1D");
            chipBorder = BrushFromHex("#8B7133");
            healthText.Text +=
                release.WindowsAmd64Asset is RelayComponentReleaseAsset asset &&
                asset.HasVerifiedSha256
                    ? " Доступно безопасное скачивание и проверка в staging."
                    : " Windows AMD64 asset не содержит подтверждённый SHA-256 digest; загрузка заблокирована.";
        }
        else if (release is not null && RelayComponentManager.IsInstalledVersionNewer(
                     snapshot.InstalledVersion,
                     release.NormalizedVersion))
        {
            chipText = "Новее stable";
            chipForeground = BrushFromHex("#9AD8FF");
            chipBackground = BrushFromHex("#1D3040");
            chipBorder = BrushFromHex("#3E728F");
        }
        else if (snapshot.Health == RelayComponentHealth.Warning)
        {
            chipText = "Требует внимания";
            chipForeground = BrushFromHex("#FFD17A");
            chipBackground = BrushFromHex("#392F1D");
            chipBorder = BrushFromHex("#8B7133");
        }
        else
        {
            chipText = release is null ? "Исправен" : "Актуален";
            chipForeground = BrushFromHex("#66E99F");
            chipBackground = BrushFromHex("#18372B");
            chipBorder = BrushFromHex("#2E8E61");
        }

        statusChipText.Text = chipText;
        statusChipText.Foreground = chipForeground;
        statusChip.Background = chipBackground;
        statusChip.BorderBrush = chipBorder;

        RenderStaging(kind, snapshot, release);
    }

    private void RenderStaging(
        RelayComponentKind kind,
        RelayComponentSnapshot snapshot,
        RelayComponentReleaseInfo? release)
    {
        _staging.TryGetValue(
            kind,
            out RelayComponentStagingSnapshot? staging);

        _backups.TryGetValue(
            kind,
            out RelayComponentBackupSnapshot? backup);

        Border stagingBorder = kind == RelayComponentKind.SingBox
            ? SingBoxStagingBorder
            : XrayStagingBorder;

        TextBlock stagingText = kind == RelayComponentKind.SingBox
            ? SingBoxStagingText
            : XrayStagingText;

        WpfButton stageButton = kind == RelayComponentKind.SingBox
            ? SingBoxStageButton
            : XrayStageButton;

        WpfButton deleteButton = kind == RelayComponentKind.SingBox
            ? SingBoxDeleteStageButton
            : XrayDeleteStageButton;

        WpfButton installButton = kind == RelayComponentKind.SingBox
            ? SingBoxInstallButton
            : XrayInstallButton;

        WpfButton rollbackButton = kind == RelayComponentKind.SingBox
            ? SingBoxRollbackButton
            : XrayRollbackButton;

        bool updateAvailable =
            release is not null &&
            RelayComponentManager.IsUpdateAvailable(
                snapshot.InstalledVersion,
                release.NormalizedVersion);

        if (staging is null || !staging.Exists)
        {
            stagingText.Text =
                "Staging: обновление ещё не загружено.";
            stagingText.Foreground = BrushFromHex("#8F8F9C");
            stagingBorder.BorderBrush = BrushFromHex("#343447");
            deleteButton.Visibility = Visibility.Collapsed;
        }
        else if (staging.Ready)
        {
            string stagedTime = staging.StagedAtUtc is DateTimeOffset stagedAt
                ? stagedAt.ToLocalTime().ToString(
                    "dd.MM.yyyy HH:mm",
                    CultureInfo.CurrentCulture)
                : "время не определено";

            stagingText.Text =
                $"Подготовлено: {staging.TagName} · SHA-256 подтверждён · " +
                $"{staging.SafeDirectory} · {stagedTime}. " +
                "Можно установить с автоматическим rollback.";

            stagingText.Foreground = BrushFromHex("#66E99F");
            stagingBorder.BorderBrush = BrushFromHex("#2E8E61");
            deleteButton.Visibility = Visibility.Visible;
        }
        else
        {
            stagingText.Text =
                $"Staging требует очистки: {staging.Message}";
            stagingText.Foreground = MediaBrushes.OrangeRed;
            stagingBorder.BorderBrush = BrushFromHex("#8C3E49");
            deleteButton.Visibility = Visibility.Visible;
        }

        if (backup is { Exists: true })
        {
            stagingText.Text += Environment.NewLine;

            if (backup.Ready)
            {
                string backupTime = backup.CreatedAtUtc is DateTimeOffset createdAt
                    ? createdAt.ToLocalTime().ToString(
                        "dd.MM.yyyy HH:mm",
                        CultureInfo.CurrentCulture)
                    : "время не определено";

                stagingText.Text +=
                    $"Rollback доступен: {backup.PreviousVersion} · " +
                    $"{backup.SafeDirectory} · {backupTime}.";
            }
            else
            {
                stagingText.Text +=
                    "Rollback backup повреждён: " + backup.Message;
                stagingText.Foreground = MediaBrushes.OrangeRed;
                stagingBorder.BorderBrush = BrushFromHex("#8C3E49");
            }
        }

        bool stagedVersionDiffers =
            staging is { Ready: true } &&
            !RelayComponentManager.AreVersionsEquivalent(
                snapshot.InstalledVersion,
                staging.NormalizedVersion);

        bool rollbackAvailable =
            backup is { Ready: true } &&
            !RelayComponentManager.AreVersionsEquivalent(
                snapshot.InstalledVersion,
                backup.PreviousVersion);

        stageButton.Visibility = updateAvailable
            ? Visibility.Visible
            : Visibility.Collapsed;

        stageButton.Content =
            staging is { Ready: true } &&
            release is not null &&
            RelayComponentManager.AreVersionsEquivalent(
                staging.NormalizedVersion,
                release.NormalizedVersion)
                ? "Перескачать в staging"
                : "Скачать обновление";

        bool releaseAssetIsVerified =
            release?.WindowsAmd64Asset is RelayComponentReleaseAsset asset &&
            asset.HasVerifiedSha256;

        stageButton.IsEnabled =
            !_busy &&
            updateAvailable &&
            releaseAssetIsVerified &&
            snapshot.Health is not RelayComponentHealth.Missing
                and not RelayComponentHealth.Failed;

        stageButton.ToolTip = updateAvailable && !releaseAssetIsVerified
            ? "Официальный Windows AMD64 asset не содержит подтверждённый SHA-256 digest."
            : "Скачать и повторно проверить официальный release asset.";

        installButton.Visibility = stagedVersionDiffers
            ? Visibility.Visible
            : Visibility.Collapsed;
        installButton.IsEnabled =
            !_busy &&
            stagedVersionDiffers &&
            snapshot.Health is not RelayComponentHealth.Missing
                and not RelayComponentHealth.Failed;
        installButton.Content = staging is { Ready: true }
            ? $"Установить {staging.TagName}"
            : "Установить";
        installButton.ToolTip =
            "Остановить активный Relay, создать backup, атомарно заменить компонент и проверить version/SHA-256.";

        rollbackButton.Visibility = rollbackAvailable
            ? Visibility.Visible
            : Visibility.Collapsed;
        rollbackButton.IsEnabled = !_busy && rollbackAvailable;
        rollbackButton.Content = backup is { Ready: true }
            ? $"Вернуть {backup.PreviousVersion}"
            : "Вернуть предыдущую";
        rollbackButton.ToolTip =
            "Восстановить предыдущий проверенный бинарник из приватного rollback backup.";

        deleteButton.IsEnabled = !_busy;
    }

    private async Task StageAsync(RelayComponentKind kind)
    {
        if (!_snapshots.TryGetValue(
                kind,
                out RelayComponentSnapshot? snapshot) ||
            !_releases.TryGetValue(
                kind,
                out RelayComponentReleaseInfo? release))
        {
            SetOverallStatus(
                "Сначала выполните проверку локальных компонентов и официальных релизов.",
                MediaBrushes.Goldenrod);
            return;
        }

        if (!RelayComponentManager.IsUpdateAvailable(
                snapshot.InstalledVersion,
                release.NormalizedVersion))
        {
            SetOverallStatus(
                $"{GetDisplayName(kind)} уже актуален.",
                BrushFromHex("#5CFF94"));
            return;
        }

        if (!TryBeginOperation(
                $"Подготавливаю {GetDisplayName(kind)} {release.TagName}..."))
        {
            return;
        }

        try
        {
            IProgress<RelayComponentDownloadProgress> progress =
                new Progress<RelayComponentDownloadProgress>(
                    state => SetOverallStatus(
                        $"{GetDisplayName(state.Kind)}: {state.Message}",
                        BrushFromHex("#9AD8FF")));

            RelayComponentStagingSnapshot staged =
                await _componentManager.StageReleaseAsync(
                    kind,
                    release,
                    progress,
                    _operationCancellation!.Token);

            _staging[kind] = staged;
            RenderCard(kind);

            SetOverallStatus(
                $"{GetDisplayName(kind)} {staged.TagName} проверен и подготовлен. " +
                "Рабочий компонент не заменялся.",
                BrushFromHex("#5CFF94"));
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus(
                "Подготовка обновления отменена.",
                MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            RelayComponentStagingSnapshot inspected =
                await _componentManager.InspectStagingAsync(kind);

            _staging[kind] = inspected;
            RenderCard(kind);

            SetOverallStatus(
                $"Не удалось подготовить {GetDisplayName(kind)}: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task DeleteStagedAsync(RelayComponentKind kind)
    {
        if (!TryBeginOperation(
                $"Удаляю staging {GetDisplayName(kind)}..."))
        {
            return;
        }

        try
        {
            _componentManager.DeleteStagedUpdate(kind);

            RelayComponentStagingSnapshot staging =
                await _componentManager.InspectStagingAsync(
                    kind,
                    _operationCancellation!.Token);

            _staging[kind] = staging;
            RenderCard(kind);

            SetOverallStatus(
                $"Загруженное обновление {GetDisplayName(kind)} удалено. " +
                "Рабочий компонент не изменялся.",
                BrushFromHex("#5CFF94"));
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus(
                "Удаление staging отменено.",
                MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            SetOverallStatus(
                $"Не удалось удалить staging: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task InstallAsync(RelayComponentKind kind)
    {
        if (!_staging.TryGetValue(
                kind,
                out RelayComponentStagingSnapshot? staging) ||
            !staging.Ready)
        {
            SetOverallStatus(
                "Сначала скачайте и проверьте обновление в staging.",
                MediaBrushes.Goldenrod);
            return;
        }

        string currentVersion =
            _snapshots.TryGetValue(
                kind,
                out RelayComponentSnapshot? currentSnapshot)
                ? currentSnapshot.InstalledVersion ?? "не определена"
                : "не определена";

        bool confirmed =
            RelayComponentActionDialog.ConfirmInstall(
                this,
                GetDisplayName(kind),
                currentVersion,
                staging.TagName ?? staging.NormalizedVersion ?? "не определена");

        if (!confirmed)
            return;

        if (!TryBeginOperation(
                $"Устанавливаю {GetDisplayName(kind)} {staging.TagName}..."))
        {
            return;
        }

        try
        {
            if (_stopRelayTransportsAsync is not null)
            {
                SetOverallStatus(
                    "Останавливаю активный профиль Serpium Relay...",
                    BrushFromHex("#9AD8FF"));
                await _stopRelayTransportsAsync();
            }

            IProgress<RelayComponentInstallProgress> progress =
                new Progress<RelayComponentInstallProgress>(
                    state => SetOverallStatus(
                        $"{GetDisplayName(state.Kind)}: {state.Message}",
                        BrushFromHex("#9AD8FF")));

            RelayComponentInstallResult result =
                await _componentManager.InstallStagedUpdateAsync(
                    kind,
                    progress,
                    _operationCancellation!.Token);

            await RefreshComponentStateCoreAsync(
                kind,
                _operationCancellation.Token);

            RenderCard(kind);
            SetOverallStatus(
                result.Message,
                result.Succeeded ? BrushFromHex("#5CFF94") : MediaBrushes.Goldenrod);
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus(
                "Установка компонента отменена.",
                MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            await RefreshComponentStateCoreBestEffortAsync(kind);
            RenderCard(kind);
            SetOverallStatus(
                $"Не удалось установить {GetDisplayName(kind)}: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task RollbackAsync(RelayComponentKind kind)
    {
        if (!_backups.TryGetValue(
                kind,
                out RelayComponentBackupSnapshot? backup) ||
            !backup.Ready)
        {
            SetOverallStatus(
                "Проверенный rollback backup отсутствует.",
                MediaBrushes.Goldenrod);
            return;
        }

        string currentVersion =
            _snapshots.TryGetValue(
                kind,
                out RelayComponentSnapshot? currentSnapshot)
                ? currentSnapshot.InstalledVersion ?? "не определена"
                : "не определена";

        bool confirmed =
            RelayComponentActionDialog.ConfirmRollback(
                this,
                GetDisplayName(kind),
                currentVersion,
                backup.PreviousVersion ?? "не определена");

        if (!confirmed)
            return;

        if (!TryBeginOperation(
                $"Возвращаю {GetDisplayName(kind)} {backup.PreviousVersion}..."))
        {
            return;
        }

        try
        {
            if (_stopRelayTransportsAsync is not null)
            {
                SetOverallStatus(
                    "Останавливаю активный профиль Serpium Relay...",
                    BrushFromHex("#9AD8FF"));
                await _stopRelayTransportsAsync();
            }

            IProgress<RelayComponentInstallProgress> progress =
                new Progress<RelayComponentInstallProgress>(
                    state => SetOverallStatus(
                        $"{GetDisplayName(state.Kind)}: {state.Message}",
                        BrushFromHex("#9AD8FF")));

            RelayComponentInstallResult result =
                await _componentManager.RollbackInstalledUpdateAsync(
                    kind,
                    progress,
                    _operationCancellation!.Token);

            await RefreshComponentStateCoreAsync(
                kind,
                _operationCancellation.Token);

            RenderCard(kind);
            SetOverallStatus(
                result.Message,
                BrushFromHex("#5CFF94"));
        }
        catch (OperationCanceledException)
        {
            SetOverallStatus(
                "Rollback отменён.",
                MediaBrushes.Goldenrod);
        }
        catch (Exception ex)
        {
            await RefreshComponentStateCoreBestEffortAsync(kind);
            RenderCard(kind);
            SetOverallStatus(
                $"Rollback {GetDisplayName(kind)} не завершён: {ex.Message}",
                MediaBrushes.OrangeRed);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task RefreshComponentStateCoreAsync(
        RelayComponentKind kind,
        CancellationToken cancellationToken)
    {
        Task<RelayComponentSnapshot> snapshotTask =
            _componentManager.InspectAsync(kind, cancellationToken);
        Task<RelayComponentStagingSnapshot> stagingTask =
            _componentManager.InspectStagingAsync(kind, cancellationToken);
        Task<RelayComponentBackupSnapshot> backupTask =
            _componentManager.InspectBackupAsync(kind, cancellationToken);

        await Task.WhenAll(
            snapshotTask,
            stagingTask,
            backupTask);

        _snapshots[kind] = await snapshotTask;
        _staging[kind] = await stagingTask;
        _backups[kind] = await backupTask;
    }

    private async Task RefreshComponentStateCoreBestEffortAsync(
        RelayComponentKind kind)
    {
        try
        {
            await RefreshComponentStateCoreAsync(
                kind,
                CancellationToken.None);
        }
        catch
        {
            // Preserve the original install/rollback error in the status bar.
        }
    }

    private string BuildComponentStatusText(
        RelayComponentKind kind)
    {
        string displayName =
            GetDisplayName(kind);

        if (!_snapshots.TryGetValue(
                kind,
                out RelayComponentSnapshot? snapshot))
        {
            string unavailableText =
                $"{displayName}: локальная проверка ещё не завершена.";

            _summaryChanged?.Invoke(unavailableText);
            return unavailableText;
        }

        string text =
            snapshot.Health switch
            {
                RelayComponentHealth.Missing =>
                    $"{displayName}: компонент не найден.",

                RelayComponentHealth.Failed =>
                    $"{displayName}: локальная проверка не пройдена.",

                RelayComponentHealth.Warning =>
                    $"{displayName}: локальная проверка завершена с предупреждением.",

                _ =>
                    $"{displayName} прошёл локальную проверку."
            };

        if (_releases.TryGetValue(
                kind,
                out RelayComponentReleaseInfo? release))
        {
            if (RelayComponentManager.IsUpdateAvailable(
                    snapshot.InstalledVersion,
                    release.NormalizedVersion))
            {
                text +=
                    $" Доступен официальный стабильный релиз {release.TagName}.";
            }
            else if (RelayComponentManager.IsInstalledVersionNewer(
                         snapshot.InstalledVersion,
                         release.NormalizedVersion))
            {
                text +=
                    " Установленная версия новее официального stable-релиза.";
            }
            else
            {
                text +=
                    " Новых официальных стабильных релизов не обнаружено.";
            }
        }
        else
        {
            text +=
                " Официальный релиз этой кнопкой не проверялся.";
        }

        if (_staging.TryGetValue(
                kind,
                out RelayComponentStagingSnapshot? staging))
        {
            if (staging.Ready)
            {
                text +=
                    $" Staging подготовлен: {staging.TagName ?? staging.NormalizedVersion ?? "версия не определена"}.";
            }
            else if (staging.Exists)
            {
                text +=
                    " Staging требует очистки.";
            }
        }

        if (_backups.TryGetValue(
                kind,
                out RelayComponentBackupSnapshot? backup))
        {
            if (backup.Ready)
            {
                text +=
                    $" Rollback доступен: {backup.PreviousVersion ?? "версия не определена"}.";
            }
            else if (backup.Exists)
            {
                text +=
                    " Rollback backup повреждён.";
            }
        }

        _summaryChanged?.Invoke(text);
        return text;
    }

    private MediaBrush BuildComponentStatusBrush(
        RelayComponentKind kind)
    {
        if (_backups.TryGetValue(
                kind,
                out RelayComponentBackupSnapshot? backup) &&
            backup.Exists &&
            !backup.Ready)
        {
            return MediaBrushes.OrangeRed;
        }

        if (_staging.TryGetValue(
                kind,
                out RelayComponentStagingSnapshot? staging) &&
            staging.Exists &&
            !staging.Ready)
        {
            return MediaBrushes.OrangeRed;
        }

        if (!_snapshots.TryGetValue(
                kind,
                out RelayComponentSnapshot? snapshot))
        {
            return MediaBrushes.Goldenrod;
        }

        if (snapshot.Health is
            RelayComponentHealth.Missing or
            RelayComponentHealth.Failed)
        {
            return MediaBrushes.OrangeRed;
        }

        bool hasUpdate =
            _releases.TryGetValue(
                kind,
                out RelayComponentReleaseInfo? release) &&
            RelayComponentManager.IsUpdateAvailable(
                snapshot.InstalledVersion,
                release.NormalizedVersion);

        if (hasUpdate ||
            snapshot.Health == RelayComponentHealth.Warning)
        {
            return MediaBrushes.Goldenrod;
        }

        return BrushFromHex("#5CFF94");
    }

    private string BuildSummaryText()
    {
        if (_snapshots.Count < 2)
            return "Локальная инвентаризация компонентов ещё не завершена.";

        int failed = _snapshots.Values.Count(snapshot =>
            snapshot.Health is RelayComponentHealth.Missing or RelayComponentHealth.Failed);
        int warnings = _snapshots.Values.Count(snapshot =>
            snapshot.Health == RelayComponentHealth.Warning);
        int updates = _snapshots.Values.Count(snapshot =>
            _releases.TryGetValue(snapshot.Kind, out RelayComponentReleaseInfo? release) &&
            RelayComponentManager.IsUpdateAvailable(
                snapshot.InstalledVersion,
                release.NormalizedVersion));

        string text = failed > 0
            ? $"Проблемных компонентов: {failed}."
            : warnings > 0
                ? $"Компоненты доступны, предупреждений: {warnings}."
                : "sing-box и Xray Core прошли локальную проверку.";

        if (_releases.Count == 2)
        {
            text += updates > 0
                ? $" Официальных стабильных релизов новее: {updates}."
                : " Новых официальных стабильных релизов не обнаружено.";
        }
        else
        {
            text += " Проверка официальных релизов ещё не выполнена.";
        }

        int stagedReady = _staging.Values.Count(item => item.Ready);
        int stagedInvalid = _staging.Values.Count(item => item.Exists && !item.Ready);

        if (stagedReady > 0)
            text += $" Подготовлено в staging: {stagedReady}.";

        if (stagedInvalid > 0)
            text += $" Staging требует очистки: {stagedInvalid}.";

        int rollbackReady = _backups.Values.Count(item => item.Ready);
        int rollbackInvalid = _backups.Values.Count(item => item.Exists && !item.Ready);

        if (rollbackReady > 0)
            text += $" Rollback доступен: {rollbackReady}.";

        if (rollbackInvalid > 0)
            text += $" Повреждённых rollback backup: {rollbackInvalid}.";

        _summaryChanged?.Invoke(text);
        return text;
    }

    private MediaBrush BuildSummaryBrush()
    {
        if (_backups.Values.Any(item => item.Exists && !item.Ready))
            return MediaBrushes.OrangeRed;

        if (_staging.Values.Any(item => item.Exists && !item.Ready))
            return MediaBrushes.OrangeRed;

        if (_snapshots.Values.Any(snapshot =>
                snapshot.Health is RelayComponentHealth.Missing or RelayComponentHealth.Failed))
        {
            return MediaBrushes.OrangeRed;
        }

        bool hasUpdate = _snapshots.Values.Any(snapshot =>
            _releases.TryGetValue(snapshot.Kind, out RelayComponentReleaseInfo? release) &&
            RelayComponentManager.IsUpdateAvailable(
                snapshot.InstalledVersion,
                release.NormalizedVersion));

        if (hasUpdate || _snapshots.Values.Any(snapshot =>
                snapshot.Health == RelayComponentHealth.Warning))
        {
            return MediaBrushes.Goldenrod;
        }

        return BrushFromHex("#5CFF94");
    }

    private void SetOverallStatus(string message, MediaBrush brush)
    {
        OverallStatusTextBlock.Text = message;
        OverallStatusTextBlock.Foreground = brush;
        OverallStatusIndicator.Fill = brush;
        OverallStatusBorder.BorderBrush = brush;
    }

    private bool TryBeginOperation(string statusText)
    {
        if (_busy)
            return false;

        _busy = true;
        _operationCancellation = new CancellationTokenSource();
        RefreshLocalButton.IsEnabled = false;
        CheckUpdatesButton.IsEnabled = false;
        AutoCheckRelayComponentsCheckBox.IsEnabled = false;
        SingBoxStageButton.IsEnabled = false;
        XrayStageButton.IsEnabled = false;
        SingBoxDeleteStageButton.IsEnabled = false;
        XrayDeleteStageButton.IsEnabled = false;
        SingBoxInstallButton.IsEnabled = false;
        XrayInstallButton.IsEnabled = false;
        SingBoxRollbackButton.IsEnabled = false;
        XrayRollbackButton.IsEnabled = false;
        SetOverallStatus(statusText, BrushFromHex("#9AD8FF"));
        return true;
    }

    private void EndOperation()
    {
        _operationCancellation?.Dispose();
        _operationCancellation = null;
        _busy = false;
        RefreshLocalButton.IsEnabled = true;
        CheckUpdatesButton.IsEnabled = true;
        AutoCheckRelayComponentsCheckBox.IsEnabled = true;
        RenderAll();
    }

    private void CancelCurrentOperation()
    {
        try
        {
            _operationCancellation?.Cancel();
        }
        catch
        {
            // Ignore cancellation races while the window is closing.
        }
    }

    private void AutoCheckRelayComponents_Changed(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings)
            return;

        _settings.AutoCheckRelayComponents =
            AutoCheckRelayComponentsCheckBox.IsChecked == true;
        _settings.Save();
    }

    private void ApplyLastCheckText()
    {
        LastCheckTextBlock.Text = _settings.LastRelayComponentCheckUtc is DateTimeOffset check
            ? $"Последняя проверка: {check.ToLocalTime():dd.MM.yyyy HH:mm}"
            : "Последняя проверка: ещё не выполнялась";
    }

    private static string GetDisplayName(RelayComponentKind kind) =>
        kind == RelayComponentKind.SingBox ? "sing-box" : "Xray Core";

    private static MediaBrush BrushFromHex(string value) =>
        (MediaBrush)new MediaBrushConverter().ConvertFromString(value)!;

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
            return;

        try
        {
            DragMove();
        }
        catch (InvalidOperationException)
        {
            // The button may have been released before DragMove started.
        }
    }

    private void Window_KeyDown(object sender, InputKeyEventArgs e)
    {
        if (e.Key != InputKey.Escape)
            return;

        e.Handled = true;
        Close();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
