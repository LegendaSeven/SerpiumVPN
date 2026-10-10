using System.IO;
using System.Windows;
using System.Windows.Threading;
using SerpiumVPN.Relay;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.ProfileVault;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Routing;
using SerpiumVPN.UI;

namespace SerpiumVPN;

public partial class MainWindow
{
    private readonly InstalledApplicationDiscovery _simpleDiscovery = new();
    private readonly CancellationTokenSource _simpleLifetime = new();
    private CancellationTokenSource? _simpleConnectCancellation;
    private readonly DispatcherTimer _simpleDiscoveryTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private IReadOnlyList<DiscoveredApplication> _simpleApplications = Array.Empty<DiscoveredApplication>();
    private bool _simpleDiscoveryBusy;
    private TaskCompletionSource? _simpleDiscoveryCompletion;
    private bool _simpleBusy;
    private bool _simpleReady;
    private string? _simpleActivity;
    private Guid? _simpleProfileId;
    private int _simpleMessageVersion;
    private bool _simpleWasConnected;
    private ConnectionFileLogger? _simpleConnectionLog;
    private readonly ProfileSelectionStore _simpleProfileSelection = new();

    private bool SimpleConnected => _activeSavedProfileId.HasValue &&
        _activeSavedProfileUsesRoutingTun && _serpiumSingBoxSessionManager.HasLiveProcess &&
        _serpiumSingBoxSessionManager.State == RelayGatewayState.Running &&
        (_validatedRelayProfile is null || (_serpiumXraySessionManager.HasLiveProcess && _serpiumXraySessionManager.State == RelayGatewayState.Running));

    private void InitializeSimpleHome()
    {
        InitializeSimpleComponentUpdates();
        try
        {
            _simpleConnectionLog = new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"SerpiumVPN","Logs","connection-errors.log"));
            _simpleConnectionLog.Write("Connection diagnostics enabled.");
            _serpiumSingBoxSessionManager.LogReceived += line =>
            {
                if (line.Contains("ERROR",StringComparison.OrdinalIgnoreCase) || line.Contains("WARN",StringComparison.OrdinalIgnoreCase))
                    _simpleConnectionLog?.Write(SensitiveDiagnosticRedactor.RedactText(line));
            };
        }
        catch { /* Diagnostics must not prevent the main screen from opening. */ }
        SimpleHome.ConnectRequested += SimpleConnectRequested;
        SimpleHome.ProfileSelectionRequested += SimpleProfileSelected;
        SimpleHome.ProfilesDeleteRequested += SimpleProfilesDeleteRequested;
        SimpleHome.ApplicationRouteRequested += SimpleApplicationRouteRequested;
        SimpleHome.ManualApplicationAddRequested += SimpleManualApplicationAddRequested;
        SimpleHome.ManualApplicationDeleteRequested += SimpleManualApplicationDeleteRequested;
        SimpleHome.WebsiteAddRequested += SimpleWebsiteAddRequested;
        SimpleHome.WebsiteRouteRequested += SimpleWebsiteRouteRequested;
        SimpleHome.WebsiteDeleteRequested += id => SimpleDeleteRouteRequested(id, RoutingTargetKind.Website);
        _serpiumSingBoxSessionManager.ActiveConnectionsChanged += snapshot =>
            _simpleDiscovery.ObserveInternetApplications(snapshot.Connections.Where(connection => connection.UsesInternet).Select(connection => connection.ProcessPath));
        _simpleDiscoveryTimer.Tick += async (_, _) => await RefreshSimpleApplicationsAsync();
    }

    private async Task LoadSimpleHomeAsync()
    {
        try
        {
            // Reading again is intentional: a failed read must not be treated as an empty policy.
            _routingRegistryEntries = (await _secureRoutingRegistry.ListAsync()).ToArray();
            _savedProfileEntries = await _secureProfileVault.ListProfilesAsync(_simpleLifetime.Token);
            _simpleProfileId = _simpleProfileSelection.Load(_savedProfileEntries.Select(item => item.Id));
            RenderSimpleProfiles();
            _simpleReady = true;
            RenderSimpleApplications();
            UpdateSimpleConnectionState();
            await RefreshSimpleApplicationsAsync();
            _simpleDiscoveryTimer.Start();
        }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            SimpleHome.SetMessage("Не удалось загрузить настройки. Перезапустите приложение.", true);
        }
    }

    private void RenderSimpleProfiles()
    {
        if (_simpleProfileId.HasValue && !_savedProfileEntries.Any(entry => entry.Id == _simpleProfileId))
            _simpleProfileId = null;
        SimpleHome.SetProfiles(_savedProfileEntries.Select(entry => new SimpleProfileItem(entry.Id, entry.SelectionDisplayName)), _simpleProfileId);
    }

    private void SimpleProfileSelected(Guid? id)
    {
        if (_simpleBusy || !_simpleReady || SimpleConnected) return;
        _simpleProfileId = id.HasValue && _savedProfileEntries.Any(entry => entry.Id == id) ? id : null;
        _simpleMessageVersion++;
        if (!_simpleProfileSelection.TrySave(_simpleProfileId))
            SimpleHome.SetMessage("Выбор действует сейчас, но не сохранился для следующего запуска.", true);
        UpdateSimpleConnectionState();
    }

    private async void SimpleProfilesDeleteRequested(IReadOnlyList<Guid> requested)
    {
        Guid[] ids = requested.Distinct().ToArray();
        if (_simpleBusy || !_simpleReady || SimpleConnected || ids.Length == 0 ||
            ids.Any(id => _activeSavedProfileId == id || !_savedProfileEntries.Any(entry => entry.Id == id))) return;
        SetSimpleBusy(true, "Удаление…");
        try
        {
            int removed = await _secureProfileVault.DeleteProfilesAsync(ids, _simpleLifetime.Token);
            if (_simpleProfileId.HasValue && ids.Contains(_simpleProfileId.Value))
            {
                _simpleProfileId = null;
                _simpleProfileSelection.TrySave(null);
                SimpleHome.ClearKey();
            }
            _savedProfileEntries = await _secureProfileVault.ListProfilesAsync(_simpleLifetime.Token);
            RenderSimpleProfiles();
            await RefreshSecureProfileVaultStatusAsync();
            ShowSimpleConfirmation(removed == 1 ? "Профиль удалён" : $"Удалено профилей: {removed}");
        }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            SimpleHome.SetMessage("Не удалось удалить профили. Повторите попытку.", true);
        }
        finally { SetSimpleBusy(false); }
    }

    private async Task RefreshSimpleApplicationsAsync()
    {
        if (_simpleDiscoveryBusy || _simpleBusy || _simpleLifetime.IsCancellationRequested) return;
        _simpleDiscoveryBusy = true;
        _simpleDiscoveryCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            var discovered = await _simpleDiscovery.DiscoverAsync(_simpleLifetime.Token);
            if (_simpleLifetime.IsCancellationRequested) return;
            _simpleApplications = discovered;
            if (!_simpleBusy)
            {
                foreach (var app in discovered.Where(item => item.ApplicationId.Length > 0))
                {
                    var original = _routingRegistryEntries.FirstOrDefault(item => item.Kind == RoutingTargetKind.Application &&
                        (item.ApplicationId.Equals(app.ApplicationId, StringComparison.OrdinalIgnoreCase) ||
                         (item.ApplicationId.Length == 0 && item.PrimaryValue.Equals(app.ExecutablePath, StringComparison.OrdinalIgnoreCase))));
                    if (original is null) continue;
                    var paths = app.ExecutablePaths.Append(app.ExecutablePath).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    if (original.ApplicationId.Length > 0 && original.PrimaryValue.Equals(app.ExecutablePath, StringComparison.OrdinalIgnoreCase) && paths.SetEquals(original.RelatedExecutables.Append(original.PrimaryValue))) continue;
                    bool changed = await ChangeSimpleRouteAsync(original,
                        async () => await Task.Run(() => _secureRoutingRegistry.RefreshPackagedApplicationAsync(original, app.ToTarget(), _simpleLifetime.Token)),
                        "Приложение обновилось. Выбор VPN сохранён.");
                    if (!changed || _simpleLifetime.IsCancellationRequested) break;
                }
            }
            if (!_simpleBusy) RenderSimpleApplications();
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            SimpleHome.UpdateEmptyState("Не удалось получить список приложений. Повторим автоматически.");
        }
        finally
        {
            _simpleDiscoveryBusy = false;
            _simpleDiscoveryCompletion.TrySetResult();
            _simpleDiscoveryCompletion = null;
        }
    }

    private void RenderSimpleApplications()
    {
        SimpleHome.SetWebsites(_routingRegistryEntries);
        var rows = SimpleHomeView.BuildApplicationRows(_simpleApplications, _routingRegistryEntries);
        // Do not disturb focus or scroll position during background discovery when nothing changed.
        if (SimpleHome.Applications.Select(item => (item.ExecutablePath, item.DisplayName, item.IsManuallyAdded, item.RuleId, item.IsWebApplication, item.ApplicationId, Paths: string.Join('|', item.ExecutablePaths))).SequenceEqual(rows.Select(item => (item.ExecutablePath, item.DisplayName, item.IsManuallyAdded, item.RuleId, item.IsWebApplication, item.ApplicationId, Paths: string.Join('|', item.ExecutablePaths)))))
        {
            for (int i = 0; i < rows.Count; i++) SimpleHome.Applications[i].IsVpnEnabled = rows[i].IsVpnEnabled;
        }
        else
        {
            SimpleHome.Applications.Clear();
            foreach (var row in rows) SimpleHome.Applications.Add(row);
        }
        SimpleHome.UpdateEmptyState();
    }

    private void UpdateSimpleConnectionState()
    {
        if (SimpleHome is null) return;
        bool connected = SimpleConnected;
        if (!_simpleBusy && _simpleWasConnected && !connected)
            SimpleHome.SetMessage("Соединение прервано. Нажмите «Подключиться».", true);
        if (!_simpleBusy) _simpleWasConnected = connected;
        SimpleHome.SetConnectionState(connected, _simpleBusy, _simpleReady, _simpleProfileId.HasValue, _simpleActivity,
            canStop: _simpleConnectCancellation is { IsCancellationRequested: false });
    }

    private void SetSimpleBusy(bool busy, string? activity = null)
    {
        if (busy && !_simpleBusy)
            _activeOperationCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!busy)
        {
            _activeOperationCompletion?.TrySetResult();
            _activeOperationCompletion = null;
        }
        _simpleBusy = busy;
        _simpleActivity = activity;
        _simpleMessageVersion++;
        if (busy) SimpleHome.SetMessage("");
        UpdateSimpleConnectionState();
    }

    private async void SimpleConnectRequested(object? sender, EventArgs args)
    {
        if (_simpleBusy)
        {
            if (_simpleConnectCancellation is { IsCancellationRequested: false } pending)
            {
                // The owning attempt performs cleanup after its work observes cancellation.
                // Never race StopAsync against an in-flight StartAsync.
                pending.Cancel();
                _simpleActivity = "Остановка…";
                UpdateSimpleConnectionState();
            }
            return;
        }
        if (!_simpleReady) return;
        bool disconnect = SimpleConnected;
        using var attempt = disconnect ? null : CancellationTokenSource.CreateLinkedTokenSource(_simpleLifetime.Token);
        _simpleConnectCancellation = attempt;
        CancellationToken cancellationToken = attempt?.Token ?? CancellationToken.None;
        SetSimpleBusy(true, disconnect ? "Отключение…" : "Проверка ключа…");
        try
        {
            if (disconnect)
            {
                await StopActiveSavedProfileAsync();
                _simpleWasConnected = false;
            }
            else
            {
                string key = SimpleHome.Key;
                if (key.Length > 0)
                {
                    if (key.TrimStart().StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        SetSimpleBusy(true, "Загрузка профилей…");
                    _simpleProfileId = await PrepareSimpleProfileAsync(key, cancellationToken);
                    SimpleHome.ClearKey();
                    RenderSimpleProfiles();
                    _simpleProfileSelection.TrySave(_simpleProfileId);
                }
                if (!_simpleProfileId.HasValue)
                    throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
                cancellationToken.ThrowIfCancellationRequested();
                SetSimpleBusy(true, "Проверка соединения…");
                await StartSimpleSavedProfileAsync(_simpleProfileId.Value, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (!_simpleProfileSelection.TrySave(_simpleProfileId))
                    SimpleHome.SetMessage("Соединение активно, но выбор профиля не сохранился для следующего запуска.", true);
                else
                    SimpleHome.SetMessage("Проверка пройдена. Соединение активно.");
            }
        }
        catch (Exception) when (attempt?.IsCancellationRequested == true)
        {
            await StopSimpleTransportsSafelyAsync();
            _activeSavedProfileId = null;
            _validatedRelayProfile = null;
            DisposeValidatedProviderRuntimeProfile();
            _simpleWasConnected = false;
            try
            {
                // Import may have committed just before Stop. Keep that profile available.
                _savedProfileEntries = await _secureProfileVault.ListProfilesAsync();
                RenderSimpleProfiles();
            }
            catch (Exception error) { LogSimpleFailure(error); }
            bool stopped = !_serpiumSingBoxSessionManager.HasLiveProcess && !_serpiumXraySessionManager.HasLiveProcess;
            if (!stopped) _simpleReady = false;
            SimpleHome.SetMessage(stopped && _simpleReady ? "Подключение остановлено." : "Не удалось полностью остановить подключение. Перезапустите приложение.", !stopped || !_simpleReady);
        }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            await StopSimpleTransportsSafelyAsync();
            _simpleWasConnected = false;
            SimpleHome.SetMessage(disconnect ? "Не удалось полностью отключиться. Перезапустите приложение." : ConnectionFeedback.Describe(error), true);
        }
        finally
        {
            _simpleConnectCancellation = null;
            SetSimpleBusy(false);
        }
    }

    private async Task<Guid> PrepareSimpleProfileAsync(string sourceKey, CancellationToken cancellationToken)
    {
        // Key decoding, DPAPI and file ACL work must not block the Stop button.
        Guid firstProfile = await Task.Run(async () =>
        {
            var keys = await new ConnectionKeySourceResolver().ResolveAsync(sourceKey, cancellationToken);
            Guid? first = null;
            foreach (string key in keys)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var parsed = _serpiumParser.Parse(key);
                if (!parsed.Success) throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
                SecureProfileVaultSaveResult imported;
                if (parsed.Envelope is ProviderEnvelope envelope)
                {
                    var adapter = _providerEnvelopeAdapters.Find(envelope.Scheme) ?? throw new ConnectionCheckException(ConnectionFailureKind.UnsupportedKey);
                    var resolved = await adapter.ResolveAsync(envelope, cancellationToken);
                    using ProviderRuntimeProfile profile = resolved.RuntimeProfile ?? throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
                    if (!resolved.Success) throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
                    imported = await _secureProfileVault.SaveProviderProfileAsync(profile, key, cancellationToken);
                }
                else
                {
                    var profile = parsed.Profile ?? throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
                    if (profile.Protocol == "hysteria2")
                    {
                        using var nativeProfile = Hysteria2ProfileFactory.Create(profile);
                        imported = await _secureProfileVault.SaveProviderProfileAsync(nativeProfile, key, cancellationToken);
                    }
                    else imported = await _secureProfileVault.SaveXrayProfileAsync(profile, 10808, key, cancellationToken);
                }
                first ??= imported.Entry.Id;
            }
            return first ?? throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
        }, cancellationToken);
        _savedProfileEntries = await _secureProfileVault.ListProfilesAsync(cancellationToken);
        await RefreshSecureProfileVaultStatusAsync();
        return firstProfile;
    }

    private async Task StartSimpleSavedProfileAsync(Guid id, CancellationToken cancellationToken)
    {
        await ConnectSavedProfileAsync(id, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (!SimpleConnected || _activeSavedProfileId != id)
            throw new ConnectionCheckException(ConnectionFailureKind.ProbeFailed);
    }

    private async void ShowSimpleConfirmation(string message)
    {
        SimpleHome.SetMessage(message);
        // The enclosing operation will increment the version once when it ends.
        int version = _simpleMessageVersion + 1;
        try { await Task.Delay(2200, _simpleLifetime.Token); }
        catch (OperationCanceledException) { return; }
        if (version == _simpleMessageVersion) SimpleHome.SetMessage("");
    }
    private void LogSimpleFailure(Exception error)
    {
        string message = "Simple UI: " + SensitiveDiagnosticRedactor.RedactText(error.Message);
        _simpleConnectionLog?.Write(message);
    }

    private async Task StopSimpleTransportsSafelyAsync()
    {
        try { await StopAllRelayTransportsBestEffortAsync(); }
        catch (Exception error) { LogSimpleFailure(error); _simpleReady = false; }
    }
}
