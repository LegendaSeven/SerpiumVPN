using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using SerpiumVPN.Relay;
using SerpiumVPN.Relay.Components;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Lifecycle;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.ProfileVault;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Providers.Avo;
using SerpiumVPN.Relay.Routing;
using SerpiumVPN.Relay.SingBox;
using SerpiumVPN.Relay.Xray;
using SerpiumVPN.UI;
using Forms = System.Windows.Forms;

namespace SerpiumVPN;

public partial class MainWindow : Window
{
    private readonly UserRuntimeSettings _settings = UserRuntimeSettings.Load();
    private readonly AppUpdateManager _appUpdateManager = new();
    private readonly SerpiumParser _serpiumParser = new();
    private readonly ProviderEnvelopeAdapterRegistry _providerEnvelopeAdapters = new();
    private readonly SecureProfileVault _secureProfileVault = new();
    private readonly SecureRoutingRegistry _secureRoutingRegistry = new();
    private readonly SecureRoutingRuleSetRuntime _routingRuleSetRuntime = new() { FullTunnelWhenEmpty = false };
    private readonly SerpiumSingBoxValidationService _singBoxValidationService = new();
    private readonly SerpiumSingBoxSessionManager _serpiumSingBoxSessionManager = new();
    private readonly SecureXraySessionManager _serpiumXraySessionManager = new();
    private readonly RelayComponentManager _relayComponentManager = new();
    private readonly DispatcherTimer _relayLifecycleTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private IReadOnlyList<RoutingRegistryEntry> _routingRegistryEntries = [];
    private IReadOnlyList<SecureProfileVaultEntry> _savedProfileEntries = [];
    private SerpiumConnectionProfile? _validatedRelayProfile;
    private ProviderRuntimeProfile? _validatedProviderRuntimeProfile;
    private Guid? _activeSavedProfileId;
    private bool _activeSavedProfileUsesRoutingTun;
    private Forms.NotifyIcon? _trayIcon;
    private bool _isRealExit;
    private bool _shutdownStarted;
    private bool _shutdownCompleted;
    private TaskCompletionSource? _activeOperationCompletion;
    private TaskCompletionSource? _startupCompletion;

    public MainWindow()
    {
        InitializeAppearance();
        InitializeComponent();
        SimpleHome.SetTheme(_appearanceTheme);
        SimpleHome.ThemeToggleRequested += ThemeToggleRequested;
        _providerEnvelopeAdapters.Register(new AvoBareKeyProviderAdapter());
        _serpiumXraySessionManager.StateChanged += _ => SafeDispatcherInvoke(UpdateSimpleConnectionState);
        _serpiumSingBoxSessionManager.StateChanged += _ => SafeDispatcherInvoke(UpdateSimpleConnectionState);
        _serpiumXraySessionManager.LogReceived += line => _simpleConnectionLog?.Write(line);
        _relayLifecycleTimer.Tick += RelayLifecycleTimer_TickAsync;
        SourceInitialized += (_, _) => UpdateTitleBarTheme();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        InitializeSimpleHome();
        InitializeTrayIcon();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _startupCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await RelayLifecycleRecovery.CleanupOwnedRuntimeAsync(AppContext.BaseDirectory, _simpleLifetime.Token);
            await LoadSimpleHomeAsync();
            if (_simpleLifetime.IsCancellationRequested) return;
            _relayLifecycleTimer.Start();
            if (_settings.AutoCheckRelayComponents) _ = CheckSimpleComponentUpdatesAsync(false);
            if (_settings.AutoUpdateProgram) _ = CheckAppUpdatesAsync();
        }
        catch (OperationCanceledException) when (_simpleLifetime.IsCancellationRequested) { }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            SimpleHome.SetMessage("Не удалось подготовить VPN. Перезапустите приложение.", true);
        }
        finally { _startupCompletion.TrySetResult(); _startupCompletion = null; }
    }

    private async Task ConnectSavedProfileAsync(Guid profileId, CancellationToken cancellationToken)
    {
        var entry = _savedProfileEntries.FirstOrDefault(item => item.Id == profileId)
            ?? throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
        await StopActiveSavedProfileAsync();
        try
        {
            _routingRegistryEntries = (await _secureRoutingRegistry.ListAsync(cancellationToken))
                .Where(item => item.Kind == RoutingTargetKind.Application).ToArray();
            bool isXray = string.Equals(entry.Engine, "xray", StringComparison.OrdinalIgnoreCase);
            var policy = await _routingRuleSetRuntime.UpdateAsync(_routingRegistryEntries, isXray, cancellationToken);
            string relayDirectory = Path.Combine(AppContext.BaseDirectory, "bin_files", "relay");
            if (isXray)
            {
                var saved = await _secureProfileVault.OpenXrayProfileAsync(profileId, cancellationToken);
                _validatedRelayProfile = saved.Profile;
                await _serpiumXraySessionManager.StartAsync(Path.Combine(relayDirectory, "xray.exe"),
                    Path.Combine(relayDirectory, "configs", "key-client.json"), saved.Profile, saved.SocksPort, cancellationToken);
                _validatedProviderRuntimeProfile = SerpiumRoutingConfigCompiler.BuildXrayBridgeProfile(
                    profileId, saved.SocksPort, _routingRegistryEntries, _routingRuleSetRuntime.RuleSetPath);
            }
            else
            {
                using var saved = await _secureProfileVault.OpenProviderProfileAsync(profileId, cancellationToken);
                _validatedProviderRuntimeProfile = SerpiumRoutingConfigCompiler.CompileProviderProfile(
                    saved, _routingRegistryEntries, _routingRuleSetRuntime.RuleSetPath, applicationSelectionOnly: true);
            }
            string singBox = Path.Combine(relayDirectory, "sing-box.exe");
            var check = await _singBoxValidationService.ValidateAsync(singBox, _validatedProviderRuntimeProfile, cancellationToken);
            if (!check.Success) throw new InvalidOperationException(check.Message);
            // Start waits for the interface and a successful HTTPS probe through this profile.
            await _serpiumSingBoxSessionManager.StartAsync(singBox, _validatedProviderRuntimeProfile, cancellationToken);
            await _serpiumSingBoxSessionManager.WaitForRoutingPolicyAsync(policy.ActivationProbe, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            _activeSavedProfileUsesRoutingTun = true;
            _activeSavedProfileId = profileId;
        }
        catch
        {
            await StopSimpleTransportsSafelyAsync();
            throw;
        }
    }

    private async Task StopActiveSavedProfileAsync()
    {
        List<Exception> errors = [];
        try { await _serpiumSingBoxSessionManager.StopAsync(); } catch (Exception error) { errors.Add(error); }
        try { await _serpiumXraySessionManager.StopAsync(); } catch (Exception error) { errors.Add(error); }
        try { await RelayLifecycleRecovery.CleanupOwnedRuntimeAsync(AppContext.BaseDirectory); }
        catch (Exception error) { errors.Add(error); }
        _activeSavedProfileId = null;
        _activeSavedProfileUsesRoutingTun = false;
        _validatedRelayProfile = null;
        DisposeValidatedProviderRuntimeProfile();
        _routingRuleSetRuntime.DeleteBestEffort();
        if (_serpiumSingBoxSessionManager.HasLiveProcess || _serpiumXraySessionManager.HasLiveProcess)
            errors.Add(new IOException("VPN process is still running after stop."));
        if (errors.Count > 0) throw new AggregateException(errors);
    }

    private Task StopAllRelayTransportsBestEffortAsync() => StopActiveSavedProfileAsync();

    private void DisposeValidatedProviderRuntimeProfile()
    {
        _validatedProviderRuntimeProfile?.Dispose();
        _validatedProviderRuntimeProfile = null;
    }

    private async Task RefreshSecureProfileVaultStatusAsync()
    {
        _savedProfileEntries = await _secureProfileVault.ListProfilesAsync(_simpleLifetime.Token);
        RenderSimpleProfiles();
    }

    private async void RelayLifecycleTimer_TickAsync(object? sender, EventArgs e)
    {
        if (_simpleBusy || _shutdownStarted || !_activeSavedProfileId.HasValue || SimpleConnected) return;
        SetSimpleBusy(true, "Отключение…");
        try
        {
            await StopSimpleTransportsSafelyAsync();
            _simpleWasConnected = false;
            SimpleHome.SetMessage("Соединение прервано. Нажмите «Подключиться».", true);
        }
        finally { SetSimpleBusy(false); }
    }

    private async Task CheckAppUpdatesAsync()
    {
        try
        {
            var result = await _appUpdateManager.CheckDownloadAndApplyAsync(null, _simpleLifetime.Token);
            if (result.Status != AppUpdateCheckStatus.ReadyToRestart || _simpleLifetime.IsCancellationRequested) return;
            if (_simpleBusy || SimpleConnected) return;
            if (System.Windows.MessageBox.Show(this, "Обновление Serpium готово. Установить и перезапустить?",
                "Обновление", MessageBoxButton.YesNo, MessageBoxImage.Information) != MessageBoxResult.Yes) return;
            // Reserve the UI before the first await so a new connection cannot race the restart.
            _shutdownStarted = true;
            await PrepareForExitAsync();
            _isRealExit = _shutdownCompleted = true;
            _appUpdateManager.RestartAndApply();
        }
        catch (OperationCanceledException) when (_simpleLifetime.IsCancellationRequested) { }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            if (_shutdownStarted) { _isRealExit = _shutdownCompleted = true; Close(); }
        }
    }

    private void SafeDispatcherInvoke(Action action)
    {
        if (_shutdownCompleted || Dispatcher.HasShutdownStarted) return;
        if (Dispatcher.CheckAccess()) action();
        else Dispatcher.BeginInvoke(() => { if (!_shutdownCompleted) action(); });
    }

    private void UpdateTitleBarTheme()
    {
        int dark = _appearanceTheme == AppTheme.Midnight ? 1 : 0;
        IntPtr handle = new WindowInteropHelper(this).Handle;
        if (handle != IntPtr.Zero && DwmSetWindowAttribute(handle, 20, ref dark, sizeof(int)) != 0)
            DwmSetWindowAttribute(handle, 19, ref dark, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private void InitializeTrayIcon()
    {
        System.Drawing.Icon trayIcon;
        try
        {
            using var stream = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/SerpiumVPN;component/Assets/Serpium.App.ico"))?.Stream
                ?? throw new IOException("The embedded tray icon is unavailable.");
            using var source = new System.Drawing.Icon(stream);
            trayIcon = (System.Drawing.Icon)source.Clone();
        }
        catch (Exception error) when (error is IOException or ArgumentException or InvalidOperationException)
        {
            LogSimpleFailure(error);
            // A damaged optional tray image must not prevent the main window from opening.
            trayIcon = (System.Drawing.Icon)System.Drawing.SystemIcons.Application.Clone();
        }
        _trayIcon = new Forms.NotifyIcon { Text = "Serpium VPN", Icon = trayIcon, Visible = true };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => ShowFromTray());
        menu.Items.Add("Выход", null, (_, _) => { _isRealExit = true; Close(); });
        _trayIcon.ContextMenuStrip = menu;
        _trayIcon.DoubleClick += (_, _) => ShowFromTray();
    }

    public void ShowFromTray()
    {
        if (_shutdownStarted) return;
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    private async void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_shutdownCompleted) return;
        e.Cancel = true;
        if (!_isRealExit) { Hide(); return; }
        if (_shutdownStarted) return;
        _shutdownStarted = true;
        try { await PrepareForExitAsync(); }
        catch (Exception error) { LogSimpleFailure(error); }
        finally { _shutdownCompleted = true; Close(); }
    }

    private async Task PrepareForExitAsync()
    {
        _simpleReady = false;
        _simpleDiscoveryTimer.Stop();
        _relayLifecycleTimer.Stop();
        _componentUpdateTimer.Stop();
        _simpleLifetime.Cancel();
        _simpleConnectCancellation?.Cancel();
        SimpleHome.ClearKey();
        UpdateSimpleConnectionState();
        if (_activeOperationCompletion is { } pending) await pending.Task;
        if (_startupCompletion is { } startup) await startup.Task;
        if (_simpleDiscoveryCompletion is { } discovery) await discovery.Task;
        if (_componentCheckCompletion is { } components) await components.Task;
        await StopSimpleTransportsSafelyAsync();
        _simpleDiscovery.Dispose();
        _serpiumSingBoxSessionManager.Dispose();
        _serpiumXraySessionManager.Dispose();
        _relayComponentManager.Dispose();
        if (_trayIcon is { } tray)
        {
            tray.Visible = false;
            tray.ContextMenuStrip?.Dispose();
            tray.Icon?.Dispose();
            tray.Dispose();
            _trayIcon = null;
        }
    }
}
