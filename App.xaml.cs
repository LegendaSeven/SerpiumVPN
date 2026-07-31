using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SerpiumVPN.Core;

namespace SerpiumVPN
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : System.Windows.Application
    {
        private const string SingleInstanceMutexName = "Local\\SerpiumVPN.SingleInstance";
        private const string ShowWindowEventName = "Local\\SerpiumVPN.ShowWindow";

        private Mutex? _singleInstanceMutex;
        private EventWaitHandle? _showWindowEvent;
        private CancellationTokenSource? _shutdownCts;
        private bool _ownsSingleInstanceMutex;

        private PlatformRuntime? _platformRuntime;
        private PlatformFileLogger? _platformLogger;
        private Task? _platformStartupTask;

        protected override void OnStartup(StartupEventArgs e)
        {
            _singleInstanceMutex = CreateSingleInstanceMutex(out bool createdNew);
            _ownsSingleInstanceMutex = createdNew;

            if (!createdNew)
            {
                SignalExistingInstance();
                Shutdown();
                return;
            }

            base.OnStartup(e);

            _shutdownCts = new CancellationTokenSource();
            _showWindowEvent = CreateShowWindowEvent();
            StartShowWindowListener(_shutdownCts.Token);

            InitializePlatformRuntime(_shutdownCts.Token);

            MainWindow mainWindow = new MainWindow();
            MainWindow = mainWindow;
            mainWindow.Show();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _shutdownCts?.Cancel();
            _showWindowEvent?.Set();

            WaitForPlatformStartup();
            StopPlatformRuntimeSafely();

            // Final safety net for embedded Relay processes.
            StopEmbeddedRelayProcesses();

            _showWindowEvent?.Dispose();

            if (_ownsSingleInstanceMutex)
            {
                try
                {
                    _singleInstanceMutex?.ReleaseMutex();
                }
                catch (ApplicationException)
                {
                    // The mutex was not owned by this process anymore. Ignore on shutdown.
                }
            }

            _singleInstanceMutex?.Dispose();
            _singleInstanceMutex = null;
            _ownsSingleInstanceMutex = false;

            _shutdownCts?.Dispose();
            _shutdownCts = null;

            base.OnExit(e);
        }

        private void InitializePlatformRuntime(CancellationToken cancellationToken)
        {
            try
            {
                _platformLogger = PlatformFileLogger.CreateDefault();
                _platformLogger.Write("[App] SerpiumVPN process started.");

                _platformRuntime = PlatformBootstrap.Create(
                    log: _platformLogger.Write);

                PlatformRuntimeHost.Attach(_platformRuntime);

                _platformStartupTask = StartPlatformRuntimeAsync(
                    _platformRuntime,
                    cancellationToken);
            }
            catch (Exception exception)
            {
                WritePlatformLog(
                    $"[App] Runtime bootstrap failed: {exception.GetType().Name}: {exception.Message}");
            }
        }

        private async Task StartPlatformRuntimeAsync(
            PlatformRuntime runtime,
            CancellationToken cancellationToken)
        {
            try
            {
                PlatformRuntimeStartResult result = await runtime
                    .StartAsync(cancellationToken)
                    .ConfigureAwait(false);

                WritePlatformLog(
                    $"[App] Runtime startup result: State={result.State}; " +
                    $"Components={result.Components.Loaded}/{result.Components.Found}; " +
                    $"EnginePackages={result.DynamicEngines.Loaded}/{result.DynamicEngines.Found}; " +
                    $"Failures={result.DynamicEngines.Failed}.");
            }
            catch (OperationCanceledException)
            {
                WritePlatformLog("[App] Runtime startup was cancelled during application shutdown.");
            }
            catch (Exception exception)
            {
                // Runtime activation must not prevent the WPF shell from opening.
                WritePlatformLog(
                    $"[App] Runtime startup failed: {exception.GetType().Name}: {exception.Message}");
            }
        }

        private void WaitForPlatformStartup()
        {
            Task? startupTask = _platformStartupTask;
            _platformStartupTask = null;

            if (startupTask is null)
                return;

            try
            {
                startupTask.GetAwaiter().GetResult();
            }
            catch (Exception exception)
            {
                WritePlatformLog(
                    $"[App] Runtime startup wait failed: {exception.GetType().Name}: {exception.Message}");
            }
        }

        private void StopPlatformRuntimeSafely()
        {
            PlatformRuntime? runtime = _platformRuntime;
            _platformRuntime = null;

            if (runtime is null)
                return;

            try
            {
                runtime.StopAsync().GetAwaiter().GetResult();
            }
            catch (Exception exception)
            {
                WritePlatformLog(
                    $"[App] Runtime shutdown failed: {exception.GetType().Name}: {exception.Message}");
            }

            try
            {
                runtime.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            catch (Exception exception)
            {
                WritePlatformLog(
                    $"[App] Runtime dispose failed: {exception.GetType().Name}: {exception.Message}");
            }
            finally
            {
                PlatformRuntimeHost.Detach(runtime);
            }

            WritePlatformLog("[App] SerpiumVPN process is exiting.");
        }

        private void WritePlatformLog(string message)
        {
            _platformLogger?.Write(message);
        }

        private static void StopEmbeddedRelayProcesses()
        {
            string relayDirectoryName = Path.Combine("bin_files", "relay");

            foreach (Process process in Process.GetProcessesByName("xray"))
            {
                try
                {
                    string? executablePath = process.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(executablePath))
                        continue;

                    if (!executablePath.Contains(
                            relayDirectoryName,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(3000);
                }
                catch
                {
                    // Relay cleanup must never block application shutdown.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        private void StartShowWindowListener(CancellationToken cancellationToken)
        {
            if (_showWindowEvent == null)
                return;

            Task.Run(() =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    _showWindowEvent.WaitOne();
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    Dispatcher.BeginInvoke(() =>
                    {
                        if (MainWindow is MainWindow mainWindow)
                            mainWindow.ShowFromTray();
                    });
                }
            }, cancellationToken);
        }

        private static Mutex CreateSingleInstanceMutex(out bool createdNew)
        {
            SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            MutexSecurity security = new MutexSecurity();
            security.AddAccessRule(new MutexAccessRule(
                everyone,
                MutexRights.FullControl,
                AccessControlType.Allow
            ));

            return MutexAcl.Create(initiallyOwned: true, SingleInstanceMutexName, out createdNew, security);
        }

        private static EventWaitHandle CreateShowWindowEvent()
        {
            SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            EventWaitHandleSecurity security = new EventWaitHandleSecurity();
            security.AddAccessRule(new EventWaitHandleAccessRule(
                everyone,
                EventWaitHandleRights.FullControl,
                AccessControlType.Allow
            ));

            return EventWaitHandleAcl.Create(
                initialState: false,
                mode: EventResetMode.AutoReset,
                name: ShowWindowEventName,
                createdNew: out _,
                eventSecurity: security
            );
        }

        private static void SignalExistingInstance()
        {
            try
            {
                using EventWaitHandle showWindowEvent = EventWaitHandle.OpenExisting(ShowWindowEventName);
                showWindowEvent.Set();
            }
            catch
            {
                // If the existing process is shutting down, there is nothing useful to signal.
            }
        }
    }
}
