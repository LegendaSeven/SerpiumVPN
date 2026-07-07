using System;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

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

            MainWindow mainWindow = new MainWindow();
            MainWindow = mainWindow;
            mainWindow.Show();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _shutdownCts?.Cancel();
            _showWindowEvent?.Set();
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
