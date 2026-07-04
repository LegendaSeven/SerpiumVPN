using System;
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

        protected override void OnStartup(StartupEventArgs e)
        {
            _singleInstanceMutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out bool createdNew);
            if (!createdNew)
            {
                SignalExistingInstance();
                Shutdown();
                return;
            }

            base.OnStartup(e);

            _shutdownCts = new CancellationTokenSource();
            _showWindowEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowWindowEventName);
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

            _singleInstanceMutex?.ReleaseMutex();
            _singleInstanceMutex?.Dispose();

            _shutdownCts?.Dispose();
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
