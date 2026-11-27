using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using SerpiumVPN.UI;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;

namespace SerpiumVPN;

public partial class MainWindow
{
    private readonly DispatcherTimer _appUpdateTimer = new() { Interval = TimeSpan.FromHours(6) };
    private CancellationTokenSource? _appUpdateCancellation;
    private TaskCompletionSource? _appUpdateCompletion;
    private bool _appUpdateInstalling;
    private string _appUpdateMessage = "Проверим, доступна ли новая версия.";

    private void InitializeAppUpdates()
    {
        SimpleHome.ProgramUpdateRequested += ProgramUpdateRequested;
        SimpleHome.ProgramUpdateRecheckRequested += async (_, _) => await CheckAppUpdatesAsync();
        SimpleHome.ProgramUpdateCancelRequested += (_, _) => _appUpdateCancellation?.Cancel();
        SimpleHome.AutomaticProgramChecksChanged += enabled =>
        {
            _settings.AutoUpdateProgram = enabled;
            try { _settings.Save(); }
            catch (Exception error) { LogSimpleFailure(error); _appUpdateMessage = "Настройка действует сейчас, но не сохранилась для следующего запуска."; RenderAppUpdate(); }
            if (enabled) _ = CheckAppUpdatesAsync();
        };
        SimpleHome.SetAutomaticProgramChecks(_settings.AutoUpdateProgram);
        _appUpdateTimer.Tick += async (_, _) => { if (_settings.AutoUpdateProgram) await CheckAppUpdatesAsync(); };
        _appUpdateTimer.Start();
        RenderAppUpdate();
    }

    private void RenderAppUpdate(int? progress = null)
    {
        var action = _appUpdateManager.IsReady ? ProgramUpdateAction.Install :
            _appUpdateManager.AvailableUpdate is not null ? ProgramUpdateAction.Download : ProgramUpdateAction.Check;
        SimpleHome.SetProgramUpdateState(_appUpdateManager.CurrentVersion, _appUpdateMessage, action,
            _appUpdateManager.AvailableUpdate is not null, _appUpdateCancellation is not null || _appUpdateInstalling,
            progress, _appUpdateCancellation is { IsCancellationRequested: false });
    }

    private async Task CheckAppUpdatesAsync() => await RunAppUpdateOperationAsync(download: false);

    private async Task RunAppUpdateOperationAsync(bool download)
    {
        if (_appUpdateCancellation is not null || _appUpdateInstalling || _simpleLifetime.IsCancellationRequested) return;
        if (!download && _appUpdateManager.IsReady) return;
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(_simpleLifetime.Token);
        _appUpdateCancellation = attempt;
        _appUpdateCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _appUpdateMessage = download ? "Загрузка обновления: 0%" : "Проверяем новые версии Serpium…";
        RenderAppUpdate(download ? 0 : null);
        try
        {
            if (download)
            {
                var progress = new Progress<int>(value =>
                {
                    if (!ReferenceEquals(_appUpdateCancellation, attempt) || attempt.IsCancellationRequested) return;
                    _appUpdateMessage = value == 100 ? "Проверяем скачанное обновление…" : $"Загрузка обновления: {value}%";
                    RenderAppUpdate(value);
                });
                await _appUpdateManager.DownloadAsync(progress, attempt.Token);
                _appUpdateMessage = $"Версия {_appUpdateManager.AvailableUpdate!.Version} скачана и проверена. Можно установить.";
            }
            else
            {
                var update = await _appUpdateManager.CheckAsync(attempt.Token);
                _appUpdateMessage = update is null ? "Установлена актуальная версия." : $"Доступна версия {update.Version} · {Math.Ceiling(update.Size / 1048576d)} МБ.";
            }
        }
        catch (OperationCanceledException)
        { _appUpdateMessage = attempt.IsCancellationRequested ? "Остановлено. Можно повторить." : "Сервер обновлений не ответил вовремя. Повторите попытку."; }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            _appUpdateMessage = error switch
            {
                HttpRequestException => "Не удалось связаться с GitHub. Проверьте интернет и повторите попытку.",
                InvalidDataException => error.Message,
                UnauthorizedAccessException => "Нет доступа к папке загрузки обновления.",
                IOException => "Не удалось сохранить обновление. Проверьте свободное место и повторите попытку.",
                _ => "Не удалось проверить обновление. Повторите попытку позже."
            };
        }
        finally
        {
            _appUpdateCancellation = null;
            _appUpdateCompletion.TrySetResult(); _appUpdateCompletion = null;
            if (!_simpleLifetime.IsCancellationRequested) RenderAppUpdate();
        }
    }

    private async void ProgramUpdateRequested(object? sender, EventArgs e)
    {
        if (_appUpdateCancellation is not null || _appUpdateInstalling || _shutdownStarted) return;
        if (!_appUpdateManager.IsReady)
        { await RunAppUpdateOperationAsync(_appUpdateManager.AvailableUpdate is not null); return; }
        if (_simpleBusy || !_simpleReady) return;
        string question = $"Установить Serpium {_appUpdateManager.AvailableUpdate!.Version} и перезапустить приложение?" +
            (SimpleConnected ? "\nVPN будет отключён. После перезапуска подключитесь снова." : "");
        if (MessageBox.Show(this, question, "Обновление Serpium", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        _appUpdateInstalling = true;
        _shutdownStarted = true;
        // Reserve interaction without creating an operation that shutdown would wait on itself.
        _simpleBusy = true; _simpleActivity = "Подготовка обновления…";
        UpdateSimpleConnectionState(); RenderAppUpdate();
        try
        {
            using var updater = await _appUpdateManager.StartUpdaterAsync();
            await PrepareForExitAsync();
            _isRealExit = _shutdownCompleted = true;
            Application.Current.Shutdown();
        }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            if (_simpleLifetime.IsCancellationRequested)
            {
                MessageBox.Show(this, "Не удалось завершить подготовку обновления. Приложение будет закрыто.", "Обновление Serpium");
                _isRealExit = _shutdownCompleted = true; Application.Current.Shutdown();
            }
            else
            {
                _appUpdateMessage = "Не удалось запустить установку. " + (error is FileNotFoundException ? error.Message : "Повторите попытку.");
                _shutdownStarted = false; _appUpdateInstalling = false; _simpleBusy = false; _simpleActivity = null;
                UpdateSimpleConnectionState(); RenderAppUpdate();
            }
        }
    }
}
