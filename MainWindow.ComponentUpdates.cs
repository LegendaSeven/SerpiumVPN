using System.Windows.Threading;
using SerpiumVPN.Relay.Components;

namespace SerpiumVPN;

public partial class MainWindow
{
    private readonly DispatcherTimer _componentUpdateTimer = new(){Interval=TimeSpan.FromHours(1)};
    private bool _componentCheckBusy;
    private bool _componentInstallBusy;
    private bool _componentUpdatesAvailable;
    private string _componentUpdateMessage="sing-box и Xray · проверка обновлений";

    private void InitializeSimpleComponentUpdates()
    {
        SimpleHome.ComponentUpdatesRequested+=SimpleComponentUpdatesRequested;
        _componentUpdateTimer.Tick+=async (_,_)=>
        { if(_settings.AutoCheckRelayComponents)await CheckSimpleComponentUpdatesAsync(false); };
        _componentUpdateTimer.Start();
        RenderSimpleComponentUpdates();
    }

    private void RenderSimpleComponentUpdates()=>SimpleHome.SetComponentUpdateState(
        _componentUpdateMessage,_componentUpdatesAvailable,_componentCheckBusy||_componentInstallBusy);

    private async Task CheckSimpleComponentUpdatesAsync(bool force)
    {
        if(_componentCheckBusy||_componentInstallBusy||_simpleLifetime.IsCancellationRequested)return;
        _componentCheckBusy=true;_componentUpdateMessage="Проверяем обновления компонентов…";RenderSimpleComponentUpdates();
        try
        {
            var snapshots=await _relayComponentManager.InspectAllAsync(_simpleLifetime.Token);
            bool cached=!force && _settings.LastRelayComponentCheckUtc is DateTimeOffset previous &&
                previous<=DateTimeOffset.UtcNow && DateTimeOffset.UtcNow-previous<TimeSpan.FromHours(24) &&
                !string.IsNullOrEmpty(_settings.LastKnownSingBoxRelease)&&!string.IsNullOrEmpty(_settings.LastKnownXrayRelease);
            if(!cached)
            {
                var releases=await _relayComponentManager.CheckLatestStableReleasesAsync(_simpleLifetime.Token);
                _settings.LastRelayComponentCheckUtc=DateTimeOffset.UtcNow;
                _settings.LastKnownSingBoxRelease=releases[RelayComponentKind.SingBox].TagName;
                _settings.LastKnownXrayRelease=releases[RelayComponentKind.XrayCore].TagName;
                _settings.Save();
            }
            var available=new List<string>();
            if(RelayComponentManager.IsUpdateAvailable(snapshots[RelayComponentKind.SingBox].InstalledVersion,_settings.LastKnownSingBoxRelease))available.Add("sing-box");
            if(RelayComponentManager.IsUpdateAvailable(snapshots[RelayComponentKind.XrayCore].InstalledVersion,_settings.LastKnownXrayRelease))available.Add("Xray");
            _componentUpdatesAvailable=available.Count>0;
            _componentUpdateMessage=available.Count>0?"Доступно обновление: "+string.Join(", ",available)+". Совместимость проверим перед установкой.":
                snapshots.Values.All(s=>s.Health==RelayComponentHealth.Healthy)?"sing-box и Xray: новых стабильных версий нет.":"Один из компонентов требует проверки. Перезапустите приложение.";
        }
        catch(OperationCanceledException) when(_simpleLifetime.IsCancellationRequested){}
        catch(Exception error){LogSimpleFailure(error);_componentUpdatesAvailable=false;_componentUpdateMessage="Не удалось проверить обновления. Повторите позже.";}
        finally{_componentCheckBusy=false;if(!_simpleLifetime.IsCancellationRequested)RenderSimpleComponentUpdates();}
    }

    private async void SimpleComponentUpdatesRequested(object? sender,EventArgs args)
    {
        if(_componentCheckBusy||_componentInstallBusy||_simpleBusy)return;
        if(!_componentUpdatesAvailable){await CheckSimpleComponentUpdatesAsync(true);return;}
        if(SimpleConnected||_serpiumSingBoxSessionManager.HasLiveProcess||_serpiumXraySessionManager.HasLiveProcess)
        {_componentUpdateMessage="Отключите VPN перед обновлением компонентов.";RenderSimpleComponentUpdates();return;}
        using var attempt=CancellationTokenSource.CreateLinkedTokenSource(_simpleLifetime.Token);
        _simpleConnectCancellation=attempt;
        _componentInstallBusy=true;RenderSimpleComponentUpdates();SetSimpleBusy(true,"Проверка обновлений…");
        var results=new List<string>();
        try
        {
            // Refresh official metadata; never install solely from the cached availability label.
            var releases=await _relayComponentManager.CheckLatestStableReleasesAsync(attempt.Token);
            var snapshots=await _relayComponentManager.InspectAllAsync(attempt.Token);
            foreach(var kind in new[]{RelayComponentKind.SingBox,RelayComponentKind.XrayCore})
            {
                var release=releases[kind];var current=snapshots[kind];string name=kind==RelayComponentKind.SingBox?"sing-box":"Xray";
                if(!RelayComponentManager.IsUpdateAvailable(current.InstalledVersion,release.NormalizedVersion))continue;
                var download=new Progress<RelayComponentDownloadProgress>(p=>
                {if(_componentInstallBusy&&ReferenceEquals(_simpleConnectCancellation,attempt)&&!attempt.IsCancellationRequested)SetSimpleBusy(true,$"Загрузка {name}: {p.Percent}%");});
                await _relayComponentManager.StageReleaseAsync(kind,release,download,attempt.Token);
                var install=new Progress<RelayComponentInstallProgress>(_=>
                {if(_componentInstallBusy&&ReferenceEquals(_simpleConnectCancellation,attempt)&&!attempt.IsCancellationRequested)SetSimpleBusy(true,$"Проверка и обновление {name}…");});
                var result=await _relayComponentManager.InstallStagedUpdateAsync(kind,install,attempt.Token);
                results.Add(result.Succeeded?$"{name}: обновлён до {result.InstalledVersion}.":$"{name}: проверка совместимости не пройдена; оставлена версия {result.InstalledVersion}.");
            }
            _componentUpdateMessage=results.Count>0?string.Join(" ",results):"sing-box и Xray: новых стабильных версий нет.";
        }
        catch(OperationCanceledException) when(attempt.IsCancellationRequested)
        {_componentUpdateMessage=string.Join(" ",results.Append("Обновление остановлено."));}
        catch(Exception error)
        {
            LogSimpleFailure(error);
            _componentUpdateMessage=string.Join(" ",results.Append("Обновление не завершено. Повторите проверку компонентов."));
        }
        finally
        {
            _componentInstallBusy=false;_componentUpdatesAvailable=false;_simpleConnectCancellation=null;
            if(!_simpleLifetime.IsCancellationRequested){SetSimpleBusy(false);RenderSimpleComponentUpdates();}
        }
    }
}
