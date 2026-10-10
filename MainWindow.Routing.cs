using System.IO;
using SerpiumVPN.Relay.Routing;
using SerpiumVPN.UI;

namespace SerpiumVPN;

public partial class MainWindow
{
    private async void SimpleApplicationRouteRequested(ApplicationRouteRequest request)
    {
        var original = _routingRegistryEntries.FirstOrDefault(item => request.Application.RuleId.HasValue
            ? item.Id == request.Application.RuleId
            : item.Kind == (request.Application.IsWebApplication ? RoutingTargetKind.Website : RoutingTargetKind.Application) &&
              string.Equals(item.PrimaryValue, request.Application.ExecutablePath, StringComparison.OrdinalIgnoreCase));
        await ChangeSimpleRouteAsync(original, async () =>
        {
            if (original is not null)
            {
                if (!await _secureRoutingRegistry.SetEnabledAsync(original.Id, request.Enabled)) throw new IOException("Application rule missing");
                return original with { IsEnabled = request.Enabled };
            }
            if (request.Application.RuleId.HasValue) throw new InvalidOperationException("Приложение уже удалено из списка.");
            var target = new ManualApplicationTarget(request.Application.DisplayName, request.Application.ExecutablePath, request.Application.IsWebApplication)
                { ApplicationId = request.Application.ApplicationId, ExecutablePaths = request.Application.ExecutablePaths };
            return await Task.Run(() => _secureRoutingRegistry.SaveApplicationTargetAsync(target, request.Enabled, false, _simpleLifetime.Token));
        }, request.Application.IsWebApplication
            ? request.Enabled ? "VPN для сайта веб-приложения включён, в том числе в обычных вкладках." : "Для сайта веб-приложения выбран прямой маршрут."
            : request.Enabled ? "VPN для приложения включён." : "Правило приложения выключено. Правила сайтов продолжают действовать.");
    }

    private async void SimpleManualApplicationAddRequested(ManualApplicationTarget target)
    {
        if (_simpleBusy || !_simpleReady) return;
        var kind = target.IsWebApplication ? RoutingTargetKind.Website : RoutingTargetKind.Application;
        var original = _routingRegistryEntries.FirstOrDefault(item => item.Kind == kind &&
            ((target.ApplicationId.Length > 0 && item.ApplicationId.Equals(target.ApplicationId, StringComparison.OrdinalIgnoreCase)) ||
             string.Equals(item.PrimaryValue, target.PrimaryValue, StringComparison.OrdinalIgnoreCase)));
        await ChangeSimpleRouteAsync(original, async () => await Task.Run(() => _secureRoutingRegistry.AddManualApplicationAsync(target, _simpleLifetime.Token)),
            target.IsWebApplication ? "Веб-приложение добавлено. Тумблер управляет сайтом, в том числе в обычных вкладках браузера."
                : "Приложение добавлено. VPN выбирается тумблером.");
    }

    private void SimpleManualApplicationDeleteRequested(Guid id)
    {
        var entry = _routingRegistryEntries.FirstOrDefault(item => item.Id == id && item.IsManuallyAdded);
        if (entry is not null) SimpleDeleteRouteRequested(id, entry.Kind);
    }

    private async void SimpleWebsiteAddRequested(WebsiteAddRequest request)
    {
        bool added = await ChangeSimpleRouteAsync(null,
            async () => await _secureRoutingRegistry.AddWebsiteAsync(request.Input, request.IncludeSubdomains, _simpleLifetime.Token),
            "Сайт добавлен: VPN включён для этого правила.");
        if (added) SimpleHome.ClearWebsiteInput();
    }

    private async void SimpleWebsiteRouteRequested(WebsiteRouteRequest request)
    {
        var original = _routingRegistryEntries.FirstOrDefault(item => item.Kind == RoutingTargetKind.Website && item.Id == request.Id);
        if (original is null) return;
        await ChangeSimpleRouteAsync(original, async () =>
        {
            if (!await _secureRoutingRegistry.SetEnabledAsync(original.Id, request.Enabled)) throw new IOException("Website rule missing");
            return original with { IsEnabled = request.Enabled };
        }, request.Enabled ? "VPN для сайта включён." : "Для сайта выбран прямой маршрут.");
    }

    private async void SimpleDeleteRouteRequested(Guid id, RoutingTargetKind kind)
    {
        var original = _routingRegistryEntries.FirstOrDefault(item => item.Id == id && item.Kind == kind);
        if (original is null || (kind == RoutingTargetKind.Application && !original.IsManuallyAdded)) return;
        await ChangeSimpleRouteAsync(original, async () =>
        {
            if (!await _secureRoutingRegistry.DeleteAsync(id)) throw new IOException("Routing rule missing");
            return null;
        }, kind == RoutingTargetKind.Website ? "Сайт удалён. Теперь действует правило приложения." :
            "Ручная запись удалена. Автоопределённое приложение может остаться в списке с выключенным VPN.");
    }

    private async Task<bool> ChangeSimpleRouteAsync(RoutingRegistryEntry? original,
        Func<Task<RoutingRegistryEntry?>> mutate, string confirmation)
    {
        if (_simpleBusy || !_simpleReady) return false;
        Guid? runningProfile = SimpleConnected ? _activeSavedProfileId : null;
        RoutingRegistryEntry? updated = null;
        bool persisted = false;
        SetSimpleBusy(true, "Применение…");
        SimpleHome.SetRoutingMessage("Применяем правило…");
        try
        {
            updated = await mutate();
            persisted = true;
            _routingRegistryEntries = (await _secureRoutingRegistry.ListAsync()).ToArray();
            if (runningProfile.HasValue)
                await ApplySimpleLiveRouteAsync(runningProfile.Value, new[] { original, updated }.OfType<RoutingRegistryEntry>().ToArray());
            RenderSimpleApplications();
            SimpleHome.SetRoutingMessage(confirmation);
            return true;
        }
        catch (Exception error)
        {
            LogSimpleFailure(error);
            bool restored = true;
            try
            {
                if (persisted)
                {
                    if (original is not null) await _secureRoutingRegistry.RestoreEntryAsync(original);
                    else if (updated is not null) await _secureRoutingRegistry.DeleteAsync(updated.Id);
                }
                _routingRegistryEntries = (await _secureRoutingRegistry.ListAsync()).ToArray();
                if (runningProfile.HasValue && persisted)
                    await ApplySimpleLiveRouteAsync(runningProfile.Value, new[] { original, updated }.OfType<RoutingRegistryEntry>().ToArray());
            }
            catch (Exception rollbackError)
            {
                restored = false; LogSimpleFailure(rollbackError);
                await StopSimpleTransportsSafelyAsync();
                try { _routingRegistryEntries = (await _secureRoutingRegistry.ListAsync()).ToArray(); }
                catch { _simpleReady = false; }
            }
            RenderSimpleApplications();
            _simpleWasConnected = SimpleConnected;
            string message = !persisted && error is FormatException or ArgumentException or InvalidOperationException
                ? error.Message : restored ? "Не удалось применить правило. Прежний выбор восстановлен." : "Не удалось восстановить правила. VPN остановлен.";
            SimpleHome.SetRoutingMessage(message, true);
            return false;
        }
        finally { SetSimpleBusy(false); }
    }

    private async Task ApplySimpleLiveRouteAsync(Guid profileId, RoutingRegistryEntry[] affected)
    {
        if (!SimpleConnected || _activeSavedProfileId != profileId) throw new InvalidOperationException("The connected profile changed.");
        var profile = _savedProfileEntries.FirstOrDefault(item => item.Id == profileId) ?? throw new InvalidOperationException("The active profile is unavailable.");
        var update = await _routingRuleSetRuntime.UpdateAsync(_routingRegistryEntries,
            string.Equals(profile.Engine, "xray", StringComparison.OrdinalIgnoreCase), _simpleLifetime.Token);
        await _serpiumSingBoxSessionManager.ApplySfpLivePolicyAsync(update.ActivationProbe,
            new SfpRoutingPolicy(_routingRegistryEntries, affected), _simpleLifetime.Token);
        if (!SimpleConnected || _activeSavedProfileId != profileId) throw new InvalidOperationException("The connection ended during the route switch.");
    }
}
