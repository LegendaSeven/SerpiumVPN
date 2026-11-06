using System.Windows;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN;

public partial class MainWindow
{
    private async Task<string?> AuthorizeSubscriptionDeviceAsync(Uri source, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var store = new SubscriptionDeviceIdentityStore();
        string? existing = store.Read(source);
        if (existing is not null) return existing;
        bool consent = await Dispatcher.InvokeAsync(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return System.Windows.MessageBox.Show(this,
                $"Сервис {source.IdnHost}:{source.Port} требует привязку устройства.\n\n" +
                "Передать ему отдельный случайный идентификатор Serpium? Он будет сохранён для этого сервиса. " +
                "Серийные номера компьютера и имя пользователя не отправляются.\n\n" +
                "Провайдер может засчитать Serpium как новое устройство в подписке.",
                "Привязка устройства", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;
        });
        cancellationToken.ThrowIfCancellationRequested();
        return consent ? store.Authorize(source) : null;
    }
}
