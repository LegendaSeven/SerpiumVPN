using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SerpiumVPN.Relay.Diagnostics;

public enum ConnectionFailureKind
{
    Unknown, InvalidKey, UnsupportedKey, ProfileUnavailable, AuthenticationRejected,
    NameResolution, ConnectionRefused, NetworkUnavailable, SecureHandshake, Timeout,
    ProbeUnavailable, ProbeFailed, EngineMissing, AdministratorRequired, InvalidConfiguration,
    SubscriptionUnavailable, SubscriptionExpired, SubscriptionInvalid, SubscriptionTooLarge, SubscriptionTimeout
}

/// <summary>Only fixed, user-safe messages cross the connection/UI boundary.</summary>
public sealed class ConnectionCheckException : Exception
{
    public ConnectionFailureKind Kind { get; }
    public ConnectionCheckException(ConnectionFailureKind kind, Exception? inner = null)
        : base(ConnectionFeedback.Message(kind), inner) => Kind = kind;
}

public static class ConnectionFeedback
{
    public static string Describe(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is ConnectionCheckException check) return Message(check.Kind);
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            var kind = ClassifyDiagnostic(current.Message);
            if (kind != ConnectionFailureKind.Unknown) return Message(kind);
            if (current is CryptographicException or KeyNotFoundException) return Message(ConnectionFailureKind.ProfileUnavailable);
            if (current is FileNotFoundException) return Message(ConnectionFailureKind.EngineMissing);
            if (current is SocketException socket)
                return Message(socket.SocketErrorCode switch
                {
                    SocketError.HostNotFound or SocketError.TryAgain => ConnectionFailureKind.NameResolution,
                    SocketError.ConnectionRefused => ConnectionFailureKind.ConnectionRefused,
                    SocketError.NetworkUnreachable or SocketError.HostUnreachable => ConnectionFailureKind.NetworkUnavailable,
                    SocketError.TimedOut => ConnectionFailureKind.Timeout,
                    _ => ConnectionFailureKind.ProbeFailed
                });
        }
        return Message(error is TimeoutException or OperationCanceledException
            ? ConnectionFailureKind.Timeout : ConnectionFailureKind.Unknown);
    }

    public static ConnectionFailureKind ClassifyDiagnostic(string diagnostic)
    {
        string text = diagnostic.ToLowerInvariant();
        if (text.Contains("от имени администратора")) return ConnectionFailureKind.AdministratorRequired;
        if (text.Contains("sing-box отклонил")) return ConnectionFailureKind.InvalidConfiguration;
        if (text.Contains("authentication failed") || text.Contains("invalid user") || text.Contains("invalid password") ||
            text.Contains("authentication rejected") || text.Contains("authorization failed"))
            return ConnectionFailureKind.AuthenticationRejected;
        if (text.Contains("no such host") || text.Contains("name resolution") || text.Contains("dns lookup") || text.Contains("nxdomain"))
            return ConnectionFailureKind.NameResolution;
        if (text.Contains("connection refused") || text.Contains("actively refused")) return ConnectionFailureKind.ConnectionRefused;
        if (text.Contains("network is unreachable") || text.Contains("no route to host") || text.Contains("network unreachable"))
            return ConnectionFailureKind.NetworkUnavailable;
        if (text.Contains("certificate") || text.Contains("tls handshake") || text.Contains("reality verification"))
            return ConnectionFailureKind.SecureHandshake;
        if (text.Contains("timeout") || text.Contains("timed out") || text.Contains("deadline exceeded") || text.Contains("таймаут"))
            return ConnectionFailureKind.Timeout;
        return ConnectionFailureKind.Unknown;
    }

    public static string Message(ConnectionFailureKind kind) => kind switch
    {
        ConnectionFailureKind.InvalidKey => "Ключ повреждён или имеет неверный формат. Скопируйте его целиком и попробуйте снова.",
        ConnectionFailureKind.UnsupportedKey => "Этот тип ключа пока не поддерживается. Нужен ключ VLESS, VMess, Trojan, Hysteria2, AVO или HTTPS-ссылка на подписку.",
        ConnectionFailureKind.SubscriptionUnavailable => "Не удалось загрузить профили по ссылке. Проверьте интернет и доступность сервиса подписки.",
        ConnectionFailureKind.SubscriptionExpired => "Ссылка недоступна или срок её действия истёк. Запросите актуальную ссылку у провайдера.",
        ConnectionFailureKind.SubscriptionInvalid => "По ссылке не получен поддерживаемый список подключений. Нужна ссылка на подписку, а не на веб-страницу.",
        ConnectionFailureKind.SubscriptionTooLarge => "Список подключений превышает допустимый размер. Запросите меньшую подписку.",
        ConnectionFailureKind.SubscriptionTimeout => "Сервис подписки не ответил вовремя. Проверьте интернет и повторите попытку.",
        ConnectionFailureKind.ProfileUnavailable => "Не удалось прочитать сохранённый профиль. Вставьте ключ заново.",
        ConnectionFailureKind.AuthenticationRejected => "VPN-сервер отклонил данные доступа. Запросите актуальный ключ у провайдера.",
        ConnectionFailureKind.NameResolution => "Не удалось определить адрес сервера или проверочного сайта. Проверьте интернет и DNS.",
        ConnectionFailureKind.ConnectionRefused => "Сервер отказал в соединении. Проверьте его доступность или запросите актуальный ключ.",
        ConnectionFailureKind.NetworkUnavailable => "Сеть недоступна. Проверьте интернет и повторите подключение.",
        ConnectionFailureKind.SecureHandshake => "Не удалось установить защищённое соединение. Проверьте дату на компьютере и актуальность ключа.",
        ConnectionFailureKind.Timeout => "Проверка не получила ответ вовремя. Сервер или проверочный сайт может быть недоступен. Проверьте интернет и повторите попытку.",
        ConnectionFailureKind.ProbeUnavailable => "Служба проверки соединения недоступна. Перезапустите Serpium и повторите попытку.",
        ConnectionFailureKind.ProbeFailed => "Доступ в интернет через VPN не подтверждён. Сервер не сообщил точную причину; проверьте интернет и актуальность ключа.",
        ConnectionFailureKind.EngineMissing => "Не найден компонент подключения. Восстановите файлы приложения и попробуйте снова.",
        ConnectionFailureKind.AdministratorRequired => "Для подключения запустите Serpium от имени администратора.",
        ConnectionFailureKind.InvalidConfiguration => "Сетевой движок не принял настройки профиля. Обновите приложение или запросите другой ключ.",
        _ => "Не удалось завершить проверку соединения. Подключение не установлено. Повторите попытку или запросите актуальный ключ."
    };
}
