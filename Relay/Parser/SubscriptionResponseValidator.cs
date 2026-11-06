using System.Net;
using System.Net.Http;
using SerpiumVPN.Relay.Diagnostics;

namespace SerpiumVPN.Relay.Parser;

/// <summary>Some subscription panels return status messages disguised as loopback VLESS nodes.</summary>
public static class SubscriptionResponseValidator
{
    public static void CheckHeaders(HttpResponseMessage response)
    {
        bool Flag(string name) => response.Headers.TryGetValues(name, out var values) &&
            values.Any(value => value.Equals("true", StringComparison.OrdinalIgnoreCase));
        if (Flag("x-hwid-max-devices-reached"))
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionDeviceLimit);
        if (Flag("x-hwid-not-supported"))
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionDeviceRequired);
        // Older panels also set this generic legacy flag when HWID is missing, so specific flags win.
        if (Flag("x-hwid-limit"))
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionDeviceLimit);
    }

    public static void CheckNodes(IReadOnlyList<string> keys)
    {
        var notices = new List<string>();
        foreach (string key in keys)
        {
            if (!Uri.TryCreate(key, UriKind.Absolute, out var uri) || uri.Scheme != "vless" || uri.Port != 1)
                continue;
            string host = uri.Host.Trim('[', ']');
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                (IPAddress.TryParse(host, out var ip) && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))))
                notices.Add(Uri.UnescapeDataString(uri.Fragment.TrimStart('#')).ToLowerInvariant());
        }
        if (notices.Count == 0) return;
        // Never expose arbitrary provider text, URLs or keys in messages/logs; even mixed lists fail before saving.
        string text = string.Join(' ', notices);
        ConnectionFailureKind kind = text.Contains("app not supported") || text.Contains("unsupported app") || text.Contains("клиент не поддерж")
            ? ConnectionFailureKind.SubscriptionClientRejected
            : text.Contains("limit") || text.Contains("лимит") || text.Contains("max devices")
            ? ConnectionFailureKind.SubscriptionDeviceLimit
            : text.Contains("hwid") || text.Contains("устройство не определ")
            ? ConnectionFailureKind.SubscriptionDeviceRequired
            : ConnectionFailureKind.SubscriptionProviderNotice;
        throw new ConnectionCheckException(kind);
    }
}
