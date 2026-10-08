using System.IO;
using System.Net;
using SerpiumVPN.Relay.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SerpiumVPN.Relay.SingBox;

/// <summary>Checks the VPN outbound itself, independently of Windows per-process routing.</summary>
public static class VpnOutboundProbe
{
    public static string ReadOutboundTag(byte[] configuration)
    {
        using var document = JsonDocument.Parse(configuration);
        var root = document.RootElement;
        if (root.TryGetProperty("route",out var route) && route.TryGetProperty("rules",out var rules))
        {
            foreach (var rule in rules.EnumerateArray())
            {
                if (!rule.TryGetProperty("domain",out var domains) || domains.ValueKind != JsonValueKind.Array ||
                    !domains.EnumerateArray().Any(value => value.GetString() == "www.gstatic.com") ||
                    !rule.TryGetProperty("outbound",out var outbound)) continue;
                string? tag = outbound.GetString();
                if (string.IsNullOrWhiteSpace(tag)) continue;
                bool isProxy = root.GetProperty("outbounds").EnumerateArray().Any(item =>
                    item.TryGetProperty("tag",out var itemTag) && itemTag.GetString() == tag &&
                    item.TryGetProperty("type",out var type) && type.GetString() is not ("direct" or "block" or "dns"));
                if (isProxy) return tag;
            }
        }
        throw new InvalidDataException("Не найден VPN-маршрут для проверки подключения.");
    }

    public static async Task CheckAsync(HttpClient client,int apiPort,string apiSecret,string outboundTag,CancellationToken cancellationToken)
    {
        if (apiPort is < 1 or > 65535 || string.IsNullOrWhiteSpace(apiSecret) || string.IsNullOrWhiteSpace(outboundTag))
            throw new InvalidOperationException("Проверка VPN недоступна.");
        // sing-box's authenticated loopback API dials through the requested outbound.
        // An ordinary HttpClient GET can succeed over DIRECT and must not count here.
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"http://127.0.0.1:{apiPort}/proxies/{Uri.EscapeDataString(outboundTag)}/delay?timeout=7000&url=" +
            Uri.EscapeDataString("https://www.gstatic.com/generate_204"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer",apiSecret);
        using var response = await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            // This HTTP status belongs to the local controller, not the VPN server.
            var kind = response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.NotFound
                ? ConnectionFailureKind.ProbeUnavailable : ConnectionFailureKind.ProbeFailed;
            if (response.StatusCode == HttpStatusCode.GatewayTimeout) kind = ConnectionFailureKind.Timeout;
            if (kind == ConnectionFailureKind.ProbeFailed)
            {
                try
                {
                    await response.Content.LoadIntoBufferAsync(8192, cancellationToken);
                    using var failure = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                    if (failure.RootElement.ValueKind == JsonValueKind.Object &&
                        failure.RootElement.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.String)
                    {
                        var classified = ConnectionFeedback.ClassifyDiagnostic(message.GetString()!);
                        if (classified != ConnectionFailureKind.Unknown) kind = classified;
                    }
                }
                catch (Exception error) when (error is JsonException or HttpRequestException) { }
            }
            throw new ConnectionCheckException(kind);
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream,cancellationToken:cancellationToken);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("delay",out var delay) ||
            delay.ValueKind != JsonValueKind.Number || !delay.TryGetInt32(out int milliseconds) || milliseconds <= 0)
            throw new InvalidDataException("Сетевой движок не подтвердил VPN-соединение.");
    }
}
