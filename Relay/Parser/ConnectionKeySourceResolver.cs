using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using SerpiumVPN.Relay.Diagnostics;

namespace SerpiumVPN.Relay.Parser;

/// <summary>Downloads a subscription only when explicitly supplied, and keeps its secrets in memory.</summary>
public sealed class ConnectionKeySourceResolver
{
    private const int MaximumBytes = 131_072;
    private static readonly HttpClient SharedHttp = new(new HttpClientHandler
    {
        UseProxy = false, UseCookies = false, AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.All
    }) { Timeout = Timeout.InfiniteTimeSpan };
    private readonly HttpClient _http;

    public ConnectionKeySourceResolver(HttpClient? http = null) => _http = http ?? SharedHttp;

    public async Task<IReadOnlyList<string>> ResolveAsync(string input, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string source = input.Trim('\uFEFF', ' ', '\r', '\n', '\t');
        if (source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            source = await DownloadAsync(source, cancellationToken).ConfigureAwait(false);
        return ParseKeys(source);
    }

    public static IReadOnlyList<string> ParseKeys(string source)
    {
        string decoded;
        try { decoded = EncodedKeyEnvelopeDecoder.Decode(source).NormalizedKey; }
        catch (FormatException) { throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey); }
        var keys = decoded.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal).ToArray();
        if (keys.Length is 0 or > 100)
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
        var parser = new SerpiumParser();
        // Validate every item before the caller saves any profile; never silently discard a node.
        foreach (string key in keys)
        {
            if (key.Contains("://", StringComparison.Ordinal) &&
                !new[] { "vless://", "vmess://", "trojan://", "avo://", "hysteria2://", "hy2://" }.Any(prefix => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                throw new ConnectionCheckException(ConnectionFailureKind.UnsupportedKey);
            if (!parser.Parse(key).Success)
                throw new ConnectionCheckException(ConnectionFailureKind.InvalidKey);
        }
        return Array.AsReadOnly(keys);
    }

    private async Task<string> DownloadAsync(string source, CancellationToken cancellationToken)
    {
        if (source.Length > 8192 || !Uri.TryCreate(source, UriKind.Absolute, out var uri))
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            for (int redirect = 0; redirect <= 3; redirect++)
            {
                if (uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo))
                    throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.UserAgent.ParseAdd("SerpiumVPN/1.0");
                request.Headers.Accept.ParseAdd("text/plain");
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
                {
                    if (redirect == 3 || response.Headers.Location is not { } location)
                        throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable);
                    uri = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    continue;
                }
                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.NotFound or HttpStatusCode.Gone)
                    throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionExpired);
                if (!response.IsSuccessStatusCode)
                    throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable);
                if (response.Content.Headers.ContentLength > MaximumBytes)
                    throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTooLarge);
                if (response.Content.Headers.ContentType?.MediaType is "text/html" or "application/xhtml+xml")
                    throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
                byte[] buffer = new byte[MaximumBytes + 1];
                try
                {
                    await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                    int count = 0, read;
                    while (count < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(count), deadline.Token).ConfigureAwait(false)) > 0)
                        count += read;
                    if (count > MaximumBytes) throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTooLarge);
                    if (count == 0) throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
                    return new UTF8Encoding(false, true).GetString(buffer, 0, count);
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTimeout); }
        catch (Exception error) when (error is HttpRequestException or IOException)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable); }
        catch (DecoderFallbackException)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid); }
    }
}
