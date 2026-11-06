using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Outline;

/// <summary>Public, explicitly selected sources only. No login, cookies or page scripts.</summary>
public sealed class OutlineKeySource
{
    public const string DefaultSource = "https://t.me/s/outlinevpn_ru";
    public const int MaximumCandidates = 8;
    private const int MaximumBytes = 524288;
    private static readonly HttpClient SharedClient = CreateClient();
    private readonly HttpClient _client;
    public OutlineKeySource(HttpClient? client = null) => _client = client ?? SharedClient;

    public async Task<IReadOnlyList<string>> ResolveAsync(string source, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            Uri uri = SourceUri(source);
            string text = await DownloadAsync(uri, deadline.Token);
            var candidates = ExtractCandidates(text, uri.Host.Equals("t.me", StringComparison.OrdinalIgnoreCase));
            var result = new List<string>();
            foreach (string candidate in candidates)
            {
                deadline.Token.ThrowIfCancellationRequested();
                try
                {
                    string key = candidate.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase)
                        ? await ResolveDynamicAsync(candidate, deadline.Token) : candidate;
                    if (new ShadowsocksKeyParser().Parse(key).Success && !result.Contains(key, StringComparer.Ordinal)) result.Add(key);
                }
                catch (ConnectionCheckException) { /* A bad source entry does not hide other candidates. */ }
                if (result.Count == MaximumCandidates) break;
            }
            if (result.Count == 0) throw new ConnectionCheckException(ConnectionFailureKind.OutlineSourceNeedsManual);
            return result.AsReadOnly();
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTimeout); }
    }

    public async Task<string> ResolveDynamicAsync(string source, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(12));
        try
        {
            string body = (await DownloadAsync(SourceUri(source), deadline.Token)).Trim();
            string key = body.StartsWith('{') ? ShadowsocksKeyParser.FromJson(body) : body;
            if (!new ShadowsocksKeyParser().Parse(key).Success)
                throw new ConnectionCheckException(ConnectionFailureKind.UnsupportedKey);
            return key;
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTimeout); }
        catch (Exception error) when (error is FormatException or System.Text.Json.JsonException or InvalidOperationException or KeyNotFoundException)
        { throw new ConnectionCheckException(ConnectionFailureKind.UnsupportedKey); }
    }

    public static IReadOnlyList<string> ExtractCandidates(string text, bool newestFirst = false)
    {
        if (text.Length > MaximumBytes) throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTooLarge);
        string decoded = WebUtility.HtmlDecode(text.Trim('\uFEFF', ' ', '\r', '\n', '\t'));
        // Page code and comments are not a public list of keys.
        decoded = Regex.Replace(decoded, @"<(script|style)\b[^>]*>[\s\S]*?</\1>|<!--[\s\S]*?-->", "",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (decoded.StartsWith('{'))
        {
            try { return [ShadowsocksKeyParser.FromJson(decoded)]; }
            catch (Exception error) when (error is FormatException or System.Text.Json.JsonException or InvalidOperationException or KeyNotFoundException) { return []; }
        }
        if (!decoded.Contains("://", StringComparison.Ordinal))
        {
            try { decoded = ShadowsocksKeyParser.DecodeBase64(decoded); }
            catch (Exception error) when (error is FormatException or DecoderFallbackException) { return []; }
        }
        var matches = Regex.Matches(decoded, @"\b(?:ss|ssconf)://[^\s<>""'`]+",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)).Select(m => m.Value);
        if (newestFirst) matches = matches.Reverse();
        return matches.Where(k => k.Length <= 8192).Distinct(StringComparer.Ordinal).Take(MaximumCandidates).ToArray();
    }

    public static Uri SourceUri(string source)
    {
        source = source.Trim();
        if (source.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase)) source = "https://" + source[9..];
        if (source.Length > 8192 || !Uri.TryCreate(source, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.UserInfo.Length > 0 || Uri.CheckHostName(uri.Host) == UriHostNameType.Unknown)
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && !IsPublicAddress(ip))
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionInvalid);
        if (uri.Host.Equals("t.me", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(uri.AbsolutePath, @"^/[A-Za-z0-9_]{5,32}/?$", RegexOptions.CultureInvariant))
            uri = new Uri("https://t.me/s/" + uri.AbsolutePath.Trim('/'));
        return new UriBuilder(uri) { Fragment = "" }.Uri;
    }

    private async Task<string> DownloadAsync(Uri uri, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(12));
        try
        {
            for (int redirect = 0; redirect <= 3; redirect++)
            {
                uri = SourceUri(uri.AbsoluteUri);
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.UserAgent.ParseAdd("SerpiumVPN/1.0");
                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
                {
                    if (redirect == 3 || response.Headers.Location is not { } location) break;
                    uri = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    continue;
                }
                if (!response.IsSuccessStatusCode) throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable);
                if (response.Content.Headers.ContentLength > MaximumBytes) throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTooLarge);
                byte[] buffer = new byte[MaximumBytes + 1];
                try
                {
                    await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
                    int count = 0, read;
                    while (count < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(count), deadline.Token)) > 0) count += read;
                    if (count > MaximumBytes) throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTooLarge);
                    return new UTF8Encoding(false, true).GetString(buffer, 0, count);
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionTimeout); }
        catch (Exception error) when (error is HttpRequestException or IOException or DecoderFallbackException)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionUnavailable); }
    }

    private static HttpClient CreateClient() => PublicSubscriptionTransport.CreateClient();

    public static bool IsPublicAddress(IPAddress address) => PublicSubscriptionTransport.IsPublicAddress(address);
}
