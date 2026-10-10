using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SerpiumVPN.Relay.Routing;

/// <summary>Confirms live policy activation and drains only the affected application's old route.</summary>
public sealed class SfpLiveRoutingClient
{
    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private readonly string _secret;

    public SfpLiveRoutingClient(HttpClient http, int port, string secret)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        _http = http;
        _baseUri = new Uri($"http://127.0.0.1:{port}/");
        _secret = secret;
    }

    public async Task WaitForPolicyAsync(string activationProbe, CancellationToken cancellationToken = default)
    {
        SfpPolicyAcknowledgement.ValidateProbe(activationProbe);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));
        try
        {
            while (true)
            {
                using var json = await GetJsonAsync("dns/query?name=" + activationProbe + "&type=A", timeout.Token).ConfigureAwait(false);
                var root = json.RootElement;
                if (!root.TryGetProperty("Server", out var server) || server.GetString() != "internal" ||
                    !root.TryGetProperty("Question", out var questions) || questions.ValueKind != JsonValueKind.Array ||
                    questions.GetArrayLength() != 1 || questions[0].GetProperty("Name").GetString() != activationProbe + "." ||
                    questions[0].GetProperty("Qtype").GetInt32() != 1)
                    throw new InvalidDataException("SFP policy acknowledgement is unavailable.");
                int status = root.GetProperty("Status").GetInt32();
                if (status == 0) return;
                if (status != 3) throw new InvalidDataException("Unexpected SFP policy acknowledgement.");
                await Task.Delay(25, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("The engine did not confirm the new SFP policy."); }
    }

    public async Task<int> CloseStaleConnectionsAsync(IEnumerable<string> processPaths, bool desiredVpn,
        CancellationToken cancellationToken = default)
    {
        var paths = new HashSet<string>(processPaths.Where(p => !string.IsNullOrWhiteSpace(p)).Select(NormalizePath), StringComparer.OrdinalIgnoreCase);
        if (paths.Count == 0) throw new ArgumentException("No application paths supplied.", nameof(processPaths));
        return await CloseStaleConnectionsCoreAsync(metadata =>
        {
            if (!metadata.TryGetProperty("processPath", out var process) || process.ValueKind != JsonValueKind.String ||
                !paths.Contains(NormalizePath(process.GetString()!))) return null;
            return desiredVpn;
        }, cancellationToken).ConfigureAwait(false);
    }

    public Task<int> CloseStaleConnectionsAsync(SfpRoutingPolicy policy, CancellationToken cancellationToken = default) =>
        CloseStaleConnectionsCoreAsync(metadata => policy.TryGetDesiredVpn(metadata, out bool vpn) ? vpn : null, cancellationToken);

    private async Task<int> CloseStaleConnectionsCoreAsync(Func<JsonElement, bool?> desiredRoute, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        int closed = 0, emptyPasses = 0;
        try
        {
            while (true)
            {
                using var json = await GetJsonAsync("connections", timeout.Token).ConfigureAwait(false);
                var root = json.RootElement;
                if (!root.TryGetProperty("connections", out var connections) || connections.ValueKind != JsonValueKind.Array)
                    throw new InvalidDataException("SFP active connection snapshot is unavailable.");
                var stale = new HashSet<string>(StringComparer.Ordinal);
                foreach (var connection in connections.EnumerateArray())
                {
                    if (!connection.TryGetProperty("metadata", out var metadata) || metadata.ValueKind != JsonValueKind.Object) continue;
                    bool? desiredVpn = desiredRoute(metadata);
                    if (!desiredVpn.HasValue) continue;
                    bool knownRoute = connection.TryGetProperty("chains", out var chains) &&
                        chains.ValueKind == JsonValueKind.Array && chains.GetArrayLength() > 0;
                    bool direct = knownRoute && chains.EnumerateArray().Any(chain => chain.ValueKind == JsonValueKind.String && chain.GetString() == "direct");
                    bool bypassesVpn = metadata.TryGetProperty("destinationIP", out var destination) &&
                        destination.ValueKind == JsonValueKind.String && SfpDirectRouteExceptions.BypassesVpn(destination.GetString());
                    bool expectedDirect = !desiredVpn.Value || bypassesVpn;
                    // Unknown routes for this app are also closed; never guess that they are already correct.
                    // LAN/loopback connections remain direct even while the app's VPN toggle is on.
                    if (knownRoute && direct == expectedDirect) continue;
                    if (!connection.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(id.GetString()))
                        throw new InvalidDataException("SFP cannot close an unidentified application connection.");
                    stale.Add(id.GetString()!);
                }
                if (stale.Count == 0)
                {
                    if (++emptyPasses >= 2) return closed;
                    await Task.Delay(40, timeout.Token).ConfigureAwait(false);
                    continue;
                }
                emptyPasses = 0;
                await Parallel.ForEachAsync(stale, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = timeout.Token },
                    async (id, token) =>
                    {
                        using var request = CreateRequest(HttpMethod.Delete, "connections/" + Uri.EscapeDataString(id));
                        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                        // It may have closed itself since the snapshot.
                        if (response.StatusCode != HttpStatusCode.NotFound) response.EnsureSuccessStatusCode();
                        Interlocked.Increment(ref closed);
                    }).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("Some application connections could not be closed."); }
    }

    private async Task<JsonDocument> GetJsonAsync(string path, CancellationToken token)
    {
        using var request = CreateRequest(HttpMethod.Get, path);
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        return await JsonDocument.ParseAsync(stream, cancellationToken: token).ConfigureAwait(false);
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, new Uri(_baseUri, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _secret);
        return request;
    }

    private static string NormalizePath(string value)
    {
        string path = value.Trim().Trim('"').Replace('/', '\\');
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        return path;
    }
}
