namespace SerpiumVPN.Relay;

/// <summary>
/// Compatibility facade retained for the current Relay UI.
/// MVP6.2 no longer launches tailscale.exe or the Windows Tailscale service.
/// The actual tailnet connection is created by the embedded SerpiumNet bridge.
/// </summary>
public sealed class TailscaleManager
{
    public string? ExecutablePath { get; private set; }
    public string? LastBackendState { get; private set; }

    public Task<string> EnsureReadyAndGetIpAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        SerpiumNetClientEnrollment enrollment =
            SerpiumNetClientConfig.ResolveEnrollment();

        ExecutablePath = enrollment.BinaryPath;
        LastBackendState = enrollment.HasPersistentState
            ? "SerpiumNetPersistentState"
            : "SerpiumNetOneTimeEnrollment";

        // The current UI places this value in parentheses after its legacy
        // “Tailscale” label. No system interface exists in tsnet userspace mode.
        return Task.FromResult("SerpiumNet headless");
    }
}
