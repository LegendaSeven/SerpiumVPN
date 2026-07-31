using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Providers;

public sealed class ProviderResolveResult
{
    private ProviderResolveResult(
        bool success,
        SerpiumConnectionProfile? profile,
        ProviderRuntimeProfile? runtimeProfile,
        string error)
    {
        Success = success;
        Profile = profile;
        RuntimeProfile = runtimeProfile;
        Error = error;
    }

    public bool Success { get; }
    public SerpiumConnectionProfile? Profile { get; }
    public ProviderRuntimeProfile? RuntimeProfile { get; }
    public string Error { get; }

    public bool HasConnectionProfile => Profile is not null;
    public bool HasRuntimeProfile => RuntimeProfile is not null;

    public static ProviderResolveResult Ok(SerpiumConnectionProfile profile) =>
        new(true, profile, null, string.Empty);

    public static ProviderResolveResult Native(ProviderRuntimeProfile runtimeProfile) =>
        new(true, null, runtimeProfile, string.Empty);

    public static ProviderResolveResult Fail(string error) =>
        new(false, null, null, error);
}
