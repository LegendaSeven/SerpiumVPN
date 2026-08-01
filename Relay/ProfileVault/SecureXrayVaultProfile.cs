using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.ProfileVault;

public sealed record SecureXrayVaultProfile(
    SerpiumConnectionProfile Profile,
    int SocksPort);
