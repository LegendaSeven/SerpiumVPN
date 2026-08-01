namespace SerpiumVPN.Relay.ProfileVault;

/// <summary>
/// Safe metadata for a profile stored in the encrypted Serpium vault.
/// Server addresses, credentials and the sing-box configuration are never exposed here.
/// </summary>
public sealed record SecureProfileVaultEntry(
    Guid Id,
    string ProviderName,
    string ProfileId,
    string Engine,
    IReadOnlyList<string> Protocols,
    int InboundCount,
    int OutboundCount,
    int RouteRuleCount,
    int DnsServerCount,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc)
{
    public string MaskedProfileId
    {
        get
        {
            if (string.IsNullOrEmpty(ProfileId))
                return "••••";
            if (ProfileId.Length <= 8)
                return new string('•', ProfileId.Length);

            return ProfileId[..4] + "…" + ProfileId[^4..];
        }
    }

    public string SafeDisplayName =>
        $"{ProviderName.ToUpperInvariant()} • {MaskedProfileId}";
}

public sealed record SecureProfileVaultSaveResult(
    SecureProfileVaultEntry Entry,
    bool UpdatedExisting,
    int ProfileCount,
    bool DirectoryAclHardened);
