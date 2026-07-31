using System.Security.Cryptography;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Providers.Avo;

/// <summary>
/// Embedded AVO bare-key decoder proof of concept.
/// It performs only local authenticated decryption and JSON inspection.
/// No request is sent to Avo or any Serpium service.
/// </summary>
public sealed class AvoBareKeyProviderAdapter : IProviderEnvelopeAdapter
{
    public string Scheme => "avo";

    public Task<ProviderResolveResult> ResolveAsync(
        ProviderEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        cancellationToken.ThrowIfCancellationRequested();

        byte[]? plaintext = null;
        try
        {
            plaintext = AvoBareKeyCryptography.Decrypt(envelope);
            cancellationToken.ThrowIfCancellationRequested();

            ProviderRuntimeProfile runtimeProfile =
                AvoProviderProfileInspector.Create(envelope.ProfileId, plaintext);
            plaintext = null; // ownership transferred to ProviderRuntimeProfile

            return Task.FromResult(ProviderResolveResult.Native(runtimeProfile));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Task.FromResult(ProviderResolveResult.Fail(
                "Не удалось раскрыть AVO-профиль: " + ex.Message));
        }
        finally
        {
            if (plaintext is not null)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
