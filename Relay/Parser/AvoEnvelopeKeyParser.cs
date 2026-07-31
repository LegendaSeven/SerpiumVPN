namespace SerpiumVPN.Relay.Parser;

/// <summary>
/// Recognizes the provider envelope shape used by avo:// keys.
/// It validates only the container structure. Decryption/resolution belongs
/// to a separate provider adapter and is intentionally not guessed here.
/// </summary>
public sealed class AvoEnvelopeKeyParser : ISerpiumKeyParser
{
    private const string Prefix = "avo://";
    private const int MaxPayloadCharacters = 2_000_000;

    public bool CanParse(string key) =>
        key.TrimStart().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    public SerpiumParseResult Parse(string key)
    {
        try
        {
            string body = key.Trim()[Prefix.Length..].Trim();
            int separator = body.IndexOf(':');
            if (separator <= 0)
            {
                return SerpiumParseResult.Fail(
                    "AVO-контейнер должен иметь вид avo://<profile-id>:<payload>.");
            }

            string profileId = body[..separator].Trim();
            string payload = body[(separator + 1)..].Trim();

            if (!Guid.TryParse(profileId, out _))
            {
                return SerpiumParseResult.Fail(
                    "В AVO-контейнере указан некорректный идентификатор профиля.");
            }

            if (string.IsNullOrWhiteSpace(payload))
                return SerpiumParseResult.Fail("В AVO-контейнере отсутствует защищённый пакет.");

            if (payload.Length > MaxPayloadCharacters)
                return SerpiumParseResult.Fail("AVO-контейнер превышает допустимый размер.");

            if (!TryValidateBase64(payload, out int payloadBytes))
            {
                return SerpiumParseResult.Fail(
                    "Защищённый пакет AVO содержит некорректный Base64.");
            }

            ProviderEnvelope envelope = new()
            {
                Scheme = "avo",
                ProviderName = "Avo",
                ProfileId = profileId,
                Payload = payload,
                PayloadByteCount = payloadBytes
            };

            return SerpiumParseResult.Provider(envelope);
        }
        catch (Exception ex)
        {
            return SerpiumParseResult.Fail(
                "Не удалось разобрать AVO-контейнер: " + ex.Message);
        }
    }

    private static bool TryValidateBase64(string value, out int decodedBytes)
    {
        decodedBytes = 0;
        string normalized = value.Trim()
            .Replace('-', '+')
            .Replace('_', '/');

        int remainder = normalized.Length % 4;
        if (remainder != 0)
            normalized = normalized.PadRight(normalized.Length + (4 - remainder), '=');

        try
        {
            byte[] bytes = Convert.FromBase64String(normalized);
            decodedBytes = bytes.Length;
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
