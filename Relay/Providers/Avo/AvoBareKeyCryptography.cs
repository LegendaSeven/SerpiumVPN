using System.Security.Cryptography;
using System.Text;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Providers.Avo;

internal static class AvoBareKeyCryptography
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("avovpn/device-key/v1");

    // Compatibility material recovered from the user's authorized desktop client.
    // It is split so the clear value is not stored as a plain string in the assembly.
    private static readonly byte[] MaterialMask =
    {
        90, 195, 23, 145, 46, 109, 180, 8, 210, 68, 127, 161, 54, 232, 89,
        12, 131, 33, 246, 75, 157, 50, 199, 24, 106, 213, 64, 190, 115, 15,
        148, 43, 225, 92, 135, 57, 166, 17, 205, 104, 34, 240, 78
    };

    private static readonly byte[] MaterialCipher =
    {
        57, 168, 69, 242, 91, 8, 241, 90, 185, 20, 14, 208, 92, 178, 24,
        78, 244, 89, 135, 37, 244, 109, 141, 71, 36, 183, 34, 137, 67, 94,
        162, 64, 212, 58, 194, 124, 243, 80, 167, 7, 107, 157, 57
    };

    public static byte[] Decrypt(ProviderEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (!string.Equals(envelope.Scheme, "avo", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Передан контейнер другого провайдера.");
        if (!Guid.TryParse(envelope.ProfileId, out _))
            throw new FormatException("AVO-профиль содержит некорректный UUID.");

        byte[] raw = DecodePayload(envelope.Payload);
        if (raw.Length <= NonceSize + TagSize)
        {
            CryptographicOperations.ZeroMemory(raw);
            throw new FormatException("Защищённый пакет AVO слишком короткий.");
        }

        byte[] clientMaterial = RebuildCompatibilityMaterial();
        byte[] uuidBytes = Encoding.UTF8.GetBytes(envelope.ProfileId);
        byte[] ikmHash = SHA256.HashData(clientMaterial);
        byte[] saltInput = Encoding.UTF8.GetBytes("uuid:" + envelope.ProfileId);
        byte[] saltHash = SHA256.HashData(saltInput);
        byte[] key = HkdfSha256(ikmHash, saltHash, HkdfInfo, KeySize);

        int cipherLength = raw.Length - NonceSize - TagSize;
        byte[] plaintext = new byte[cipherLength];

        try
        {
            ReadOnlySpan<byte> nonce = raw.AsSpan(0, NonceSize);
            ReadOnlySpan<byte> ciphertext = raw.AsSpan(NonceSize, cipherLength);
            ReadOnlySpan<byte> tag = raw.AsSpan(NonceSize + cipherLength, TagSize);

            using AesGcm aes = new(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, uuidBytes);
            return plaintext;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException(
                "Ключ AVO не прошёл проверку подлинности. Возможно, он повреждён или относится к другой версии формата.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
            CryptographicOperations.ZeroMemory(clientMaterial);
            CryptographicOperations.ZeroMemory(uuidBytes);
            CryptographicOperations.ZeroMemory(ikmHash);
            CryptographicOperations.ZeroMemory(saltInput);
            CryptographicOperations.ZeroMemory(saltHash);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DecodePayload(string payload)
    {
        string normalized = payload.Trim()
            .Replace('-', '+')
            .Replace('_', '/');

        int remainder = normalized.Length % 4;
        if (remainder != 0)
            normalized = normalized.PadRight(normalized.Length + (4 - remainder), '=');

        try
        {
            return Convert.FromBase64String(normalized);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Защищённый пакет AVO содержит некорректный Base64.", ex);
        }
    }

    private static byte[] RebuildCompatibilityMaterial()
    {
        if (MaterialMask.Length != MaterialCipher.Length)
            throw new InvalidOperationException("Материал совместимости AVO повреждён.");

        byte[] result = new byte[MaterialMask.Length];
        for (int index = 0; index < result.Length; index++)
            result[index] = (byte)(MaterialMask[index] ^ MaterialCipher[index]);
        return result;
    }

    private static byte[] HkdfSha256(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int outputLength)
    {
        if (outputLength <= 0 || outputLength > 255 * 32)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        byte[] prk;
        using (HMACSHA256 extract = new(salt.ToArray()))
            prk = extract.ComputeHash(ikm.ToArray());

        byte[] output = new byte[outputLength];
        byte[] previous = Array.Empty<byte>();
        int written = 0;
        byte counter = 1;

        try
        {
            while (written < outputLength)
            {
                byte[] input = new byte[previous.Length + info.Length + 1];
                previous.CopyTo(input, 0);
                info.CopyTo(input.AsSpan(previous.Length));
                input[^1] = counter;

                byte[] block;
                using (HMACSHA256 expand = new(prk))
                    block = expand.ComputeHash(input);

                CryptographicOperations.ZeroMemory(input);
                if (previous.Length > 0)
                    CryptographicOperations.ZeroMemory(previous);
                previous = block;

                int take = Math.Min(block.Length, outputLength - written);
                block.AsSpan(0, take).CopyTo(output.AsSpan(written));
                written += take;
                counter++;
            }

            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            if (previous.Length > 0)
                CryptographicOperations.ZeroMemory(previous);
        }
    }
}
