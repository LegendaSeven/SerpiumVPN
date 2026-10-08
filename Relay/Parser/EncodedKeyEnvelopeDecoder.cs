using System.Security.Cryptography;
using System.Text;

namespace SerpiumVPN.Relay.Parser;

/// <summary>
/// Result of unwrapping an optional text envelope around a supported Serpium key.
/// The original and decoded keys are never included in diagnostic strings.
/// </summary>
public sealed class EncodedKeyEnvelopeDecodeResult
{
    public EncodedKeyEnvelopeDecodeResult(
        string normalizedKey,
        bool wasDecoded,
        int decodeLayers,
        string detectedScheme,
        string safeSummaryPrefix)
    {
        NormalizedKey = normalizedKey;
        WasDecoded = wasDecoded;
        DecodeLayers = decodeLayers;
        DetectedScheme = detectedScheme;
        SafeSummaryPrefix = safeSummaryPrefix;
    }

    public string NormalizedKey { get; }

    public bool WasDecoded { get; }

    public int DecodeLayers { get; }

    public string DetectedScheme { get; }

    public string SafeSummaryPrefix { get; }
}

/// <summary>
/// Safely unwraps Base64/Base64URL envelopes such as Base64(vless://...).
/// Decoding is performed only in memory, is limited to two layers, and is
/// accepted only when the inner text starts with a protocol already supported
/// by Serpium Parser.
/// </summary>
public static class EncodedKeyEnvelopeDecoder
{
    private const int MaxInputCharacters = 131_072;
    private const int MaxDecodedBytes = 98_304;
    private const int MaxDecodeLayers = 2;

    private static readonly string[] SupportedPrefixes =
    [
        "vless://",
        "vmess://",
        "trojan://",
        "avo://",
        "hysteria2://",
        "hy2://"
    ];

    public static EncodedKeyEnvelopeDecodeResult Decode(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new FormatException("Ключ пуст.");

        string original = NormalizeText(input);
        if (original.Length > MaxInputCharacters)
        {
            throw new FormatException(
                $"Ключ превышает безопасный лимит {MaxInputCharacters} символов.");
        }

        string? directScheme = TryGetSupportedScheme(original);
        if (directScheme is not null)
        {
            return new EncodedKeyEnvelopeDecodeResult(
                original,
                wasDecoded: false,
                decodeLayers: 0,
                directScheme,
                safeSummaryPrefix: string.Empty);
        }

        string current = original;
        for (int layer = 1; layer <= MaxDecodeLayers; layer++)
        {
            if (!TryDecodeBase64Text(current, out string decoded))
                break;

            current = NormalizeText(decoded);
            if (current.Length > MaxInputCharacters)
            {
                throw new FormatException(
                    "Раскрытый контейнер превышает безопасный лимит размера.");
            }

            string? innerScheme = TryGetSupportedScheme(current);
            if (innerScheme is not null)
            {
                return new EncodedKeyEnvelopeDecodeResult(
                    current,
                    wasDecoded: true,
                    decodeLayers: layer,
                    innerScheme,
                    BuildSafeSummaryPrefix(layer, innerScheme));
            }
        }

        // Leave ordinary unknown text to the existing Serpium Parser so its
        // established validation/error behavior remains unchanged.
        return new EncodedKeyEnvelopeDecodeResult(
            original,
            wasDecoded: false,
            decodeLayers: 0,
            detectedScheme: string.Empty,
            safeSummaryPrefix: string.Empty);
    }

    private static string NormalizeText(string value) =>
        value.Trim('\uFEFF', ' ', '\t', '\r', '\n');

    private static string? TryGetSupportedScheme(string value)
    {
        foreach (string prefix in SupportedPrefixes)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return prefix[..^3].ToLowerInvariant();
        }

        return null;
    }

    private static bool TryDecodeBase64Text(string value, out string decoded)
    {
        decoded = string.Empty;

        if (value.Length < 12 || value.Length > MaxInputCharacters)
            return false;

        StringBuilder compactBuilder = new(value.Length);
        foreach (char character in value)
        {
            if (char.IsWhiteSpace(character))
                continue;

            if (!IsBase64Character(character))
                return false;

            compactBuilder.Append(character switch
            {
                '-' => '+',
                '_' => '/',
                _ => character
            });
        }

        string compact = compactBuilder.ToString();
        if (compact.Length < 12)
            return false;

        int remainder = compact.Length % 4;
        if (remainder == 1)
            return false;

        if (remainder != 0)
            compact = compact.PadRight(compact.Length + (4 - remainder), '=');

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(compact);
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            if (bytes.Length == 0 || bytes.Length > MaxDecodedBytes)
                return false;

            try
            {
                decoded = new UTF8Encoding(
                    encoderShouldEmitUTF8Identifier: false,
                    throwOnInvalidBytes: true).GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                decoded = string.Empty;
                return false;
            }

            foreach (char character in decoded)
            {
                if (char.IsControl(character) && !char.IsWhiteSpace(character))
                {
                    decoded = string.Empty;
                    return false;
                }
            }

            return !string.IsNullOrWhiteSpace(decoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool IsBase64Character(char character) =>
        character is >= 'A' and <= 'Z' ||
        character is >= 'a' and <= 'z' ||
        character is >= '0' and <= '9' ||
        character is '+' or '/' or '=' or '-' or '_';

    private static string BuildSafeSummaryPrefix(int layers, string scheme) =>
        "Контейнер ключа:" + Environment.NewLine +
        "• Base64-конверт (совместим с форматом Durev)." + Environment.NewLine +
        $"• Локально раскрыт в оперативной памяти; уровней: {layers}." +
        Environment.NewLine +
        $"• Внутренний протокол: {scheme.ToUpperInvariant()}." +
        Environment.NewLine +
        "• Исходная и раскрытая строки не выводятся в журнал." +
        Environment.NewLine + Environment.NewLine;
}
