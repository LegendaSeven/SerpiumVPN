using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay.Providers.Avo;

/// <summary>
/// Produces a value-free structural description of provider JSON.
/// Property names, JSON kinds, collection sizes and coarse string shapes are shown;
/// actual string, number and boolean values are never included.
/// </summary>
internal static class AvoProviderJsonSchemaInspector
{
    private const int MaxDepth = 7;
    private const int MaxLines = 96;
    private const int MaxPropertiesPerObject = 32;
    private const int MaxArraySamples = 2;
    private const int MaxNestedEncodedBytes = 256 * 1024;

    public static string Inspect(JsonElement root)
    {
        InspectionState state = new();
        AppendElement(state, "root", root, 0);

        if (state.Truncated)
            state.Lines.Add("… схема сокращена безопасным лимитом инспектора");

        state.Lines.Add(string.Empty);
        state.Lines.Add(
            $"Сигналы: encoded JSON={state.EncodedJsonCount}, Base64={state.Base64Count}, " +
            $"URI={state.UriCount}, UUID={state.UuidCount}, IP={state.IpCount}.");
        state.Lines.Add("Значения строк, чисел и логических полей скрыты.");

        return string.Join(Environment.NewLine, state.Lines);
    }

    private static void AppendElement(
        InspectionState state,
        string label,
        JsonElement element,
        int depth)
    {
        if (!CanAppend(state))
            return;

        string indent = new string(' ', depth * 2);
        string safeLabel = SanitizeLabel(label);

        if (depth > MaxDepth)
        {
            AddLine(state, $"{indent}• {safeLabel}: {DescribeKind(element.ValueKind)} (глубже лимита)");
            return;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                AppendObject(state, safeLabel, element, depth, indent);
                break;

            case JsonValueKind.Array:
                AppendArray(state, safeLabel, element, depth, indent);
                break;

            case JsonValueKind.String:
                AppendString(state, safeLabel, element.GetString() ?? string.Empty, depth, indent);
                break;

            case JsonValueKind.Number:
                AddLine(state, $"{indent}• {safeLabel}: number ({DescribeNumber(element)})");
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
                AddLine(state, $"{indent}• {safeLabel}: boolean (значение скрыто)");
                break;

            case JsonValueKind.Null:
                AddLine(state, $"{indent}• {safeLabel}: null");
                break;

            default:
                AddLine(state, $"{indent}• {safeLabel}: {DescribeKind(element.ValueKind)}");
                break;
        }
    }

    private static void AppendObject(
        InspectionState state,
        string label,
        JsonElement element,
        int depth,
        string indent)
    {
        int propertyCount = element.EnumerateObject().Count();
        AddLine(state, $"{indent}• {label}: object ({propertyCount} полей)");

        int emitted = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!CanAppend(state))
                return;

            if (emitted >= MaxPropertiesPerObject)
            {
                AddLine(
                    state,
                    $"{indent}  … ещё {Math.Max(0, propertyCount - emitted)} полей скрыто лимитом");
                return;
            }

            AppendElement(state, property.Name, property.Value, depth + 1);
            emitted++;
        }
    }

    private static void AppendArray(
        InspectionState state,
        string label,
        JsonElement element,
        int depth,
        string indent)
    {
        int count = element.GetArrayLength();
        AddLine(state, $"{indent}• {label}: array ({count} элементов)");
        if (count == 0 || depth >= MaxDepth)
            return;

        Dictionary<JsonValueKind, int> kinds = new();
        foreach (JsonElement item in element.EnumerateArray())
        {
            kinds[item.ValueKind] = kinds.TryGetValue(item.ValueKind, out int current)
                ? current + 1
                : 1;
        }

        string kindSummary = string.Join(
            ", ",
            kinds.OrderBy(pair => pair.Key)
                .Select(pair => $"{DescribeKind(pair.Key)}×{pair.Value}"));
        AddLine(state, $"{indent}  типы элементов: {kindSummary}");

        int sampleIndex = 0;
        foreach (JsonElement item in element.EnumerateArray())
        {
            if (sampleIndex >= MaxArraySamples || !CanAppend(state))
                break;

            AppendElement(state, $"[{sampleIndex}] sample", item, depth + 1);
            sampleIndex++;
        }

        if (count > sampleIndex)
            AddLine(state, $"{indent}  … остальные {count - sampleIndex} элементов не раскрываются");
    }

    private static void AppendString(
        InspectionState state,
        string label,
        string value,
        int depth,
        string indent)
    {
        string shape = ClassifyString(value, state, out JsonDocument? nestedDocument);
        string sensitivity = IsSensitiveName(label) ? "; sensitive-name" : string.Empty;
        AddLine(
            state,
            $"{indent}• {label}: string (len={value.Length}; shape={shape}{sensitivity}; значение скрыто)");

        if (nestedDocument is null || depth >= MaxDepth || !CanAppend(state))
            return;

        try
        {
            AppendElement(state, "decoded-json", nestedDocument.RootElement, depth + 1);
        }
        finally
        {
            nestedDocument.Dispose();
        }
    }

    private static string ClassifyString(
        string value,
        InspectionState state,
        out JsonDocument? nestedDocument)
    {
        nestedDocument = null;

        if (value.Length == 0)
            return "empty";

        if (Guid.TryParse(value, out _))
        {
            state.UuidCount++;
            return "uuid";
        }

        if (IPAddress.TryParse(value, out _))
        {
            state.IpCount++;
            return "ip-address";
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) &&
            !string.IsNullOrWhiteSpace(uri.Scheme))
        {
            state.UriCount++;
            return "uri";
        }

        if (TryParseJsonText(value, out nestedDocument))
        {
            state.EncodedJsonCount++;
            return nestedDocument.RootElement.ValueKind == JsonValueKind.Array
                ? "json-text-array"
                : "json-text-object";
        }

        if (TryDecodeBase64(value, out byte[] decoded))
        {
            state.Base64Count++;
            try
            {
                if (decoded.Length <= MaxNestedEncodedBytes &&
                    TryParseJsonBytes(decoded, out nestedDocument))
                {
                    state.EncodedJsonCount++;
                    return nestedDocument.RootElement.ValueKind == JsonValueKind.Array
                        ? "base64-json-array"
                        : "base64-json-object";
                }

                double printableRatio = GetPrintableRatio(decoded);
                return printableRatio >= 0.85 ? "base64-text" : "base64-binary";
            }
            finally
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
        }

        if (DateTimeOffset.TryParse(value, out _))
            return "date-time";

        if (value.All(char.IsDigit))
            return "numeric-text";

        int controlCharacters = value.Count(char.IsControl);
        return controlCharacters == 0 ? "text" : "opaque-text";
    }

    private static bool TryParseJsonText(
        string value,
        [NotNullWhen(true)] out JsonDocument? document)
    {
        document = null;
        string trimmed = value.TrimStart();
        if (trimmed.Length < 2 || (trimmed[0] != '{' && trimmed[0] != '['))
            return false;

        try
        {
            document = JsonDocument.Parse(value);
            return document.RootElement.ValueKind is JsonValueKind.Object or JsonValueKind.Array;
        }
        catch (JsonException)
        {
            document?.Dispose();
            document = null;
            return false;
        }
    }

    private static bool TryParseJsonBytes(
        byte[] bytes,
        [NotNullWhen(true)] out JsonDocument? document)
    {
        document = null;
        if (bytes.Length < 2)
            return false;

        int index = 0;
        while (index < bytes.Length &&
               (bytes[index] == (byte)' ' ||
                bytes[index] == (byte)'\t' ||
                bytes[index] == (byte)'\r' ||
                bytes[index] == (byte)'\n'))
        {
            index++;
        }

        if (index >= bytes.Length || (bytes[index] != (byte)'{' && bytes[index] != (byte)'['))
            return false;

        try
        {
            document = JsonDocument.Parse(bytes);
            return document.RootElement.ValueKind is JsonValueKind.Object or JsonValueKind.Array;
        }
        catch (JsonException)
        {
            document?.Dispose();
            document = null;
            return false;
        }
    }

    private static bool TryDecodeBase64(string value, out byte[] decoded)
    {
        decoded = Array.Empty<byte>();
        if (value.Length < 16 || value.Length > MaxNestedEncodedBytes * 2)
            return false;

        string normalized = value.Trim()
            .Replace('-', '+')
            .Replace('_', '/');

        if (normalized.Any(character =>
                !(char.IsLetterOrDigit(character) || character is '+' or '/' or '=')))
        {
            return false;
        }

        int remainder = normalized.Length % 4;
        if (remainder == 1)
            return false;
        if (remainder != 0)
            normalized = normalized.PadRight(normalized.Length + (4 - remainder), '=');

        try
        {
            decoded = Convert.FromBase64String(normalized);
            return decoded.Length > 0;
        }
        catch (FormatException)
        {
            decoded = Array.Empty<byte>();
            return false;
        }
    }

    private static double GetPrintableRatio(byte[] bytes)
    {
        if (bytes.Length == 0)
            return 0;

        int printable = 0;
        foreach (byte value in bytes)
        {
            if ((value >= 32 && value <= 126) || value is 9 or 10 or 13)
                printable++;
        }

        return printable / (double)bytes.Length;
    }

    private static string DescribeNumber(JsonElement element)
    {
        if (element.TryGetInt64(out _))
            return "integer; значение скрыто";
        if (element.TryGetDecimal(out _))
            return "decimal; значение скрыто";
        return "floating; значение скрыто";
    }

    private static string DescribeKind(JsonValueKind kind) => kind switch
    {
        JsonValueKind.Object => "object",
        JsonValueKind.Array => "array",
        JsonValueKind.String => "string",
        JsonValueKind.Number => "number",
        JsonValueKind.True or JsonValueKind.False => "boolean",
        JsonValueKind.Null => "null",
        _ => kind.ToString().ToLowerInvariant()
    };

    private static bool IsSensitiveName(string propertyName)
    {
        string normalized = propertyName.ToLowerInvariant();
        string[] markers =
        {
            "password", "passwd", "pass", "secret", "token", "credential",
            "private", "auth", "cookie", "key", "uuid", "user", "login",
            "server", "address", "host", "domain", "endpoint", "url", "ip"
        };

        return markers.Any(marker => normalized.Contains(marker, StringComparison.Ordinal));
    }

    private static string SanitizeLabel(string label)
    {
        string cleaned = label
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ')
            .Trim();

        if (cleaned.Length == 0)
            return "<empty-name>";

        if (Guid.TryParse(cleaned, out _))
            return "<uuid-field-name>";
        if (IPAddress.TryParse(cleaned, out _))
            return "<ip-field-name>";
        if (Uri.TryCreate(cleaned, UriKind.Absolute, out _))
            return "<uri-field-name>";

        bool looksOpaqueDynamicName =
            cleaned.Length >= 28 &&
            !cleaned.Any(char.IsWhiteSpace) &&
            cleaned.Count(character => char.IsLetterOrDigit(character) ||
                                       character is '-' or '_' or '+' or '/' or '=') >=
                (int)(cleaned.Length * 0.9);
        if (looksOpaqueDynamicName)
            return $"<opaque-field-name len={cleaned.Length}>";

        if (cleaned.Length > 80)
            return cleaned[..77] + "…";
        return cleaned;
    }

    private static bool CanAppend(InspectionState state)
    {
        if (state.Lines.Count < MaxLines)
            return true;

        state.Truncated = true;
        return false;
    }

    private static void AddLine(InspectionState state, string line)
    {
        if (CanAppend(state))
            state.Lines.Add(line);
    }

    private sealed class InspectionState
    {
        public List<string> Lines { get; } = new();
        public int EncodedJsonCount { get; set; }
        public int Base64Count { get; set; }
        public int UriCount { get; set; }
        public int UuidCount { get; set; }
        public int IpCount { get; set; }
        public bool Truncated { get; set; }
    }
}
