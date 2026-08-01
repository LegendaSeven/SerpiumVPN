using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace SerpiumVPN.Relay.Diagnostics;

/// <summary>
/// Produces user-visible diagnostics without exposing reusable VPN credentials.
/// This class never receives ownership of profile secrets and never writes files.
/// </summary>
public static class SensitiveDiagnosticRedactor
{
    private const int MaximumSafeLabelLength = 96;

    private static readonly Regex KeyUriRegex = new(
        @"(?i)\b(vless|vmess|trojan|avo)://[^\s""'<>]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex LongEncodedTokenRegex = new(
        @"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{80,}={0,2}(?![A-Za-z0-9+/_-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SensitiveParameterRegex = new(
        @"(?i)\b(uuid|id|password|passwd|token|secret|private_key|privatekey|pbk|sid|shortid|key)=([^&\s]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex UuidRegex = new(
        @"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex RepeatedWhitespaceRegex = new(
        @"\s+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static string RedactText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        string redacted = KeyUriRegex.Replace(
            value,
            match => match.Groups[1].Value.ToUpperInvariant() + "://[СКРЫТО]");

        redacted = LongEncodedTokenRegex.Replace(
            redacted,
            "[BASE64-КОНТЕЙНЕР СКРЫТ]");

        redacted = SensitiveParameterRegex.Replace(
            redacted,
            match => match.Groups[1].Value + "=[СКРЫТО]");

        redacted = UuidRegex.Replace(redacted, "[UUID СКРЫТ]");
        return redacted;
    }

    public static string MaskHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return "скрыт";

        string normalized = host.Trim().Trim('[', ']');

        if (IPAddress.TryParse(normalized, out IPAddress? address))
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = address.GetAddressBytes();
                return $"{bytes[0]}.•••.•••.{bytes[3]}";
            }

            string[] segments = normalized
                .Split(':', StringSplitOptions.RemoveEmptyEntries);

            if (segments.Length == 0)
                return "IPv6 скрыт";

            if (segments.Length == 1)
                return segments[0][..Math.Min(2, segments[0].Length)] + ":…";

            return segments[0] + ":…:" + segments[^1];
        }

        string[] labels = normalized.Split(
            '.',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (labels.Length == 0)
            return "скрыт";

        string first = MaskLabel(labels[0]);

        if (labels.Length == 1)
            return first;

        string last = labels[^1].Length <= 12
            ? labels[^1]
            : MaskLabel(labels[^1]);

        return first + "." + last;
    }

    public static string SanitizeProfileName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        string candidate = name
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Trim();

        int secretStart = FindFirstSecretMarker(candidate);
        if (secretStart >= 0)
        {
            candidate = candidate[..secretStart]
                .Trim(' ', '\t', '-', '—', '|', '•', ':', ';');
        }

        candidate = RepeatedWhitespaceRegex.Replace(
            RedactText(candidate),
            " ").Trim();

        if (candidate.Contains("[СКРЫТО]", StringComparison.Ordinal) ||
            candidate.Contains("[UUID СКРЫТ]", StringComparison.Ordinal) ||
            candidate.Contains("[BASE64-КОНТЕЙНЕР СКРЫТ]", StringComparison.Ordinal))
        {
            return "Имя скрыто — содержало параметры подключения";
        }

        if (string.IsNullOrWhiteSpace(candidate))
            return "Имя скрыто — содержало параметры подключения";

        if (candidate.Length > MaximumSafeLabelLength)
            candidate = candidate[..(MaximumSafeLabelLength - 1)].TrimEnd() + "…";

        return candidate;
    }

    private static int FindFirstSecretMarker(string value)
    {
        int earliest = -1;

        foreach (string marker in new[]
        {
            "vless://",
            "vmess://",
            "trojan://",
            "avo://"
        })
        {
            int index = value.IndexOf(
                marker,
                StringComparison.OrdinalIgnoreCase);

            if (index >= 0 && (earliest < 0 || index < earliest))
                earliest = index;
        }

        Match encodedMatch = LongEncodedTokenRegex.Match(value);
        if (encodedMatch.Success &&
            (earliest < 0 || encodedMatch.Index < earliest))
        {
            earliest = encodedMatch.Index;
        }

        return earliest;
    }

    private static string MaskLabel(string label)
    {
        if (string.IsNullOrWhiteSpace(label))
            return "••";

        if (label.Length <= 2)
            return new string('•', label.Length);

        int visible = Math.Min(2, label.Length);
        int hidden = Math.Clamp(label.Length - visible, 3, 14);

        return label[..visible] + new string('•', hidden);
    }
}
