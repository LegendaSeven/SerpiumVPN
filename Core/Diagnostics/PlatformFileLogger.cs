using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SerpiumVPN.Core;

/// <summary>
/// Minimal process-safe logger for platform bootstrap, engine discovery and component lifecycle.
/// Logging failures are intentionally ignored so diagnostics can never crash SerpiumVPN.
/// </summary>
public sealed class PlatformFileLogger
{
    private const long RotationThresholdBytes = 2 * 1024 * 1024;

    private static readonly Regex KeyUriRegex = new(
        @"(?i)\b(vless|vmess|trojan|avo)://[^\s""'<>]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex UuidRegex = new(
        @"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex LongEncodedTokenRegex = new(
        @"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{80,}={0,2}(?![A-Za-z0-9+/_-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SensitiveAssignmentRegex = new(
        @"(?i)\b(auth[-_]?key|preauth[-_]?key|password|passwd|token|secret|private[-_]?key|pbk|sid|shortid|uuid)\s*[:=]\s*([^\s,;""']+|""[^""]*"")",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly object _sync = new();

    public PlatformFileLogger(string logPath)
    {
        if (string.IsNullOrWhiteSpace(logPath))
        {
            throw new ArgumentException("Log path cannot be empty.", nameof(logPath));
        }

        LogPath = Path.GetFullPath(logPath);
        PrepareLogFile();
    }

    public string LogPath { get; }

    public static PlatformFileLogger CreateDefault()
    {
        string localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);

        string logPath = Path.Combine(
            localAppData,
            "SerpiumVPN",
            "Logs",
            "platform-runtime.log");

        return new PlatformFileLogger(logPath);
    }

    public void Write(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return;

        string safeMessage = RedactSensitiveText(message);
        string line =
            $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} " +
            safeMessage +
            Environment.NewLine;

        lock (_sync)
        {
            try
            {
                Directory.CreateDirectory(
                    Path.GetDirectoryName(LogPath)
                    ?? AppContext.BaseDirectory);

                File.AppendAllText(LogPath, line, new UTF8Encoding(false));
            }
            catch
            {
                // Diagnostics must never alter application behavior.
            }
        }
    }

    private static string RedactSensitiveText(string value)
    {
        string redacted = KeyUriRegex.Replace(
            value,
            match => match.Groups[1].Value.ToUpperInvariant() + "://[REDACTED]");

        redacted = UuidRegex.Replace(redacted, "[UUID REDACTED]");
        redacted = LongEncodedTokenRegex.Replace(
            redacted,
            "[ENCODED TOKEN REDACTED]");

        redacted = SensitiveAssignmentRegex.Replace(
            redacted,
            match => match.Groups[1].Value + "=[REDACTED]");

        return redacted;
    }

    private static void SanitizeExistingLog(string path)
    {
        try
        {
            if (!File.Exists(path))
                return;

            FileInfo info = new(path);
            if (info.Length > 8 * 1024 * 1024)
            {
                File.Delete(path);
                return;
            }

            string original = File.ReadAllText(path, Encoding.UTF8);
            string sanitized = RedactSensitiveText(original);

            if (!string.Equals(
                    original,
                    sanitized,
                    StringComparison.Ordinal))
            {
                File.WriteAllText(
                    path,
                    sanitized,
                    new UTF8Encoding(false));
            }
        }
        catch
        {
            // Existing diagnostic history is optional.
        }
    }

    private void PrepareLogFile()
    {
        lock (_sync)
        {
            try
            {
                string directory = Path.GetDirectoryName(LogPath)
                    ?? AppContext.BaseDirectory;

                Directory.CreateDirectory(directory);
                SanitizeExistingLog(LogPath);

                if (!File.Exists(LogPath) ||
                    new FileInfo(LogPath).Length < RotationThresholdBytes)
                {
                    return;
                }

                string previousLogPath = Path.Combine(
                    directory,
                    "platform-runtime.previous.log");

                File.Move(LogPath, previousLogPath, overwrite: true);
                SanitizeExistingLog(previousLogPath);
            }
            catch
            {
                // Rotation is optional; normal logging will retry on the next write.
            }
        }
    }
}
