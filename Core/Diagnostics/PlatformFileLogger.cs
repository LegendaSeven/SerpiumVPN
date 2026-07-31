using System;
using System.IO;
using System.Text;

namespace SerpiumVPN.Core;

/// <summary>
/// Minimal process-safe logger for platform bootstrap, engine discovery and component lifecycle.
/// Logging failures are intentionally ignored so diagnostics can never crash SerpiumVPN.
/// </summary>
public sealed class PlatformFileLogger
{
    private const long RotationThresholdBytes = 2 * 1024 * 1024;
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

        string line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} {message}{Environment.NewLine}";

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

    private void PrepareLogFile()
    {
        lock (_sync)
        {
            try
            {
                string directory = Path.GetDirectoryName(LogPath)
                    ?? AppContext.BaseDirectory;

                Directory.CreateDirectory(directory);

                if (!File.Exists(LogPath) ||
                    new FileInfo(LogPath).Length < RotationThresholdBytes)
                {
                    return;
                }

                string previousLogPath = Path.Combine(
                    directory,
                    "platform-runtime.previous.log");

                File.Move(LogPath, previousLogPath, overwrite: true);
            }
            catch
            {
                // Rotation is optional; normal logging will retry on the next write.
            }
        }
    }
}
