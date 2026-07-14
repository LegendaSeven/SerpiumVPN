using System.Diagnostics;
using System.IO.Compression;

namespace SerpiumUpdater;

internal static class Program
{
    private static readonly string LogPath = Path.Combine(Path.GetTempPath(), "SerpiumUpdater.log");

    private static int Main(string[] args)
    {
        try
        {
            Log("Updater started. Args: " + string.Join(" | ", args));
            Dictionary<string, string> options = ParseArgs(args);

            string targetDir = Path.GetFullPath(Require(options, "target"));
            string zipPath = Path.GetFullPath(Require(options, "zip"));
            string originalExePath = Path.GetFullPath(Require(options, "exe"));
            string updatedExePath = Path.Combine(targetDir, Path.GetFileName(originalExePath));

            if (options.TryGetValue("pid", out string? pidValue) && int.TryParse(pidValue, out int pid))
                WaitForProcessExit(pid);

            if (!Directory.Exists(targetDir))
                throw new DirectoryNotFoundException($"Target directory not found: {targetDir}");
            if (!File.Exists(zipPath))
                throw new FileNotFoundException($"Update archive not found: {zipPath}");

            string stagingDir = Path.Combine(Path.GetTempPath(), "SerpiumVPN_update_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stagingDir);
            Log($"Extracting {zipPath} to {stagingDir}");

            try
            {
                ZipFile.ExtractToDirectory(zipPath, stagingDir, overwriteFiles: true);
                Log($"Copying update to {targetDir}");
                CopyDirectory(stagingDir, targetDir);
            }
            finally
            {
                TryDeleteDirectory(stagingDir);
                TryDeleteFile(zipPath);
            }

            if (!File.Exists(updatedExePath))
                throw new FileNotFoundException($"Updated application executable not found: {updatedExePath}");

            Log($"Starting updated app: {updatedExePath}");
            StartApp(updatedExePath, targetDir);
            Log("Update completed successfully.");
            return 0;
        }
        catch (Exception ex)
        {
            Log("FATAL: " + ex);
            try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "SerpiumUpdater_error.log"), ex.ToString()); } catch { }
            return 1;
        }
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        Dictionary<string, string> result = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal)) continue;
            string key = arg[2..];
            if (i + 1 >= args.Length) throw new ArgumentException($"Missing value for argument: {arg}");
            result[key] = args[++i];
        }
        return result;
    }

    private static string Require(Dictionary<string, string> options, string key)
    {
        if (!options.TryGetValue(key, out string? value) || string.IsNullOrWhiteSpace(value))
            throw new ArgumentException($"Missing required argument: --{key}");
        return value;
    }

    private static void WaitForProcessExit(int pid)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            Log($"Waiting for main app PID {pid} to exit...");
            if (!process.WaitForExit(30000))
                throw new TimeoutException($"Main application PID {pid} did not exit within 30 seconds.");
            Log("Main app exited.");
        }
        catch (ArgumentException)
        {
            Log("Main app was already closed.");
        }
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
    {
        foreach (string sourcePath in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            string relativePath = Path.GetRelativePath(sourceDir, sourcePath);
            if (ShouldSkip(relativePath)) continue;

            string targetPath = Path.Combine(targetDir, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            CopyFileWithRetry(sourcePath, targetPath);
        }
    }

    private static void CopyFileWithRetry(string sourcePath, string targetPath)
    {
        if (FilesAreIdentical(sourcePath, targetPath))
        {
            Log($"Unchanged file skipped: {targetPath}");
            return;
        }

        Exception? last = null;
        for (int attempt = 1; attempt <= 10; attempt++)
        {
            try
            {
                File.Copy(sourcePath, targetPath, overwrite: true);
                return;
            }
            catch (IOException ex)
            {
                last = ex;
                Log($"Copy retry {attempt}/10: {targetPath}: {ex.Message}");
                Thread.Sleep(500);
            }
            catch (UnauthorizedAccessException ex)
            {
                last = ex;
                Log($"Access retry {attempt}/10: {targetPath}: {ex.Message}");
                Thread.Sleep(500);
            }
        }

        if (IsSkippableLockedFile(targetPath))
        {
            Log($"Locked WinDivert runtime file skipped: {targetPath}");
            return;
        }

        throw new IOException($"Failed to replace file after retries: {targetPath}", last);
    }

    private static bool FilesAreIdentical(string sourcePath, string targetPath)
    {
        if (!File.Exists(targetPath))
            return false;

        FileInfo sourceInfo = new(sourcePath);
        FileInfo targetInfo = new(targetPath);

        if (sourceInfo.Length != targetInfo.Length)
            return false;

        using FileStream sourceStream = File.OpenRead(sourcePath);
        using FileStream targetStream = File.OpenRead(targetPath);

        byte[] sourceHash = System.Security.Cryptography.SHA256.HashData(sourceStream);
        byte[] targetHash = System.Security.Cryptography.SHA256.HashData(targetStream);

        return sourceHash.AsSpan().SequenceEqual(targetHash);
    }

    private static bool IsSkippableLockedFile(string targetPath)
    {
        string fileName = Path.GetFileName(targetPath);

        return fileName.Equals("WinDivert64.sys", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("WinDivert32.sys", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("WinDivert.dll", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("WinDivert64.dll", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("WinDivert32.dll", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldSkip(string relativePath)
    {
        string normalized = relativePath.Replace('\\', '/');
        return normalized.StartsWith("bin_files/logs/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("bin_files/tgws/TgWsProxy_data/", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("bin_files/serpium.runtime.json", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("bin_files/vendor_versions.json", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith("-user.txt", StringComparison.OrdinalIgnoreCase);
    }

    private static void StartApp(string exePath, string workingDirectory)
    {
        Process? process = Process.Start(new ProcessStartInfo
        {
            FileName = exePath,
            WorkingDirectory = workingDirectory,
            UseShellExecute = true
        });
        if (process is null) throw new InvalidOperationException($"Failed to start updated application: {exePath}");
    }

    private static void Log(string message)
    {
        try { File.AppendAllText(LogPath, $"{DateTime.Now:O} {message}{Environment.NewLine}"); } catch { }
    }

    private static void TryDeleteDirectory(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { } }
    private static void TryDeleteFile(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}
