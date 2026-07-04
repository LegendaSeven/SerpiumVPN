using System.Diagnostics;
using System.IO.Compression;

namespace SerpiumUpdater;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            Dictionary<string, string> options = ParseArgs(args);

            string targetDir = Require(options, "target");
            string zipPath = Require(options, "zip");
            string exePath = Require(options, "exe");

            if (options.TryGetValue("pid", out string? pidValue) &&
                int.TryParse(pidValue, out int pid))
            {
                WaitForProcessExit(pid);
            }

            if (!Directory.Exists(targetDir))
                throw new DirectoryNotFoundException($"Target directory not found: {targetDir}");

            if (!File.Exists(zipPath))
                throw new FileNotFoundException($"Update archive not found: {zipPath}");

            string stagingDir = Path.Combine(Path.GetTempPath(), "SerpiumVPN_update_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stagingDir);

            try
            {
                ZipFile.ExtractToDirectory(zipPath, stagingDir, overwriteFiles: true);
                CopyDirectory(stagingDir, targetDir);
            }
            finally
            {
                TryDeleteDirectory(stagingDir);
                TryDeleteFile(zipPath);
            }

            StartApp(exePath);
            return 0;
        }
        catch (Exception ex)
        {
            string logPath = Path.Combine(Path.GetTempPath(), "SerpiumUpdater_error.log");
            File.WriteAllText(logPath, ex.ToString());
            return 1;
        }
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        Dictionary<string, string> result = new(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
                continue;

            string key = arg[2..];
            if (i + 1 >= args.Length)
                throw new ArgumentException($"Missing value for argument: {arg}");

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
            process.WaitForExit(30000);
        }
        catch
        {
            // The app may already be closed.
        }
    }

    private static void CopyDirectory(string sourceDir, string targetDir)
    {
        foreach (string sourcePath in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            string relativePath = Path.GetRelativePath(sourceDir, sourcePath);
            if (ShouldSkip(relativePath))
                continue;

            string targetPath = Path.Combine(targetDir, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            File.Copy(sourcePath, targetPath, overwrite: true);
        }
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

    private static void StartApp(string exePath)
    {
        if (!File.Exists(exePath))
            return;

        Process.Start(new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true
        });
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            // best effort cleanup
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // best effort cleanup
        }
    }
}
