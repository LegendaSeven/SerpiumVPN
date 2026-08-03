using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32;

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

            if (IsTrueOption(options, "sync-display-version-only"))
                return RunDisplayVersionSyncOnly(options);

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

            SynchronizeInstalledDisplayVersion(updatedExePath, targetDir);

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

    private static string Require(
        IReadOnlyDictionary<string, string> options,
        string key)
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

    private const string UninstallRegistryPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    private static bool IsTrueOption(
        IReadOnlyDictionary<string, string> options,
        string key)
    {
        return options.TryGetValue(key, out string? value) &&
               bool.TryParse(value, out bool parsed) &&
               parsed;
    }

    private static int RunDisplayVersionSyncOnly(
        IReadOnlyDictionary<string, string> options)
    {
        string targetDir = Path.GetFullPath(Require(options, "target"));
        string updatedExePath = Path.GetFullPath(Require(options, "exe"));

        if (!Directory.Exists(targetDir))
        {
            Log($"DisplayVersion sync target directory not found: {targetDir}");
            return 2;
        }

        if (!File.Exists(updatedExePath))
        {
            Log($"DisplayVersion sync executable not found: {updatedExePath}");
            return 2;
        }

        string? version = GetUpdatedApplicationVersion(updatedExePath);
        if (string.IsNullOrWhiteSpace(version))
        {
            Log($"DisplayVersion sync could not read version from: {updatedExePath}");
            return 3;
        }

        bool updated = TryUpdateInstalledDisplayVersion(
            updatedExePath,
            targetDir,
            version,
            out bool accessDenied,
            out int matchedCount);

        Log(
            $"Elevated DisplayVersion sync result: updated={updated}; " +
            $"matched={matchedCount}; accessDenied={accessDenied}; version={version}.");

        return updated ? 0 : 4;
    }

    private static void SynchronizeInstalledDisplayVersion(
        string updatedExePath,
        string targetDir)
    {
        try
        {
            string? version = GetUpdatedApplicationVersion(updatedExePath);
            if (string.IsNullOrWhiteSpace(version))
            {
                Log(
                    "DisplayVersion sync skipped: application version " +
                    $"could not be read from {updatedExePath}.");
                return;
            }

            bool updated = TryUpdateInstalledDisplayVersion(
                updatedExePath,
                targetDir,
                version,
                out bool accessDenied,
                out int matchedCount);

            if (updated)
            {
                Log(
                    $"Windows installed-app version synchronized to {version}. " +
                    $"Matching uninstall entries: {matchedCount}.");
                return;
            }

            if (accessDenied && !IsCurrentProcessElevated())
            {
                Log(
                    "Matching uninstall entry requires elevation. " +
                    "Requesting one-time UAC approval for DisplayVersion sync.");

                if (TryRunElevatedDisplayVersionSync(updatedExePath, targetDir))
                {
                    Log(
                        $"Windows installed-app version synchronized to {version} " +
                        "by elevated helper.");
                    return;
                }
            }

            if (matchedCount == 0)
            {
                Log(
                    "DisplayVersion sync warning: no Serpium VPN uninstall entry " +
                    $"matched installation directory {targetDir}.");
            }
            else if (accessDenied)
            {
                Log(
                    "DisplayVersion sync warning: matching uninstall entry was found, " +
                    "but Windows denied registry write access.");
            }
            else
            {
                Log(
                    "DisplayVersion sync warning: matching uninstall entry was found, " +
                    "but its version was not updated.");
            }
        }
        catch (Exception ex)
        {
            Log(
                "DisplayVersion sync warning: " +
                ex.GetType().Name +
                ": " +
                ex.Message);
        }
    }

    private static string? GetUpdatedApplicationVersion(string updatedExePath)
    {
        FileVersionInfo info = FileVersionInfo.GetVersionInfo(updatedExePath);

        return NormalizeDisplayVersion(info.FileVersion) ??
               NormalizeDisplayVersion(info.ProductVersion);
    }

    private static string? NormalizeDisplayVersion(string? rawVersion)
    {
        if (string.IsNullOrWhiteSpace(rawVersion))
            return null;

        string candidate = rawVersion.Trim();

        int metadataIndex = candidate.IndexOf('+');
        if (metadataIndex >= 0)
            candidate = candidate[..metadataIndex];

        int suffixIndex = candidate.IndexOf('-');
        if (suffixIndex >= 0)
            candidate = candidate[..suffixIndex];

        candidate = candidate.Trim();

        if (!Version.TryParse(candidate, out Version? parsed))
            return null;

        if (parsed.Revision >= 0)
        {
            return string.Join(
                ".",
                parsed.Major,
                parsed.Minor,
                parsed.Build,
                parsed.Revision);
        }

        if (parsed.Build >= 0)
        {
            return string.Join(
                ".",
                parsed.Major,
                parsed.Minor,
                parsed.Build);
        }

        return string.Join(".", parsed.Major, parsed.Minor);
    }

    private static bool TryUpdateInstalledDisplayVersion(
        string updatedExePath,
        string targetDir,
        string version,
        out bool accessDenied,
        out int matchedCount)
    {
        accessDenied = false;
        matchedCount = 0;
        bool updated = false;

        (RegistryHive Hive, RegistryView View)[] locations =
        [
            (RegistryHive.LocalMachine, RegistryView.Registry64),
            (RegistryHive.LocalMachine, RegistryView.Registry32),
            (RegistryHive.CurrentUser, RegistryView.Registry64),
            (RegistryHive.CurrentUser, RegistryView.Registry32)
        ];

        foreach ((RegistryHive hive, RegistryView view) in locations)
        {
            try
            {
                using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
                using RegistryKey? uninstallKey =
                    baseKey.OpenSubKey(UninstallRegistryPath, writable: false);

                if (uninstallKey is null)
                    continue;

                foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                {
                    using RegistryKey? candidateKey =
                        uninstallKey.OpenSubKey(subKeyName, writable: false);

                    if (candidateKey is null)
                        continue;

                    try
                    {
                        string? displayName =
                            candidateKey.GetValue("DisplayName") as string;

                        if (!IsSerpiumDisplayName(displayName))
                            continue;

                        if (!MatchesInstallation(
                                candidateKey,
                                updatedExePath,
                                targetDir))
                        {
                            continue;
                        }

                        matchedCount++;

                        using RegistryKey? writableKey =
                            uninstallKey.OpenSubKey(subKeyName, writable: true);

                        if (writableKey is null)
                        {
                            accessDenied = true;
                            Log(
                                $"DisplayVersion write access unavailable: " +
                                $"{hive}/{view}/{subKeyName}.");
                            continue;
                        }

                        string previousVersion =
                            writableKey.GetValue("DisplayVersion") as string ??
                            "<missing>";

                        writableKey.SetValue(
                            "DisplayVersion",
                            version,
                            RegistryValueKind.String);
                        writableKey.Flush();

                        updated = true;

                        Log(
                            $"DisplayVersion updated: {previousVersion} -> {version}; " +
                            $"location={hive}/{view}/{subKeyName}.");
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        accessDenied = true;
                        Log(
                            $"DisplayVersion access denied: " +
                            $"{hive}/{view}/{subKeyName}: {ex.Message}");
                    }
                    catch (SecurityException ex)
                    {
                        accessDenied = true;
                        Log(
                            $"DisplayVersion security error: " +
                            $"{hive}/{view}/{subKeyName}: {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        Log(
                            $"Uninstall entry skipped: " +
                            $"{hive}/{view}/{subKeyName}: " +
                            $"{ex.GetType().Name}: {ex.Message}");
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                accessDenied = true;
                Log(
                    $"Uninstall registry access denied: {hive}/{view}: {ex.Message}");
            }
            catch (SecurityException ex)
            {
                accessDenied = true;
                Log(
                    $"Uninstall registry security error: {hive}/{view}: {ex.Message}");
            }
            catch (PlatformNotSupportedException ex)
            {
                Log(
                    $"Registry view unavailable: {hive}/{view}: {ex.Message}");
            }
            catch (IOException ex)
            {
                Log(
                    $"Registry view read error: {hive}/{view}: {ex.Message}");
            }
        }

        return updated;
    }

    private static bool IsSerpiumDisplayName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
            return false;

        string normalized = new(
            displayName
                .Where(char.IsLetterOrDigit)
                .Select(char.ToLowerInvariant)
                .ToArray());

        return normalized.StartsWith(
            "serpiumvpn",
            StringComparison.Ordinal);
    }

    private static bool MatchesInstallation(
        RegistryKey candidateKey,
        string updatedExePath,
        string targetDir)
    {
        string normalizedTargetDir = NormalizeDirectoryPath(targetDir);
        string normalizedUpdatedExe = NormalizeFilePath(updatedExePath);

        string? installLocation =
            candidateKey.GetValue("InstallLocation") as string;

        if (!string.IsNullOrWhiteSpace(installLocation) &&
            string.Equals(
                NormalizeDirectoryPath(installLocation),
                normalizedTargetDir,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        foreach (string valueName in new[]
                 {
                     "DisplayIcon",
                     "UninstallString",
                     "QuietUninstallString"
                 })
        {
            string? rawValue = candidateKey.GetValue(valueName) as string;
            string? executablePath = ExtractExecutablePath(rawValue);

            if (string.IsNullOrWhiteSpace(executablePath))
                continue;

            string normalizedExecutable = NormalizeFilePath(executablePath);

            if (string.Equals(
                    normalizedExecutable,
                    normalizedUpdatedExe,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string? executableDirectory =
                Path.GetDirectoryName(normalizedExecutable);

            if (!string.IsNullOrWhiteSpace(executableDirectory) &&
                string.Equals(
                    NormalizeDirectoryPath(executableDirectory),
                    normalizedTargetDir,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? ExtractExecutablePath(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
            return null;

        string value = Environment
            .ExpandEnvironmentVariables(rawValue)
            .Trim();

        if (value.StartsWith('"'))
        {
            int closingQuote = value.IndexOf('"', 1);
            if (closingQuote > 1)
                return value[1..closingQuote];
        }

        int exeIndex = value.IndexOf(
            ".exe",
            StringComparison.OrdinalIgnoreCase);

        if (exeIndex >= 0)
            return value[..(exeIndex + 4)].Trim().Trim('"');

        return value.Trim('"');
    }

    private static string NormalizeDirectoryPath(string path)
    {
        string expanded = Environment
            .ExpandEnvironmentVariables(path)
            .Trim()
            .Trim('"');

        return Path.GetFullPath(expanded)
            .TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar);
    }

    private static string NormalizeFilePath(string path)
    {
        string expanded = Environment
            .ExpandEnvironmentVariables(path)
            .Trim()
            .Trim('"');

        return Path.GetFullPath(expanded);
    }

    private static bool IsCurrentProcessElevated()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);

            return principal.IsInRole(
                WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryRunElevatedDisplayVersionSync(
        string updatedExePath,
        string targetDir)
    {
        string? updaterPath = Environment.ProcessPath;

        if (string.IsNullOrWhiteSpace(updaterPath) ||
            !File.Exists(updaterPath))
        {
            Log(
                "Elevated DisplayVersion sync skipped: " +
                "current updater executable path is unavailable.");
            return false;
        }

        try
        {
            ProcessStartInfo startInfo = new()
            {
                FileName = updaterPath,
                WorkingDirectory =
                    Path.GetDirectoryName(updaterPath) ??
                    Path.GetTempPath(),
                UseShellExecute = true,
                Verb = "runas"
            };

            startInfo.ArgumentList.Add("--sync-display-version-only");
            startInfo.ArgumentList.Add("true");
            startInfo.ArgumentList.Add("--target");
            startInfo.ArgumentList.Add(targetDir);
            startInfo.ArgumentList.Add("--exe");
            startInfo.ArgumentList.Add(updatedExePath);

            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                Log(
                    "Elevated DisplayVersion sync failed: " +
                    "Process.Start returned null.");
                return false;
            }

            if (!process.WaitForExit(30000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                }

                Log(
                    "Elevated DisplayVersion sync timed out after 30 seconds.");
                return false;
            }

            if (process.ExitCode != 0)
            {
                Log(
                    $"Elevated DisplayVersion sync exited with code " +
                    $"{process.ExitCode}.");
                return false;
            }

            return true;
        }
        catch (Win32Exception ex)
        {
            Log(
                "Elevated DisplayVersion sync was cancelled or failed: " +
                ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            Log(
                "Elevated DisplayVersion sync failed: " +
                ex.GetType().Name +
                ": " +
                ex.Message);
            return false;
        }
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
