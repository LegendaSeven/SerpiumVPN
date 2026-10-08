using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN.Relay.Lifecycle;

/// <summary>
/// Removes only Serpium-owned relay processes and generated non-vault runtime files.
/// Secure Profile Vault data is never read or changed here.
/// </summary>
public static class RelayLifecycleRecovery
{
    private static readonly string[] OwnedProcessNames =
    [
        "xray",
        "sing-box"
    ];

    private static readonly string[] GeneratedRuntimeFiles =
    [
        Path.Combine("configs", "key-client.json"),
        Path.Combine("configs", "key-client.json.tmp"),
        Path.Combine("state", "sing-box-tun-process.json"),
        Path.Combine("state", "xray-client-process.json"),
        Path.Combine("state", "xray-process.json"),
        Path.Combine("state", "key-client-process.json")
    ];

    public static async Task<RelayLifecycleCleanupResult> CleanupOwnedRuntimeAsync(
        string applicationBaseDirectory,
        CancellationToken cancellationToken = default)
    {
        string relayDirectory = GetRelayDirectory(applicationBaseDirectory);
        int processesStopped = 0;

        foreach (string processName in OwnedProcessNames)
        {
            foreach (Process process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    string? executablePath = TryGetExecutablePath(process);
                    if (string.IsNullOrWhiteSpace(executablePath))
                        continue;

                    bool relayOwned =
                        IsInsideDirectory(
                            executablePath,
                            relayDirectory);
                    if (!relayOwned)
                        continue;

                    try
                    {
                        if (!process.HasExited)
                        {
                            process.Kill(entireProcessTree: true);
                            await process.WaitForExitAsync(cancellationToken);
                            processesStopped++;
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        // The process exited between enumeration and cleanup.
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        // Access can disappear while the process is terminating.
                    }
                }
            }
        }

        int filesDeleted = DeleteGeneratedSecrets(applicationBaseDirectory);
        filesDeleted += await DeletePrivateRuntimeResidueWithRetryAsync(cancellationToken).ConfigureAwait(false);
        return new RelayLifecycleCleanupResult(processesStopped, filesDeleted);
    }

    public static int DeleteGeneratedSecrets(string applicationBaseDirectory)
    {
        string relayDirectory = GetRelayDirectory(applicationBaseDirectory);
        int deleted = 0;

        foreach (string relativePath in GeneratedRuntimeFiles)
        {
            string path = Path.Combine(relayDirectory, relativePath);
            try
            {
                if (!File.Exists(path))
                    continue;

                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                if (!File.Exists(path))
                    deleted++;
            }
            catch (IOException)
            {
                // A running manager may still own the file; the next lifecycle pass retries.
            }
            catch (UnauthorizedAccessException)
            {
                // Cleanup is best effort and never weakens Vault access controls.
            }
        }

        TryDeleteEmptyDirectory(Path.Combine(relayDirectory, "configs"));
        return deleted;
    }

    private static async Task<int> DeletePrivateRuntimeResidueWithRetryAsync(
        CancellationToken cancellationToken)
    {
        int deleted = 0;

        for (int attempt = 0; attempt < 6; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            deleted += DeletePrivateXrayRuntimeFiles();
            deleted += DeleteDynamicRoutingRuleSet();

            if (!HasPrivateRuntimeResidue())
                break;

            if (attempt < 5)
            {
                await Task.Delay(100, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        return deleted;
    }

    private static int DeletePrivateXrayRuntimeFiles()
    {
        string runtimeRoot = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "SerpiumVPN",
            "Runtime");

        string[] paths =
        [
            Path.Combine(runtimeRoot, "Xray", "key-client.json"),
            Path.Combine(runtimeRoot, "state", "key-client-process.json")
        ];

        int deleted = 0;

        foreach (string path in paths)
        {
            try
            {
                if (!File.Exists(path))
                    continue;

                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);

                if (!File.Exists(path))
                    deleted++;
            }
            catch (IOException)
            {
                // The manager/Exited callback may still be releasing the file.
            }
            catch (UnauthorizedAccessException)
            {
                // A later retry runs under the same application identity.
            }
        }

        TryDeleteEmptyDirectory(Path.Combine(runtimeRoot, "Xray"));
        TryDeleteEmptyDirectory(Path.Combine(runtimeRoot, "state"));

        return deleted;
    }

    private static bool HasPrivateRuntimeResidue()
    {
        string runtimeRoot = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "SerpiumVPN",
            "Runtime");

        if (File.Exists(
                Path.Combine(runtimeRoot, "Xray", "key-client.json")) ||
            File.Exists(
                Path.Combine(
                    runtimeRoot,
                    "state",
                    "key-client-process.json")))
        {
            return true;
        }

        string routingDirectory = Path.Combine(runtimeRoot, "Routing");
        if (!Directory.Exists(routingDirectory))
            return false;

        try
        {
            return Directory.EnumerateFiles(
                routingDirectory,
                "serpium-routing-live.json*",
                SearchOption.TopDirectoryOnly).Any();
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }
    private static int DeleteDynamicRoutingRuleSet()
    {
        string runtimeDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SerpiumVPN",
            "Runtime",
            "Routing");
        int deleted = 0;

        try
        {
            if (!Directory.Exists(runtimeDirectory))
                return 0;

            foreach (string path in Directory.EnumerateFiles(
                runtimeDirectory,
                "serpium-routing-live.json*",
                SearchOption.TopDirectoryOnly))
            {
                try
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                    if (!File.Exists(path))
                        deleted++;
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            TryDeleteEmptyDirectory(runtimeDirectory);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        return deleted;
    }

    private static string GetRelayDirectory(string applicationBaseDirectory)
    {
        string baseDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(applicationBaseDirectory));
        return Path.GetFullPath(Path.Combine(baseDirectory, "bin_files", "relay"));
    }

    private static string? TryGetExecutablePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private static bool IsInsideDirectory(string filePath, string directory)
    {
        string fullFilePath = Path.GetFullPath(filePath);
        string directoryPrefix =
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) +
            Path.DirectorySeparatorChar;

        return fullFilePath.StartsWith(
            directoryPrefix,
            StringComparison.OrdinalIgnoreCase);
    }

    private static void TryDeleteEmptyDirectory(string directory)
    {
        try
        {
            if (Directory.Exists(directory) &&
                !Directory.EnumerateFileSystemEntries(directory).Any())
            {
                Directory.Delete(directory, recursive: false);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

public sealed record RelayLifecycleCleanupResult(
    int ProcessesStopped,
    int FilesDeleted);
