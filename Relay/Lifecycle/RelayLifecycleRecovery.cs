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
        Path.Combine("state", "xray-process.json")
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
                    if (string.IsNullOrWhiteSpace(executablePath) ||
                        !IsInsideDirectory(executablePath, relayDirectory))
                    {
                        continue;
                    }

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
