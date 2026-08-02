using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Owns the private local sing-box rule-set used for live route updates.
/// The file contains only enabled application paths and domain rules; VPN keys
/// and provider configuration never enter this runtime directory.
/// </summary>
public sealed class SecureRoutingRuleSetRuntime : IDisposable
{
    private const string RuleSetFileName = "serpium-routing-live.json";
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;

    public SecureRoutingRuleSetRuntime()
    {
        RuntimeDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SerpiumVPN",
            "Runtime",
            "Routing");
        RuleSetPath = Path.Combine(RuntimeDirectory, RuleSetFileName);
    }

    public string RuntimeDirectory { get; }
    public string RuleSetPath { get; }
    public bool IsPrepared => File.Exists(RuleSetPath);

    public async Task<RoutingRuleSetUpdateResult> UpdateAsync(
        IReadOnlyList<RoutingRegistryEntry> entries,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(entries);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        byte[]? ruleSetUtf8 = null;
        string? temporaryPath = null;
        try
        {
            EnsurePrivateRuntimeDirectory();
            ruleSetUtf8 = SerpiumRoutingConfigCompiler.BuildRuleSetSource(entries);
            temporaryPath = RuleSetPath + "." + Guid.NewGuid().ToString("N") + ".tmp";

            await using (FileStream stream = new(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(ruleSetUtf8, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, RuleSetPath, overwrite: true);
            temporaryPath = null;

            try
            {
                File.SetAttributes(
                    RuleSetPath,
                    FileAttributes.Hidden | FileAttributes.NotContentIndexed);
            }
            catch (ArgumentException)
            {
                // NotContentIndexed support depends on the file system.
                File.SetAttributes(RuleSetPath, FileAttributes.Hidden);
            }

            byte[] persisted = await File.ReadAllBytesAsync(
                RuleSetPath,
                cancellationToken).ConfigureAwait(false);
            byte[] expectedHash = SHA256.HashData(ruleSetUtf8);
            byte[] persistedHash = SHA256.HashData(persisted);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(
                        expectedHash,
                        persistedHash))
                {
                    throw new IOException(
                        "Проверка записанного dynamic rule-set не пройдена.");
                }

                using JsonDocument document = JsonDocument.Parse(persisted);
                JsonElement root = document.RootElement;
                if (!root.TryGetProperty("version", out JsonElement version) ||
                    version.GetInt32() != 3 ||
                    !root.TryGetProperty("rules", out JsonElement rules) ||
                    rules.ValueKind != JsonValueKind.Array)
                {
                    throw new FormatException(
                        "Записанный dynamic rule-set имеет неверную структуру.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedHash);
                CryptographicOperations.ZeroMemory(persistedHash);
                CryptographicOperations.ZeroMemory(persisted);
            }

            return new RoutingRuleSetUpdateResult(
                entries.Count(entry => entry.IsEnabled),
                ruleSetUtf8.Length,
                DateTimeOffset.UtcNow);
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(temporaryPath))
            {
                try { File.Delete(temporaryPath); } catch { }
            }

            if (ruleSetUtf8 is not null)
                CryptographicOperations.ZeroMemory(ruleSetUtf8);

            _gate.Release();
        }
    }

    public void DeleteBestEffort()
    {
        for (int attempt = 0; attempt < 6; attempt++)
        {
            bool residueRemains = false;

            try
            {
                if (File.Exists(RuleSetPath))
                {
                    File.SetAttributes(
                        RuleSetPath,
                        FileAttributes.Normal);
                    File.Delete(RuleSetPath);
                }

                if (Directory.Exists(RuntimeDirectory))
                {
                    foreach (string temporaryPath in
                        Directory.EnumerateFiles(
                            RuntimeDirectory,
                            RuleSetFileName + ".*.tmp",
                            SearchOption.TopDirectoryOnly).ToArray())
                    {
                        try
                        {
                            File.SetAttributes(
                                temporaryPath,
                                FileAttributes.Normal);
                            File.Delete(temporaryPath);
                        }
                        catch (IOException)
                        {
                            residueRemains = true;
                        }
                        catch (UnauthorizedAccessException)
                        {
                            residueRemains = true;
                        }
                    }

                    residueRemains =
                        residueRemains ||
                        File.Exists(RuleSetPath) ||
                        Directory.EnumerateFiles(
                            RuntimeDirectory,
                            RuleSetFileName + ".*",
                            SearchOption.TopDirectoryOnly).Any();

                    if (!residueRemains &&
                        !Directory.EnumerateFileSystemEntries(
                            RuntimeDirectory).Any())
                    {
                        Directory.Delete(
                            RuntimeDirectory,
                            recursive: false);
                    }
                }

                if (!residueRemains)
                    return;
            }
            catch (IOException)
            {
                residueRemains = true;
            }
            catch (UnauthorizedAccessException)
            {
                residueRemains = true;
            }

            if (residueRemains && attempt < 5)
                Thread.Sleep(100);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        DeleteBestEffort();
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    private void EnsurePrivateRuntimeDirectory()
    {
        Directory.CreateDirectory(RuntimeDirectory);

        SecurityIdentifier currentUser =
            WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "Не удалось определить SID текущего пользователя.");
        SecurityIdentifier system = new(
            WellKnownSidType.LocalSystemSid,
            domainSid: null);
        SecurityIdentifier administrators = new(
            WellKnownSidType.BuiltinAdministratorsSid,
            domainSid: null);

        DirectorySecurity security = new();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(currentUser);

        InheritanceFlags inheritance =
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit;

        foreach (SecurityIdentifier sid in new[]
        {
            currentUser,
            system,
            administrators
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        new DirectoryInfo(RuntimeDirectory).SetAccessControl(security);
    }
}

public sealed record RoutingRuleSetUpdateResult(
    int EnabledRuleCount,
    int ByteCount,
    DateTimeOffset UpdatedUtc);
