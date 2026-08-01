using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Stores per-application and per-site routing rules in a DPAPI CurrentUser container.
/// Stores application bundles discovered statically or during a short process observation. Network enforcement is added later.
/// </summary>
public sealed class SecureRoutingRegistry
{
    private const int DocumentVersion = 1;
    private const int MaxEntries = 300;
    private const int MaxPayloadBytes = 2 * 1024 * 1024;
    private const uint CryptProtectUiForbidden = 0x1;

    private static readonly byte[] ContainerMagic = Encoding.ASCII.GetBytes("SPROUTE1");
    private static readonly byte[] OptionalEntropy = SHA256.HashData(
        Encoding.UTF8.GetBytes("SerpiumVPN.RoutingRegistry.CurrentUser.v1"));
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _registryDirectory;
    private readonly string _registryPath;

    public SecureRoutingRegistry()
    {
        string localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
            throw new InvalidOperationException("Windows не вернула путь LocalAppData.");

        _registryDirectory = Path.Combine(localAppData, "SerpiumVPN", "Routing");
        _registryPath = Path.Combine(_registryDirectory, "routing.sroutes");
    }

    public string SafeLocation => @"%LOCALAPPDATA%\SerpiumVPN\Routing\routing.sroutes";

    public async Task<IReadOnlyList<RoutingRegistryEntry>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return ReadEntries()
                .OrderBy(entry => entry.Kind)
                .ThenBy(entry => entry.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RoutingRegistryEntry> AddApplicationAsync(
        string executablePath,
        CancellationToken cancellationToken = default)
    {
        RoutingRegistryEntry candidate = ApplicationDependencyScanner.BuildEntry(executablePath);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            RoutingRegistryEntry? duplicate = entries.FirstOrDefault(entry =>
                entry.Kind == RoutingTargetKind.Application &&
                string.Equals(
                    NormalizePath(entry.PrimaryValue),
                    NormalizePath(candidate.PrimaryValue),
                    StringComparison.OrdinalIgnoreCase));

            if (duplicate is not null)
                throw new InvalidOperationException("Это приложение уже находится в списке маршрутизации.");

            EnsureCapacity(entries);
            entries.Add(candidate);
            WriteEntries(entries);
            return candidate;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RoutingRegistryEntry> AddApplicationBundleAsync(
        string displayName,
        string primaryExecutablePath,
        IEnumerable<string> executablePaths,
        CancellationToken cancellationToken = default)
    {
        RoutingRegistryEntry candidate = CreateApplicationEntry(
            displayName,
            primaryExecutablePath,
            executablePaths);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            RoutingRegistryEntry? duplicate = entries.FirstOrDefault(entry =>
                entry.Kind == RoutingTargetKind.Application &&
                string.Equals(
                    NormalizePath(entry.PrimaryValue),
                    NormalizePath(candidate.PrimaryValue),
                    StringComparison.OrdinalIgnoreCase));

            if (duplicate is not null)
                throw new InvalidOperationException("Это приложение уже находится в списке маршрутизации.");

            EnsureCapacity(entries);
            entries.Add(candidate);
            WriteEntries(entries);
            return candidate;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RoutingRegistryEntry> UpdateApplicationBundleAsync(
        Guid id,
        string displayName,
        string primaryExecutablePath,
        IEnumerable<string> executablePaths,
        CancellationToken cancellationToken = default)
    {
        RoutingRegistryEntry replacement = CreateApplicationEntry(
            displayName,
            primaryExecutablePath,
            executablePaths);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            int index = entries.FindIndex(entry => entry.Id == id);
            if (index < 0)
                throw new InvalidOperationException("Приложение уже отсутствует в реестре маршрутизации.");

            RoutingRegistryEntry current = entries[index];
            if (current.Kind != RoutingTargetKind.Application)
                throw new InvalidOperationException("Выбранная запись не является приложением.");

            bool duplicateExists = entries.Any(entry =>
                entry.Id != id &&
                entry.Kind == RoutingTargetKind.Application &&
                string.Equals(
                    NormalizePath(entry.PrimaryValue),
                    NormalizePath(replacement.PrimaryValue),
                    StringComparison.OrdinalIgnoreCase));
            if (duplicateExists)
                throw new InvalidOperationException("Другая карточка уже использует этот основной EXE.");

            RoutingRegistryEntry updated = replacement with
            {
                Id = current.Id,
                IsEnabled = current.IsEnabled,
                CreatedUtc = current.CreatedUtc,
                UpdatedUtc = DateTimeOffset.UtcNow
            };

            entries[index] = updated;
            WriteEntries(entries);
            return updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RoutingRegistryEntry> AddWebsiteAsync(
        string input,
        bool includeSubdomains,
        CancellationToken cancellationToken = default)
    {
        string domain = NormalizeDomain(input);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        RoutingRegistryEntry candidate = new()
        {
            Id = Guid.NewGuid(),
            Kind = RoutingTargetKind.Website,
            DisplayName = domain,
            PrimaryValue = domain,
            RelatedExecutables = Array.Empty<string>(),
            IncludeSubdomains = includeSubdomains,
            IsEnabled = true,
            CreatedUtc = now,
            UpdatedUtc = now
        };

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            RoutingRegistryEntry? duplicate = entries.FirstOrDefault(entry =>
                entry.Kind == RoutingTargetKind.Website &&
                string.Equals(entry.PrimaryValue, domain, StringComparison.OrdinalIgnoreCase));

            if (duplicate is not null)
                throw new InvalidOperationException("Этот сайт уже находится в списке маршрутизации.");

            EnsureCapacity(entries);
            entries.Add(candidate);
            WriteEntries(entries);
            return candidate;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> SetEnabledAsync(
        Guid id,
        bool isEnabled,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            int index = entries.FindIndex(entry => entry.Id == id);
            if (index < 0)
                return false;

            RoutingRegistryEntry current = entries[index];
            entries[index] = current with
            {
                IsEnabled = isEnabled,
                UpdatedUtc = DateTimeOffset.UtcNow
            };
            WriteEntries(entries);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> DeleteAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            bool removed = entries.RemoveAll(entry => entry.Id == id) > 0;
            if (!removed)
                return false;

            WriteEntries(entries);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<int> ClearAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<RoutingRegistryEntry> entries = ReadEntries();
            int count = entries.Count;
            DeleteRegistryFile();
            return count;
        }
        finally
        {
            _gate.Release();
        }
    }

    public static string NormalizeDomain(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("Введите адрес сайта.", nameof(input));

        string value = input.Trim();
        if (!value.Contains("://", StringComparison.Ordinal))
            value = "https://" + value;

        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new FormatException("Не удалось распознать адрес сайта.");
        }

        string host = uri.Host.Trim().TrimEnd('.');
        if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            host = host[4..];

        try
        {
            host = new IdnMapping().GetAscii(host).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            throw new FormatException("Домен содержит недопустимые символы.");
        }

        if (host.Length is < 1 or > 253 ||
            host.Split('.').Any(label =>
                label.Length is < 1 or > 63 ||
                label.StartsWith('-') ||
                label.EndsWith('-') ||
                label.Any(character => !char.IsLetterOrDigit(character) && character != '-')))
        {
            throw new FormatException("Домен имеет недопустимый формат.");
        }

        return host;
    }

    private static RoutingRegistryEntry CreateApplicationEntry(
        string displayName,
        string primaryExecutablePath,
        IEnumerable<string> executablePaths)
    {
        string safeDisplayName = NormalizeDisplayName(displayName);
        string primaryPath = NormalizeExecutablePath(primaryExecutablePath, requireExists: true);
        string[] bundle = NormalizeExecutableBundle(primaryPath, executablePaths);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        return new RoutingRegistryEntry
        {
            Id = Guid.NewGuid(),
            Kind = RoutingTargetKind.Application,
            DisplayName = safeDisplayName,
            PrimaryValue = primaryPath,
            RelatedExecutables = bundle,
            IncludeSubdomains = false,
            IsEnabled = true,
            CreatedUtc = now,
            UpdatedUtc = now
        };
    }

    private static string[] NormalizeExecutableBundle(
        string primaryPath,
        IEnumerable<string> executablePaths)
    {
        if (executablePaths is null)
            throw new ArgumentNullException(nameof(executablePaths));

        List<string> normalized = new() { primaryPath };
        foreach (string path in executablePaths)
        {
            if (string.IsNullOrWhiteSpace(path))
                continue;

            string fullPath = NormalizeExecutablePath(path, requireExists: true);
            if (!normalized.Contains(fullPath, StringComparer.OrdinalIgnoreCase))
                normalized.Add(fullPath);
        }

        if (normalized.Count > 64)
            throw new InvalidOperationException("В одной группе разрешено не более 64 EXE-файлов.");

        return normalized
            .OrderBy(path => string.Equals(path, primaryPath, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(Path.GetFileName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private static string NormalizeExecutablePath(string path, bool requireExists)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Путь к EXE пуст.", nameof(path));

        string fullPath = Path.GetFullPath(path.Trim().Trim('"'));
        if (!string.Equals(Path.GetExtension(fullPath), ".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Группа может содержать только EXE-файлы.");

        if (requireExists && !File.Exists(fullPath))
            throw new FileNotFoundException("EXE-файл группы не найден.", fullPath);

        return fullPath;
    }

    private static string NormalizeDisplayName(string displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
            throw new ArgumentException("Введите название карточки приложения.", nameof(displayName));

        string normalized = new(
            displayName.Trim().Where(character => !char.IsControl(character)).ToArray());
        if (normalized.Length is < 1 or > 120)
            throw new InvalidOperationException("Название карточки должно содержать от 1 до 120 символов.");

        return normalized;
    }

    private static void EnsureCapacity(List<RoutingRegistryEntry> entries)
    {
        if (entries.Count >= MaxEntries)
            throw new InvalidOperationException($"Достигнут лимит правил маршрутизации: {MaxEntries}.");
    }

    private List<RoutingRegistryEntry> ReadEntries()
    {
        if (!File.Exists(_registryPath))
            return new List<RoutingRegistryEntry>();

        byte[] container = File.ReadAllBytes(_registryPath);
        byte[] protectedPayload = Array.Empty<byte>();
        byte[] plaintext = Array.Empty<byte>();
        try
        {
            if (container.Length <= ContainerMagic.Length ||
                !container.AsSpan(0, ContainerMagic.Length).SequenceEqual(ContainerMagic))
            {
                throw new InvalidDataException("Файл реестра маршрутизации повреждён или имеет неизвестный формат.");
            }

            protectedPayload = container.AsSpan(ContainerMagic.Length).ToArray();
            plaintext = DpapiUnprotect(protectedPayload);
            if (plaintext.Length > MaxPayloadBytes)
                throw new InvalidDataException("Реестр маршрутизации превышает допустимый размер.");

            RoutingRegistryDocument? document = JsonSerializer.Deserialize<RoutingRegistryDocument>(
                plaintext,
                JsonOptions);
            if (document is null || document.Version != DocumentVersion)
                throw new InvalidDataException("Версия реестра маршрутизации не поддерживается.");

            List<RoutingRegistryEntry> entries = document.Entries ?? new List<RoutingRegistryEntry>();
            ValidateEntries(entries);
            return entries;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(container);
            if (protectedPayload.Length > 0)
                CryptographicOperations.ZeroMemory(protectedPayload);
            if (plaintext.Length > 0)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void WriteEntries(List<RoutingRegistryEntry> entries)
    {
        if (entries.Count == 0)
        {
            DeleteRegistryFile();
            return;
        }

        ValidateEntries(entries);
        Directory.CreateDirectory(_registryDirectory);

        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(
            new RoutingRegistryDocument
            {
                Version = DocumentVersion,
                Entries = entries
            },
            JsonOptions);
        byte[] protectedPayload = Array.Empty<byte>();
        byte[] container = Array.Empty<byte>();
        string temporaryPath = _registryPath + ".tmp";

        try
        {
            if (plaintext.Length > MaxPayloadBytes)
                throw new InvalidOperationException("Реестр маршрутизации слишком велик.");

            protectedPayload = DpapiProtect(plaintext);
            container = new byte[ContainerMagic.Length + protectedPayload.Length];
            Buffer.BlockCopy(ContainerMagic, 0, container, 0, ContainerMagic.Length);
            Buffer.BlockCopy(
                protectedPayload,
                0,
                container,
                ContainerMagic.Length,
                protectedPayload.Length);

            File.WriteAllBytes(temporaryPath, container);
            File.Move(temporaryPath, _registryPath, true);
            File.SetAttributes(_registryPath, FileAttributes.Hidden);
        }
        finally
        {
            TryDelete(temporaryPath);
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedPayload.Length > 0)
                CryptographicOperations.ZeroMemory(protectedPayload);
            if (container.Length > 0)
                CryptographicOperations.ZeroMemory(container);
        }
    }

    private static void ValidateEntries(List<RoutingRegistryEntry> entries)
    {
        if (entries.Count > MaxEntries)
            throw new InvalidDataException("Реестр содержит слишком много правил.");

        HashSet<Guid> ids = new();
        foreach (RoutingRegistryEntry entry in entries)
        {
            if (entry.Id == Guid.Empty || !ids.Add(entry.Id))
                throw new InvalidDataException("Реестр содержит повторяющийся идентификатор.");
            if (string.IsNullOrWhiteSpace(entry.DisplayName) || entry.DisplayName.Length > 260)
                throw new InvalidDataException("Некорректное имя правила маршрутизации.");
            if (string.IsNullOrWhiteSpace(entry.PrimaryValue) || entry.PrimaryValue.Length > 2048)
                throw new InvalidDataException("Некорректное значение правила маршрутизации.");
            if (entry.RelatedExecutables.Length > 64 ||
                entry.RelatedExecutables.Any(path => path.Length > 2048))
            {
                throw new InvalidDataException("Некорректная группа исполняемых файлов.");
            }
        }
    }

    private void DeleteRegistryFile()
    {
        try
        {
            if (File.Exists(_registryPath))
            {
                File.SetAttributes(_registryPath, FileAttributes.Normal);
                File.Delete(_registryPath);
            }

            if (Directory.Exists(_registryDirectory) &&
                !Directory.EnumerateFileSystemEntries(_registryDirectory).Any())
            {
                Directory.Delete(_registryDirectory, false);
            }
        }
        catch (Exception ex)
        {
            throw new IOException("Не удалось очистить реестр маршрутизации.", ex);
        }
    }

    private static string NormalizePath(string path)
    {
        try
        {
            return Path.GetFullPath(path.Trim());
        }
        catch
        {
            return path.Trim();
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
        }
        catch
        {
            // A later write retries the same temporary path.
        }
    }

    private static byte[] DpapiProtect(byte[] plaintext)
    {
        DataBlob input = CreateBlob(plaintext);
        DataBlob entropy = CreateBlob(OptionalEntropy);
        DataBlob output = default;
        try
        {
            if (!CryptProtectData(
                    ref input,
                    "SerpiumVPN Routing Registry",
                    ref entropy,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output))
            {
                throw new CryptographicException(
                    "Windows DPAPI не смогла защитить реестр маршрутизации.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            return CopyBlob(output);
        }
        finally
        {
            FreeInputBlob(ref input);
            FreeInputBlob(ref entropy);
            FreeOutputBlob(ref output);
        }
    }

    private static byte[] DpapiUnprotect(byte[] protectedData)
    {
        DataBlob input = CreateBlob(protectedData);
        DataBlob entropy = CreateBlob(OptionalEntropy);
        DataBlob output = default;
        IntPtr description = IntPtr.Zero;
        try
        {
            if (!CryptUnprotectData(
                    ref input,
                    out description,
                    ref entropy,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output))
            {
                throw new CryptographicException(
                    "Реестр маршрутизации нельзя открыть в текущей учётной записи Windows.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            return CopyBlob(output);
        }
        finally
        {
            FreeInputBlob(ref input);
            FreeInputBlob(ref entropy);
            FreeOutputBlob(ref output);
            if (description != IntPtr.Zero)
                LocalFree(description);
        }
    }

    private static DataBlob CreateBlob(byte[] data)
    {
        if (data.Length == 0)
            return default;

        IntPtr pointer = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, pointer, data.Length);
        return new DataBlob { Size = data.Length, Data = pointer };
    }

    private static byte[] CopyBlob(DataBlob blob)
    {
        if (blob.Size <= 0 || blob.Data == IntPtr.Zero)
            return Array.Empty<byte>();

        byte[] result = new byte[blob.Size];
        Marshal.Copy(blob.Data, result, 0, blob.Size);
        return result;
    }

    private static void FreeInputBlob(ref DataBlob blob)
    {
        if (blob.Data == IntPtr.Zero)
            return;

        ZeroUnmanagedMemory(blob);
        Marshal.FreeHGlobal(blob.Data);
        blob = default;
    }

    private static void FreeOutputBlob(ref DataBlob blob)
    {
        if (blob.Data == IntPtr.Zero)
            return;

        ZeroUnmanagedMemory(blob);
        LocalFree(blob.Data);
        blob = default;
    }

    private static void ZeroUnmanagedMemory(DataBlob blob)
    {
        if (blob.Size <= 0 || blob.Data == IntPtr.Zero)
            return;

        byte[] zeroes = new byte[blob.Size];
        try
        {
            Marshal.Copy(zeroes, 0, blob.Data, blob.Size);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zeroes);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    private sealed class RoutingRegistryDocument
    {
        public int Version { get; set; }
        public List<RoutingRegistryEntry> Entries { get; set; } = new();
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? dataDescription,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        out IntPtr dataDescription,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
