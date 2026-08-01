using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Reflection;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.Providers;

namespace SerpiumVPN.Relay.ProfileVault;

/// <summary>
/// Stores provider and direct Xray runtime profiles as a single DPAPI CurrentUser container.
/// Original connection keys are never persisted; only SHA-256 fingerprints are kept
/// for duplicate detection. Decrypted runtime profiles exist only in memory.
/// </summary>
public sealed class SecureProfileVault
{
    private const int VaultDocumentVersion = 1;
    private const int VaultContainerVersion = 1;
    private const int MaxProfiles = 100;
    private const int MaxConfigurationBytes = 2 * 1024 * 1024;
    private const int MaxStringBytes = 16 * 1024;
    private const uint CryptProtectUiForbidden = 0x1;
    private static readonly byte[] ContainerMagic = Encoding.ASCII.GetBytes("SPVAULT1");
    private static readonly byte[] OptionalEntropy = SHA256.HashData(
        Encoding.UTF8.GetBytes("SerpiumVPN.ProfileVault.CurrentUser.v1"));
    private static readonly JsonSerializerOptions XrayProfileJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        IncludeFields = true,
        WriteIndented = false
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _vaultDirectory;
    private readonly string _vaultPath;

    public SecureProfileVault()
    {
        string localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
            throw new InvalidOperationException("Windows не вернула путь LocalAppData.");

        _vaultDirectory = Path.Combine(localAppData, "SerpiumVPN", "Vault");
        _vaultPath = Path.Combine(_vaultDirectory, "profiles.svault");
    }

    public string SafeLocation => @"%LOCALAPPDATA%\SerpiumVPN\Vault\profiles.svault";

    public async Task<IReadOnlyList<SecureProfileVaultEntry>> ListProfilesAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<VaultRecord> records = ReadRecords();
            try
            {
                return records
                    .Select(ToSafeEntry)
                    .OrderByDescending(item => item.UpdatedUtc)
                    .ToArray();
            }
            finally
            {
                DisposeRecords(records);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SecureProfileVaultSaveResult> SaveProviderProfileAsync(
        ProviderRuntimeProfile profile,
        string sourceKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.IsDisposed)
            throw new ObjectDisposedException(nameof(ProviderRuntimeProfile));
        if (string.IsNullOrWhiteSpace(sourceKey))
            throw new ArgumentException("Исходный ключ пуст.", nameof(sourceKey));

        string fingerprint = ComputeSourceFingerprint(sourceKey);
        byte[] configuration = profile.CopyConfiguration();
        if (configuration.Length > MaxConfigurationBytes)
        {
            CryptographicOperations.ZeroMemory(configuration);
            throw new InvalidOperationException("Профиль слишком велик для защищённого хранилища.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<VaultRecord> records = ReadRecords();
            try
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                int existingIndex = records.FindIndex(item =>
                    CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(item.SourceFingerprint),
                        Encoding.ASCII.GetBytes(fingerprint)));

                bool updatedExisting = existingIndex >= 0;
                VaultRecord replacement;
                if (updatedExisting)
                {
                    VaultRecord existing = records[existingIndex];
                    replacement = CreateRecord(
                        existing.Id,
                        existing.CreatedUtc,
                        now,
                        fingerprint,
                        profile,
                        configuration);
                    existing.Dispose();
                    records[existingIndex] = replacement;
                }
                else
                {
                    if (records.Count >= MaxProfiles)
                        throw new InvalidOperationException(
                            $"Достигнут лимит защищённых профилей: {MaxProfiles}.");

                    replacement = CreateRecord(
                        Guid.NewGuid(),
                        now,
                        now,
                        fingerprint,
                        profile,
                        configuration);
                    records.Add(replacement);
                }

                // Ownership of the copied configuration moved into replacement.
                configuration = Array.Empty<byte>();
                bool aclHardened = EnsureVaultDirectory();
                WriteRecords(records);

                return new SecureProfileVaultSaveResult(
                    ToSafeEntry(replacement),
                    updatedExisting,
                    records.Count,
                    aclHardened);
            }
            finally
            {
                DisposeRecords(records);
            }
        }
        finally
        {
            if (configuration.Length > 0)
                CryptographicOperations.ZeroMemory(configuration);
            _gate.Release();
        }
    }

    public async Task<SecureProfileVaultSaveResult> SaveXrayProfileAsync(
        SerpiumConnectionProfile profile,
        int socksPort,
        string sourceKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (socksPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(socksPort));
        if (string.IsNullOrWhiteSpace(sourceKey))
            throw new ArgumentException("Исходный ключ пуст.", nameof(sourceKey));

        string fingerprint = ComputeSourceFingerprint(sourceKey);
        byte[] payload = SerializeXrayProfile(profile, socksPort);
        ValidateXrayProfileRoundTrip(payload);
        if (payload.Length > MaxConfigurationBytes)
        {
            CryptographicOperations.ZeroMemory(payload);
            throw new InvalidOperationException(
                "Xray-профиль слишком велик для защищённого хранилища.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<VaultRecord> records = ReadRecords();
            try
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                int existingIndex = records.FindIndex(item =>
                    string.Equals(
                        item.SourceFingerprint,
                        fingerprint,
                        StringComparison.OrdinalIgnoreCase));

                bool updatedExisting = existingIndex >= 0;
                VaultRecord replacement;
                if (updatedExisting)
                {
                    VaultRecord existing = records[existingIndex];
                    replacement = CreateXrayRecord(
                        existing.Id,
                        existing.CreatedUtc,
                        now,
                        fingerprint,
                        profile,
                        payload);
                    existing.Dispose();
                    records[existingIndex] = replacement;
                }
                else
                {
                    if (records.Count >= MaxProfiles)
                        throw new InvalidOperationException(
                            $"Достигнут лимит защищённых профилей: {MaxProfiles}.");

                    replacement = CreateXrayRecord(
                        Guid.NewGuid(),
                        now,
                        now,
                        fingerprint,
                        profile,
                        payload);
                    records.Add(replacement);
                }

                payload = Array.Empty<byte>();
                bool aclHardened = EnsureVaultDirectory();
                WriteRecords(records);

                return new SecureProfileVaultSaveResult(
                    ToSafeEntry(replacement),
                    updatedExisting,
                    records.Count,
                    aclHardened);
            }
            finally
            {
                DisposeRecords(records);
            }
        }
        finally
        {
            if (payload.Length > 0)
                CryptographicOperations.ZeroMemory(payload);
            _gate.Release();
        }
    }

    public async Task<SecureXrayVaultProfile> OpenXrayProfileAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<VaultRecord> records = ReadRecords();
            try
            {
                VaultRecord record = records.FirstOrDefault(item => item.Id == id) ??
                    throw new KeyNotFoundException("Сохранённый профиль не найден.");

                if (!string.Equals(record.Engine, "xray", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        "Запись Vault не является Xray-профилем.");

                byte[] payload = record.Configuration.ToArray();
                try
                {
                    return DeserializeXrayProfile(payload);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(payload);
                }
            }
            finally
            {
                DisposeRecords(records);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<ProviderRuntimeProfile> OpenProviderProfileAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<VaultRecord> records = ReadRecords();
            try
            {
                VaultRecord record = records.FirstOrDefault(item => item.Id == id) ??
                    throw new KeyNotFoundException("Сохранённый профиль не найден.");

                if (string.Equals(record.Engine, "xray", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        "Запись Vault является Xray-профилем.");

                byte[] configuration = record.Configuration.ToArray();
                try
                {
                    return new ProviderRuntimeProfile(
                        record.ProviderName,
                        record.ProfileId,
                        record.Engine,
                        configuration,
                        record.Protocols,
                        record.InboundCount,
                        record.OutboundCount,
                        record.RouteRuleCount,
                        record.DnsServerCount,
                        "Профиль загружен из Serpium Secure Profile Vault.");
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(configuration);
                    throw;
                }
            }
            finally
            {
                DisposeRecords(records);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> DeleteProfileAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<VaultRecord> records = ReadRecords();
            try
            {
                int index = records.FindIndex(item => item.Id == id);
                if (index < 0)
                    return false;

                records[index].Dispose();
                records.RemoveAt(index);

                if (records.Count == 0)
                {
                    DeleteVaultFile();
                    return true;
                }

                EnsureVaultDirectory();
                WriteRecords(records);
                return true;
            }
            finally
            {
                DisposeRecords(records);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static VaultRecord CreateRecord(
        Guid id,
        DateTimeOffset createdUtc,
        DateTimeOffset updatedUtc,
        string fingerprint,
        ProviderRuntimeProfile profile,
        byte[] configuration)
    {
        return new VaultRecord
        {
            Id = id,
            SourceFingerprint = fingerprint,
            ProviderName = profile.ProviderName,
            ProfileId = profile.ProfileId,
            Engine = profile.Engine,
            Protocols = profile.Protocols.ToArray(),
            InboundCount = profile.InboundCount,
            OutboundCount = profile.OutboundCount,
            RouteRuleCount = profile.RouteRuleCount,
            DnsServerCount = profile.DnsServerCount,
            CreatedUtc = createdUtc,
            UpdatedUtc = updatedUtc,
            Configuration = configuration
        };
    }

    private static VaultRecord CreateXrayRecord(
        Guid id,
        DateTimeOffset createdUtc,
        DateTimeOffset updatedUtc,
        string fingerprint,
        SerpiumConnectionProfile profile,
        byte[] payload)
    {
        string safeName = BuildSafeXrayProfileName(profile);
        string[] protocols = new[]
            { profile.Protocol, profile.Transport, profile.Security }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new VaultRecord
        {
            Id = id,
            SourceFingerprint = fingerprint,
            ProviderName = profile.Protocol.ToUpperInvariant(),
            ProfileId = safeName,
            Engine = "xray",
            Protocols = protocols,
            InboundCount = 1,
            OutboundCount = 1,
            RouteRuleCount = 0,
            DnsServerCount = 0,
            CreatedUtc = createdUtc,
            UpdatedUtc = updatedUtc,
            Configuration = payload
        };
    }

    private static byte[] SerializeXrayProfile(
        SerpiumConnectionProfile profile,
        int socksPort)
    {
        using MemoryStream stream = new();
        try
        {
            using Utf8JsonWriter writer = new(stream);
            writer.WriteStartObject();
            writer.WriteNumber("version", 1);
            writer.WriteNumber("socksPort", socksPort);
            writer.WritePropertyName("profile");
            JsonSerializer.Serialize(
                writer,
                profile,
                typeof(SerpiumConnectionProfile),
                XrayProfileJsonOptions);
            writer.WriteEndObject();
            writer.Flush();
            return stream.ToArray();
        }
        finally
        {
            if (stream.TryGetBuffer(out ArraySegment<byte> buffer) &&
                buffer.Array is not null && stream.Length > 0)
            {
                CryptographicOperations.ZeroMemory(
                    buffer.Array.AsSpan(0, checked((int)stream.Length)));
            }
        }
    }

    private static void ValidateXrayProfileRoundTrip(byte[] payload)
    {
        SecureXrayVaultProfile opened = DeserializeXrayProfile(payload);
        byte[] verification = SerializeXrayProfile(
            opened.Profile,
            opened.SocksPort);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(payload, verification))
            {
                throw new InvalidDataException(
                    "Xray-профиль не прошёл контрольную проверку сериализации.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(verification);
        }
    }

    private static SecureXrayVaultProfile DeserializeXrayProfile(byte[] payload)
    {
        using JsonDocument document = JsonDocument.Parse(payload);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("version", out JsonElement versionElement) ||
            versionElement.GetInt32() != 1 ||
            !root.TryGetProperty("socksPort", out JsonElement socksPortElement) ||
            !root.TryGetProperty("profile", out JsonElement profileElement))
        {
            throw new InvalidDataException(
                "Xray-профиль Vault имеет неизвестный формат.");
        }

        int socksPort = socksPortElement.GetInt32();
        if (socksPort is < 1 or > 65535)
            throw new InvalidDataException(
                "Xray-профиль содержит некорректный SOCKS5-порт.");

        SerpiumConnectionProfile profile =
            DeserializeConnectionProfile(profileElement);
        return new SecureXrayVaultProfile(profile, socksPort);
    }

    private static SerpiumConnectionProfile DeserializeConnectionProfile(
        JsonElement profileElement)
    {
        try
        {
            SerpiumConnectionProfile? direct =
                profileElement.Deserialize<SerpiumConnectionProfile>(
                    XrayProfileJsonOptions);
            if (direct is not null)
                return direct;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            // Fallback below supports immutable positional records.
        }

        Dictionary<string, JsonElement> values = profileElement
            .EnumerateObject()
            .ToDictionary(
                property => property.Name,
                property => property.Value.Clone(),
                StringComparer.OrdinalIgnoreCase);

        Type profileType = typeof(SerpiumConnectionProfile);
        foreach (ConstructorInfo constructor in profileType
                     .GetConstructors(BindingFlags.Public | BindingFlags.Instance)
                     .OrderByDescending(item => item.GetParameters().Length))
        {
            ParameterInfo[] parameters = constructor.GetParameters();
            object?[] arguments = new object?[parameters.Length];
            bool compatible = true;

            for (int index = 0; index < parameters.Length; index++)
            {
                ParameterInfo parameter = parameters[index];
                if (parameter.Name is null ||
                    !values.TryGetValue(parameter.Name, out JsonElement value))
                {
                    compatible = false;
                    break;
                }

                try
                {
                    arguments[index] = value.Deserialize(
                        parameter.ParameterType,
                        XrayProfileJsonOptions);
                }
                catch
                {
                    compatible = false;
                    break;
                }
            }

            if (!compatible)
                continue;

            if (constructor.Invoke(arguments) is SerpiumConnectionProfile result)
                return result;
        }

        throw new InvalidDataException(
            "Сохранённый Xray-профиль нельзя восстановить текущей версией Serpium Parser.");
    }

    private static string BuildSafeXrayProfileName(SerpiumConnectionProfile profile)
    {
        string value = !string.IsNullOrWhiteSpace(profile.Name)
            ? profile.Name.Trim()
            : profile.Server.Trim();

        if (value.Length <= 32)
            return value;

        return value[..16] + "…" + value[^12..];
    }

    private static SecureProfileVaultEntry ToSafeEntry(VaultRecord record) => new(
        record.Id,
        record.ProviderName,
        record.ProfileId,
        record.Engine,
        record.Protocols.ToArray(),
        record.InboundCount,
        record.OutboundCount,
        record.RouteRuleCount,
        record.DnsServerCount,
        record.CreatedUtc,
        record.UpdatedUtc);

    private List<VaultRecord> ReadRecords()
    {
        if (!File.Exists(_vaultPath))
            return new List<VaultRecord>();

        byte[] container = File.ReadAllBytes(_vaultPath);
        byte[]? protectedPayload = null;
        byte[]? plainPayload = null;
        try
        {
            using MemoryStream containerStream = new(container, writable: false);
            using BinaryReader reader = new(containerStream, Encoding.UTF8, leaveOpen: true);

            byte[] magic = reader.ReadBytes(ContainerMagic.Length);
            if (!magic.AsSpan().SequenceEqual(ContainerMagic))
                throw new InvalidDataException("Неизвестный формат Serpium Profile Vault.");

            int containerVersion = reader.ReadInt32();
            if (containerVersion != VaultContainerVersion)
                throw new InvalidDataException(
                    $"Версия контейнера Vault {containerVersion} не поддерживается.");

            int protectedLength = reader.ReadInt32();
            if (protectedLength <= 0 || protectedLength > MaxConfigurationBytes * MaxProfiles)
                throw new InvalidDataException("Некорректный размер зашифрованного Vault.");

            protectedPayload = reader.ReadBytes(protectedLength);
            if (protectedPayload.Length != protectedLength ||
                containerStream.Position != containerStream.Length)
            {
                throw new InvalidDataException("Файл Vault повреждён или содержит лишние данные.");
            }

            plainPayload = DpapiUnprotect(protectedPayload);
            return DeserializeRecords(plainPayload);
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or InvalidDataException)
        {
            throw new InvalidDataException(
                "Защищённое хранилище профилей повреждено или имеет неизвестный формат.",
                ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(container);
            if (protectedPayload is not null)
                CryptographicOperations.ZeroMemory(protectedPayload);
            if (plainPayload is not null)
                CryptographicOperations.ZeroMemory(plainPayload);
        }
    }

    private void WriteRecords(List<VaultRecord> records)
    {
        byte[] plainPayload = SerializeRecords(records);
        byte[]? protectedPayload = null;
        byte[]? container = null;
        string temporaryPath = Path.Combine(
            _vaultDirectory,
            $"profiles.{Guid.NewGuid():N}.tmp");

        try
        {
            protectedPayload = DpapiProtect(plainPayload);
            using MemoryStream containerStream = new();
            using (BinaryWriter writer = new(containerStream, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(ContainerMagic);
                writer.Write(VaultContainerVersion);
                writer.Write(protectedPayload.Length);
                writer.Write(protectedPayload);
                writer.Flush();
            }

            container = containerStream.ToArray();
            using (FileStream stream = new(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(container, 0, container.Length);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(_vaultPath))
                File.SetAttributes(_vaultPath, FileAttributes.Normal);

            File.Move(temporaryPath, _vaultPath, overwrite: true);
            TryMarkVaultHidden();
        }
        finally
        {
            TryDeleteFile(temporaryPath);
            CryptographicOperations.ZeroMemory(plainPayload);
            if (protectedPayload is not null)
                CryptographicOperations.ZeroMemory(protectedPayload);
            if (container is not null)
                CryptographicOperations.ZeroMemory(container);
        }
    }

    private static byte[] SerializeRecords(List<VaultRecord> records)
    {
        using MemoryStream stream = new();
        try
        {
            using BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
            writer.Write(VaultDocumentVersion);
            writer.Write(records.Count);

            foreach (VaultRecord record in records)
            {
                writer.Write(record.Id.ToByteArray());
                WriteString(writer, record.SourceFingerprint);
                WriteString(writer, record.ProviderName);
                WriteString(writer, record.ProfileId);
                WriteString(writer, record.Engine);
                writer.Write(record.Protocols.Length);
                foreach (string protocol in record.Protocols)
                    WriteString(writer, protocol);

                writer.Write(record.InboundCount);
                writer.Write(record.OutboundCount);
                writer.Write(record.RouteRuleCount);
                writer.Write(record.DnsServerCount);
                writer.Write(record.CreatedUtc.UtcDateTime.Ticks);
                writer.Write(record.UpdatedUtc.UtcDateTime.Ticks);
                writer.Write(record.Configuration.Length);
                writer.Write(record.Configuration);
            }

            writer.Flush();
            return stream.ToArray();
        }
        finally
        {
            if (stream.TryGetBuffer(out ArraySegment<byte> buffer) &&
                buffer.Array is not null && stream.Length > 0)
            {
                CryptographicOperations.ZeroMemory(
                    buffer.Array.AsSpan(0, checked((int)stream.Length)));
            }
        }
    }

    private static List<VaultRecord> DeserializeRecords(byte[] payload)
    {
        using MemoryStream stream = new(payload, writable: false);
        using BinaryReader reader = new(stream, Encoding.UTF8, leaveOpen: true);

        int documentVersion = reader.ReadInt32();
        if (documentVersion != VaultDocumentVersion)
            throw new InvalidDataException(
                $"Версия документа Vault {documentVersion} не поддерживается.");

        int count = reader.ReadInt32();
        if (count is < 0 or > MaxProfiles)
            throw new InvalidDataException("Некорректное количество профилей в Vault.");

        List<VaultRecord> records = new(count);
        try
        {
            for (int index = 0; index < count; index++)
            {
                byte[] idBytes = reader.ReadBytes(16);
                if (idBytes.Length != 16)
                    throw new EndOfStreamException();

                VaultRecord record = new()
                {
                    Id = new Guid(idBytes),
                    SourceFingerprint = ReadString(reader),
                    ProviderName = ReadString(reader),
                    ProfileId = ReadString(reader),
                    Engine = ReadString(reader)
                };

                int protocolCount = reader.ReadInt32();
                if (protocolCount is < 0 or > 32)
                    throw new InvalidDataException("Некорректный список протоколов Vault.");
                record.Protocols = Enumerable.Range(0, protocolCount)
                    .Select(_ => ReadString(reader))
                    .ToArray();

                record.InboundCount = ReadNonNegativeInt(reader);
                record.OutboundCount = ReadNonNegativeInt(reader);
                record.RouteRuleCount = ReadNonNegativeInt(reader);
                record.DnsServerCount = ReadNonNegativeInt(reader);
                record.CreatedUtc = new DateTimeOffset(
                    reader.ReadInt64(),
                    TimeSpan.Zero);
                record.UpdatedUtc = new DateTimeOffset(
                    reader.ReadInt64(),
                    TimeSpan.Zero);

                int configurationLength = reader.ReadInt32();
                if (configurationLength <= 0 || configurationLength > MaxConfigurationBytes)
                    throw new InvalidDataException("Некорректный размер профиля Vault.");

                record.Configuration = reader.ReadBytes(configurationLength);
                if (record.Configuration.Length != configurationLength)
                {
                    record.Dispose();
                    throw new EndOfStreamException();
                }

                ValidateRecord(record);
                records.Add(record);
            }

            if (stream.Position != stream.Length)
                throw new InvalidDataException("Документ Vault содержит лишние данные.");

            return records;
        }
        catch
        {
            DisposeRecords(records);
            throw;
        }
    }

    private static void ValidateRecord(VaultRecord record)
    {
        if (record.Id == Guid.Empty ||
            string.IsNullOrWhiteSpace(record.SourceFingerprint) ||
            record.SourceFingerprint.Length != 64 ||
            string.IsNullOrWhiteSpace(record.ProviderName) ||
            string.IsNullOrWhiteSpace(record.ProfileId) ||
            string.IsNullOrWhiteSpace(record.Engine))
        {
            throw new InvalidDataException("Запись Vault не прошла проверку.");
        }
    }

    private static int ReadNonNegativeInt(BinaryReader reader)
    {
        int value = reader.ReadInt32();
        if (value < 0)
            throw new InvalidDataException("Отрицательное значение в Vault.");
        return value;
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        try
        {
            if (bytes.Length > MaxStringBytes)
                throw new InvalidDataException("Строка Vault превышает допустимый размер.");
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string ReadString(BinaryReader reader)
    {
        int length = reader.ReadInt32();
        if (length < 0 || length > MaxStringBytes)
            throw new InvalidDataException("Некорректная длина строки Vault.");

        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
            throw new EndOfStreamException();

        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private bool EnsureVaultDirectory()
    {
        Directory.CreateDirectory(_vaultDirectory);
        return TryHardenDirectoryAcl(_vaultDirectory);
    }

    private static bool TryHardenDirectoryAcl(string directoryPath)
    {
        try
        {
            string? userSid = WindowsIdentity.GetCurrent().User?.Value;
            if (string.IsNullOrWhiteSpace(userSid))
                return false;

            ProcessStartInfo startInfo = new()
            {
                FileName = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "icacls.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add(directoryPath);
            startInfo.ArgumentList.Add("/inheritance:r");
            startInfo.ArgumentList.Add("/grant:r");
            startInfo.ArgumentList.Add($"*{userSid}:(OI)(CI)F");
            startInfo.ArgumentList.Add("*S-1-5-18:(OI)(CI)F");

            using Process process = Process.Start(startInfo) ??
                throw new InvalidOperationException("Не удалось запустить icacls.exe.");
            if (!process.WaitForExit(10000))
            {
                process.Kill(entireProcessTree: true);
                return false;
            }

            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private void TryMarkVaultHidden()
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(_vaultPath);
            File.SetAttributes(_vaultPath, attributes | FileAttributes.Hidden);
        }
        catch
        {
            // Hidden is cosmetic only; DPAPI remains the security boundary.
        }
    }

    private void DeleteVaultFile()
    {
        if (!File.Exists(_vaultPath))
            return;

        File.SetAttributes(_vaultPath, FileAttributes.Normal);
        File.Delete(_vaultPath);
        if (File.Exists(_vaultPath))
            throw new IOException("Windows не смогла удалить файл защищённого профиля.");

        try
        {
            if (Directory.Exists(_vaultDirectory) &&
                !Directory.EnumerateFileSystemEntries(_vaultDirectory).Any())
            {
                Directory.Delete(_vaultDirectory, recursive: false);
            }
        }
        catch
        {
            // Empty protected folder may remain; profile data itself is already gone.
        }
    }

    private static void TryDeleteFile(string path)
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
            // Caller receives success only after the record was removed from memory.
        }
    }

    private static string ComputeSourceFingerprint(string sourceKey)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(sourceKey.Trim());
        try
        {
            return Convert.ToHexString(SHA256.HashData(keyBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
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
                    "SerpiumVPN Secure Profile Vault",
                    ref entropy,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output))
            {
                throw new CryptographicException(
                    "Windows DPAPI не смогла защитить профиль.",
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
                    "Профиль нельзя открыть в текущей учётной записи Windows.",
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
        if (blob.Data != IntPtr.Zero)
        {
            if (blob.Size > 0)
            {
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

            Marshal.FreeHGlobal(blob.Data);
            blob = default;
        }
    }

    private static void FreeOutputBlob(ref DataBlob blob)
    {
        if (blob.Data != IntPtr.Zero)
        {
            if (blob.Size > 0)
            {
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

            LocalFree(blob.Data);
            blob = default;
        }
    }

    private static void DisposeRecords(IEnumerable<VaultRecord> records)
    {
        foreach (VaultRecord record in records)
            record.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
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

    private sealed class VaultRecord : IDisposable
    {
        public Guid Id { get; set; }
        public string SourceFingerprint { get; set; } = string.Empty;
        public string ProviderName { get; set; } = string.Empty;
        public string ProfileId { get; set; } = string.Empty;
        public string Engine { get; set; } = string.Empty;
        public string[] Protocols { get; set; } = Array.Empty<string>();
        public int InboundCount { get; set; }
        public int OutboundCount { get; set; }
        public int RouteRuleCount { get; set; }
        public int DnsServerCount { get; set; }
        public DateTimeOffset CreatedUtc { get; set; }
        public DateTimeOffset UpdatedUtc { get; set; }
        private byte[] _configuration = Array.Empty<byte>();

        public byte[] Configuration
        {
            get => _configuration;
            set => _configuration = value ?? Array.Empty<byte>();
        }

        public void Dispose()
        {
            byte[] configuration = Interlocked.Exchange(
                ref _configuration,
                Array.Empty<byte>());
            if (configuration.Length > 0)
                CryptographicOperations.ZeroMemory(configuration);
        }
    }
}
