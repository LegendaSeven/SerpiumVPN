using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Read-only product health model for the packaged Serpium WFP stack.
///
/// This class never installs, starts, stops, signs or removes a driver. It only
/// correlates the packaged runtime, product ownership state and the Windows
/// service-registration footprint so the UI/router can choose WFP or a safe
/// fallback without guessing.
/// </summary>
public static class WfpProductReadiness
{
    private const string DriverServiceName = "SerpiumFlow";
    private const string ExpectedDriverFileName = "Serpium.Flow.Driver.sys";
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(5);
    private static readonly object CacheGate = new();

    private static DateTimeOffset _cachedUntil;
    private static WfpProductReadinessSnapshot? _cachedSnapshot;

    public static WfpProductReadinessSnapshot Inspect(bool force = false)
    {
        lock (CacheGate)
        {
            if (!force &&
                _cachedSnapshot is not null &&
                DateTimeOffset.UtcNow < _cachedUntil)
            {
                return _cachedSnapshot;
            }

            WfpProductReadinessSnapshot snapshot = InspectCore();
            _cachedSnapshot = snapshot;
            _cachedUntil = DateTimeOffset.UtcNow + CacheDuration;
            return snapshot;
        }
    }

    public static void Invalidate()
    {
        lock (CacheGate)
        {
            _cachedSnapshot = null;
            _cachedUntil = DateTimeOffset.MinValue;
        }
    }

    private static WfpProductReadinessSnapshot InspectCore()
    {
        WfpRuntimeResolution runtime =
            WfpRuntimeOwner.ResolvePackagedRuntime();

        if (!runtime.PackagePresent)
        {
            return Snapshot(
                WfpProductReadinessKind.RuntimeMissing,
                packagePresent: false,
                canUseWfp: false,
                "Маршрутизатор Windows: WFP runtime не упакован.",
                "Serpium продолжит использовать поддерживаемый Relay fallback.");
        }

        if (!runtime.Available)
        {
            return Snapshot(
                WfpProductReadinessKind.RuntimeInvalid,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: WFP runtime повреждён или несовместим.",
                runtime.Message);
        }

        RuntimeMetadata runtimeMetadata;
        try
        {
            runtimeMetadata = ReadRuntimeMetadata();
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            JsonException or
            CryptographicException)
        {
            return Snapshot(
                WfpProductReadinessKind.RuntimeInvalid,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: manifest WFP runtime не прошёл проверку.",
                exception.Message);
        }

        DriverServiceRegistration serviceRegistration =
            ReadDriverServiceRegistration();

        DriverOwnershipState ownership =
            ReadDriverOwnershipState();

        bool productionRuntime = string.Equals(
            runtimeMetadata.DriverTrust,
            "PRODUCTION_VERIFIED",
            StringComparison.OrdinalIgnoreCase);

        if (ownership.Corrupt)
        {
            return Snapshot(
                WfpProductReadinessKind.RecoveryRequired,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: состояние драйвера требует восстановления.",
                ownership.Message ??
                "driver-state.json повреждён или не читается.");
        }

        if (serviceRegistration.Present &&
            !serviceRegistration.ExpectedBinary)
        {
            return Snapshot(
                WfpProductReadinessKind.OwnershipConflict,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: найден конфликтующий SerpiumFlow service.",
                "Автоматическое использование/удаление запрещено: путь kernel driver не соответствует Serpium.");
        }

        if (!ownership.Present && serviceRegistration.Present)
        {
            return Snapshot(
                WfpProductReadinessKind.OwnershipConflict,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: драйвер обнаружен без product ownership state.",
                "Serpium не будет автоматически трогать такой driver service.");
        }

        if (ownership.Present &&
            (!string.Equals(
                    ownership.Owner,
                    "SerpiumVPN",
                    StringComparison.Ordinal) ||
             !string.Equals(
                    ownership.ServiceName,
                    DriverServiceName,
                    StringComparison.Ordinal) ||
             !string.Equals(
                    ownership.ProtocolAbi,
                    WfpRuntimeOwner.ProtocolAbi,
                    StringComparison.Ordinal)))
        {
            return Snapshot(
                WfpProductReadinessKind.OwnershipConflict,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: ownership state не принадлежит текущему WFP ABI.",
                "Serpium оставляет сеть в безопасном fallback-режиме.");
        }

        if (string.Equals(
                ownership.State,
                "RECOVERY_REQUIRED",
                StringComparison.OrdinalIgnoreCase))
        {
            return Snapshot(
                WfpProductReadinessKind.RecoveryRequired,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: предыдущий driver update требует recovery.",
                ownership.Message ??
                "Автоматический rollback не был подтверждён.");
        }

        if (!serviceRegistration.Present)
        {
            if (ownership.Present &&
                ownership.State.StartsWith(
                    "INSTALLED",
                    StringComparison.OrdinalIgnoreCase))
            {
                return Snapshot(
                    WfpProductReadinessKind.RecoveryRequired,
                    packagePresent: true,
                    canUseWfp: false,
                    "Маршрутизатор Windows: ownership state говорит об установке, но driver service отсутствует.",
                    "Нужен controlled driver recovery; Serpium использует fallback.");
            }

            return productionRuntime
                ? Snapshot(
                    WfpProductReadinessKind.ProductionReadyNotInstalled,
                    packagePresent: true,
                    canUseWfp: false,
                    "Маршрутизатор Windows: production WFP пакет проверен, драйвер ещё не установлен.",
                    "После controlled install Serpium сможет включить WFP без изменения Relay-профиля.")
                : Snapshot(
                    WfpProductReadinessKind.PackagedOnly,
                    packagePresent: true,
                    canUseWfp: false,
                    "Маршрутизатор Windows: WFP упакован, ожидается production-подпись/установка.",
                    "До этого момента Serpium автоматически использует Relay fallback.");
        }

        if (!productionRuntime)
        {
            return Snapshot(
                WfpProductReadinessKind.UpdateRequired,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: установленный driver не соответствует production runtime.",
                "WFP отключён до controlled production update.");
        }

        if (!ownership.Present)
        {
            return Snapshot(
                WfpProductReadinessKind.OwnershipConflict,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: product ownership драйвера не подтверждён.",
                "Serpium не будет запускать WFP по предположению.");
        }

        if (string.IsNullOrWhiteSpace(ownership.RuntimeManifestSha256) ||
            !string.Equals(
                ownership.RuntimeManifestSha256,
                runtimeMetadata.ManifestSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            return Snapshot(
                WfpProductReadinessKind.UpdateRequired,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: WFP runtime обновился, установленный driver ещё относится к предыдущему payload.",
                "Нужен controlled driver update. До него активируется Relay fallback.");
        }

        if (!ownership.State.StartsWith(
                "INSTALLED",
                StringComparison.OrdinalIgnoreCase))
        {
            return Snapshot(
                WfpProductReadinessKind.RecoveryRequired,
                packagePresent: true,
                canUseWfp: false,
                "Маршрутизатор Windows: driver service присутствует, но ownership state не является INSTALLED.",
                ownership.Message ??
                "Состояние установки требует controlled recovery.");
        }

        return Snapshot(
            WfpProductReadinessKind.InstalledReady,
            packagePresent: true,
            canUseWfp: true,
            "Маршрутизатор Windows: WFP production runtime и driver ownership готовы.",
            "Новые flows могут использовать WFP; существующие flows сохраняют свою policy generation.");
    }

    private static RuntimeMetadata ReadRuntimeMetadata()
    {
        string manifestPath = Path.Combine(
            WfpRuntimeOwner.PackagedRuntimeDirectory,
            WfpRuntimeOwner.RuntimeManifestFileName);

        using FileStream stream = File.OpenRead(manifestPath);
        using JsonDocument document = JsonDocument.Parse(stream);

        JsonElement root = document.RootElement;

        string driverTrust = TryGetString(root, "driverTrust")
            ?? "PACKAGED_ONLY";
        string installState = TryGetString(root, "installState")
            ?? "UNKNOWN";

        using FileStream hashStream = File.OpenRead(manifestPath);
        string manifestSha256 = Convert
            .ToHexString(SHA256.HashData(hashStream))
            .ToLowerInvariant();

        return new RuntimeMetadata(
            driverTrust,
            installState,
            manifestSha256);
    }

    private static DriverOwnershipState ReadDriverOwnershipState()
    {
        string path = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "SerpiumVPN",
            "WFP",
            "driver-state.json");

        if (!File.Exists(path))
            return DriverOwnershipState.Absent;

        try
        {
            using FileStream stream = File.OpenRead(path);
            using JsonDocument document = JsonDocument.Parse(stream);
            JsonElement root = document.RootElement;

            int schema =
                root.TryGetProperty(
                    "schema",
                    out JsonElement schemaElement) &&
                schemaElement.TryGetInt32(out int schemaValue)
                    ? schemaValue
                    : 0;

            if (schema != 1)
            {
                return new DriverOwnershipState(
                    Present: true,
                    Corrupt: true,
                    Owner: null,
                    ServiceName: null,
                    ProtocolAbi: null,
                    State: "CORRUPT",
                    RuntimeManifestSha256: null,
                    Message: $"Неподдерживаемая схема driver-state.json: {schema}.");
            }

            return new DriverOwnershipState(
                Present: true,
                Corrupt: false,
                Owner: TryGetString(root, "owner"),
                ServiceName: TryGetString(root, "serviceName"),
                ProtocolAbi: TryGetString(root, "protocolAbi"),
                State: TryGetString(root, "state") ?? "UNKNOWN",
                RuntimeManifestSha256:
                    TryGetString(root, "runtimeManifestSha256"),
                Message: TryGetString(root, "message"));
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            JsonException)
        {
            return new DriverOwnershipState(
                Present: true,
                Corrupt: true,
                Owner: null,
                ServiceName: null,
                ProtocolAbi: null,
                State: "CORRUPT",
                RuntimeManifestSha256: null,
                Message: exception.Message);
        }
    }

    private static DriverServiceRegistration ReadDriverServiceRegistration()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{DriverServiceName}",
                writable: false);

            if (key is null)
                return DriverServiceRegistration.Absent;

            string imagePath =
                Convert.ToString(key.GetValue("ImagePath"))
                    ?.Trim()
                    .Trim('"')
                ?? string.Empty;

            bool expectedBinary =
                imagePath.EndsWith(
                    ExpectedDriverFileName,
                    StringComparison.OrdinalIgnoreCase);

            return new DriverServiceRegistration(
                Present: true,
                ExpectedBinary: expectedBinary,
                ImagePath: imagePath);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or
            IOException)
        {
            return new DriverServiceRegistration(
                Present: true,
                ExpectedBinary: false,
                ImagePath: exception.Message);
        }
    }

    private static string? TryGetString(
        JsonElement element,
        string propertyName)
    {
        return element.TryGetProperty(
                   propertyName,
                   out JsonElement value) &&
               value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static WfpProductReadinessSnapshot Snapshot(
        WfpProductReadinessKind kind,
        bool packagePresent,
        bool canUseWfp,
        string summary,
        string detail) =>
        new(
            kind,
            packagePresent,
            canUseWfp,
            summary,
            detail);

    private sealed record RuntimeMetadata(
        string DriverTrust,
        string InstallState,
        string ManifestSha256);

    private sealed record DriverOwnershipState(
        bool Present,
        bool Corrupt,
        string? Owner,
        string? ServiceName,
        string? ProtocolAbi,
        string State,
        string? RuntimeManifestSha256,
        string? Message)
    {
        public static DriverOwnershipState Absent { get; } =
            new(
                Present: false,
                Corrupt: false,
                Owner: null,
                ServiceName: null,
                ProtocolAbi: null,
                State: "NOT_INSTALLED",
                RuntimeManifestSha256: null,
                Message: null);
    }

    private sealed record DriverServiceRegistration(
        bool Present,
        bool ExpectedBinary,
        string ImagePath)
    {
        public static DriverServiceRegistration Absent { get; } =
            new(
                Present: false,
                ExpectedBinary: false,
                ImagePath: string.Empty);
    }
}

public enum WfpProductReadinessKind
{
    RuntimeMissing,
    RuntimeInvalid,
    PackagedOnly,
    ProductionReadyNotInstalled,
    InstalledReady,
    UpdateRequired,
    RecoveryRequired,
    OwnershipConflict
}

public sealed record WfpProductReadinessSnapshot(
    WfpProductReadinessKind Kind,
    bool PackagePresent,
    bool CanUseWfp,
    string Summary,
    string Detail);
