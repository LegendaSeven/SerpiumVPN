using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace SerpiumVPN.Relay.Routing;

/// <summary>
/// Product ownership boundary for the packaged Serpium.Flow native runtime.
/// It never installs or signs the kernel driver; it only resolves/verifies the
/// application-owned payload and identifies WFP user-mode processes/state that
/// Serpium is allowed to clean up.
/// </summary>
public static class WfpRuntimeOwner
{
    public const string ProtocolAbi = "0x00040000";
    public const string RuntimeManifestFileName = "WFP_RUNTIME_MANIFEST.json";

    private static readonly string[] RequiredPayloadFiles =
    [
        "Serpium.Flow.Service.exe",
        "Serpium.Flow.Driver.sys",
        "Serpium.Flow.Driver.inf",
        "serpium.flow.driver.cat",
        "BUILD_MANIFEST.json"
    ];

    public static string PackagedRuntimeDirectory =>
        Path.Combine(
            AppContext.BaseDirectory,
            "bin_files",
            "wfp",
            "x64");

    public static string EphemeralRuntimeDirectory =>
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "SerpiumVPN",
            "Runtime",
            "WFP");

    public static WfpRuntimeResolution ResolvePackagedRuntime()
    {
        string root = PackagedRuntimeDirectory;
        if (!Directory.Exists(root))
        {
            return new WfpRuntimeResolution(
                PackagePresent: false,
                Available: false,
                ServiceExecutablePath: null,
                Message: "Packaged WFP runtime отсутствует.");
        }

        string manifestPath = Path.Combine(
            root,
            RuntimeManifestFileName);
        if (!File.Exists(manifestPath))
        {
            return Invalid(
                "WFP runtime package найден, но manifest отсутствует.");
        }

        try
        {
            using FileStream stream = File.OpenRead(manifestPath);
            using JsonDocument document = JsonDocument.Parse(stream);
            JsonElement rootElement = document.RootElement;

            int schema = rootElement.TryGetProperty(
                    "schema",
                    out JsonElement schemaElement) &&
                schemaElement.TryGetInt32(out int schemaValue)
                    ? schemaValue
                    : 0;
            if (schema != 1)
                return Invalid($"Неподдерживаемая схема WFP runtime manifest: {schema}.");

            string? protocolAbi = TryGetString(
                rootElement,
                "protocolAbi");
            if (!string.Equals(
                    protocolAbi,
                    ProtocolAbi,
                    StringComparison.Ordinal))
            {
                return Invalid(
                    $"WFP runtime ABI {protocolAbi ?? "<missing>"} не совпадает с {ProtocolAbi}.");
            }

            string? platform = TryGetString(
                rootElement,
                "platform");
            if (!string.Equals(
                    platform,
                    "x64",
                    StringComparison.OrdinalIgnoreCase))
            {
                return Invalid(
                    $"WFP runtime platform {platform ?? "<missing>"} не поддерживается.");
            }

            if (!rootElement.TryGetProperty(
                    "files",
                    out JsonElement filesElement) ||
                filesElement.ValueKind != JsonValueKind.Array)
            {
                return Invalid("WFP runtime manifest не содержит files[].");
            }

            Dictionary<string, string> expectedHashes = new(
                StringComparer.OrdinalIgnoreCase);

            foreach (JsonElement fileElement in filesElement.EnumerateArray())
            {
                string? name = TryGetString(fileElement, "name");
                string? sha256 = TryGetString(fileElement, "sha256");

                if (string.IsNullOrWhiteSpace(name) ||
                    string.IsNullOrWhiteSpace(sha256) ||
                    !string.Equals(
                        Path.GetFileName(name),
                        name,
                        StringComparison.Ordinal))
                {
                    return Invalid("WFP runtime manifest содержит небезопасную запись файла.");
                }

                expectedHashes[name] = sha256.Trim().ToLowerInvariant();
            }

            foreach (string requiredName in RequiredPayloadFiles)
            {
                if (!expectedHashes.TryGetValue(
                        requiredName,
                        out string? expectedHash))
                {
                    return Invalid(
                        $"WFP runtime manifest не содержит {requiredName}.");
                }

                string filePath = Path.Combine(root, requiredName);
                if (!File.Exists(filePath))
                {
                    return Invalid(
                        $"WFP runtime payload неполный: отсутствует {requiredName}.");
                }

                string actualHash = ComputeSha256(filePath);
                if (!string.Equals(
                        actualHash,
                        expectedHash,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return Invalid(
                        $"WFP runtime hash mismatch: {requiredName}.");
                }
            }

            string servicePath = Path.Combine(
                root,
                "Serpium.Flow.Service.exe");

            return new WfpRuntimeResolution(
                PackagePresent: true,
                Available: true,
                ServiceExecutablePath: servicePath,
                Message: "Packaged WFP runtime проверен.");
        }
        catch (IOException exception)
        {
            return Invalid(
                "Не удалось прочитать WFP runtime package: " +
                exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return Invalid(
                "Нет доступа к WFP runtime package: " +
                exception.Message);
        }
        catch (JsonException exception)
        {
            return Invalid(
                "WFP runtime manifest повреждён: " +
                exception.Message);
        }
        catch (CryptographicException exception)
        {
            return Invalid(
                "Не удалось проверить WFP runtime hash: " +
                exception.Message);
        }
    }

    public static bool IsOwnedExecutablePath(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            return false;

        return IsInsideDirectory(
                   executablePath,
                   PackagedRuntimeDirectory) ||
               IsInsideDirectory(
                   executablePath,
                   EphemeralRuntimeDirectory);
    }

    public static int CleanupEphemeralState()
    {
        string root = EphemeralRuntimeDirectory;
        if (!Directory.Exists(root))
            return 0;

        try
        {
            int files = Directory
                .EnumerateFiles(
                    root,
                    "*",
                    SearchOption.AllDirectories)
                .Count();

            Directory.Delete(root, recursive: true);
            return files;
        }
        catch (IOException)
        {
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static WfpRuntimeResolution Invalid(string message) =>
        new(
            PackagePresent: true,
            Available: false,
            ServiceExecutablePath: null,
            Message: message);

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

    private static string ComputeSha256(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return Convert
            .ToHexString(SHA256.HashData(stream))
            .ToLowerInvariant();
    }

    private static bool IsInsideDirectory(
        string candidatePath,
        string directoryPath)
    {
        try
        {
            string candidate = Path.GetFullPath(candidatePath);
            string directory = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(directoryPath));

            return candidate.StartsWith(
                directory + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}

public sealed record WfpRuntimeResolution(
    bool PackagePresent,
    bool Available,
    string? ServiceExecutablePath,
    string Message);
