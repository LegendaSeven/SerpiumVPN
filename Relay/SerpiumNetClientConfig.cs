using System.Diagnostics;
using System.Text.Json;
using System.IO;
namespace SerpiumVPN.Relay;

/// <summary>
/// Shared configuration for the embedded SerpiumNet/tsnet client.
/// No system Tailscale installation or browser authorization is used.
/// </summary>
public static class SerpiumNetClientConfig
{
    public const string DefaultControlUrl = "http://127.0.0.1:8080";

    public static string RootDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SerpiumVPN",
        "SerpiumNet");

    public static string ClientStateDirectory =>
        Path.Combine(RootDirectory, "Client");

    public static string ClientAuthKeyPath =>
        Path.Combine(RootDirectory, "headscale-client-auth.key");

    public static string ClientControlUrlPath =>
        Path.Combine(RootDirectory, "client-control-url.txt");

    public static string BridgeRuntimePath =>
        Path.Combine(RootDirectory, "client-bridge-runtime.json");

    public static string ResolveBinaryPath()
    {
        string baseDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        string[] candidates =
        [
            Path.Combine(baseDir, "Engines", "serpium.SerpiumNet", "Runtime", "SerpiumNet.exe"),
            Path.Combine(baseDir, "SerpiumNet.exe"),
            Path.Combine(baseDir, "bin_files", "relay", "SerpiumNet.exe")
        ];

        string? path = candidates.FirstOrDefault(File.Exists);
        if (path is null)
        {
            throw new FileNotFoundException(
                "Встроенный SerpiumNet.exe не найден. Пересоберите внешний модуль " +
                "serpium.SerpiumNet либо переустановите компонент SerpiumNet.");
        }

        return Path.GetFullPath(path);
    }

    public static SerpiumNetClientEnrollment ResolveEnrollment()
    {
        Directory.CreateDirectory(RootDirectory);
        Directory.CreateDirectory(ClientStateDirectory);

        string controlUrl = ReadFirstNonEmpty(
            Environment.GetEnvironmentVariable("SERPIUM_CONTROL_URL"),
            ReadOptionalText(ClientControlUrlPath),
            DefaultControlUrl);

        if (!Uri.TryCreate(controlUrl, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(
                "Некорректный адрес Headscale. Укажите http:// или https:// адрес в " +
                ClientControlUrlPath + ".");
        }

        string authKey = ReadFirstNonEmpty(
            Environment.GetEnvironmentVariable("SERPIUM_AUTH_KEY"),
            ReadOptionalText(ClientAuthKeyPath),
            string.Empty);

        bool hasState = HasPersistentClientState();
        if (!hasState && string.IsNullOrWhiteSpace(authKey))
        {
            throw new InvalidOperationException(
                "Клиент SerpiumNet ещё не зарегистрирован в Headscale. " +
                "Положите одноразовый ключ в:\n" + ClientAuthKeyPath +
                "\n\nАдрес координатора задаётся в:\n" + ClientControlUrlPath +
                "\n\nБраузерная авторизация намеренно отключена.");
        }

        return new SerpiumNetClientEnrollment(
            ResolveBinaryPath(),
            controlUrl.Trim(),
            authKey.Trim(),
            hasState,
            ClientStateDirectory);
    }

    public static bool HasPersistentClientState()
    {
        try
        {
            return Directory.Exists(ClientStateDirectory) &&
                   Directory.EnumerateFiles(
                       ClientStateDirectory,
                       "*",
                       SearchOption.AllDirectories).Any();
        }
        catch
        {
            return false;
        }
    }

    public static void DeleteConsumedAuthKeyFile()
    {
        try
        {
            if (File.Exists(ClientAuthKeyPath))
                File.Delete(ClientAuthKeyPath);
        }
        catch
        {
            // A consumed one-time key is never logged. A failed cleanup is non-fatal.
        }
    }

    public static void WriteBridgeRuntime(SerpiumNetBridgeRuntime state)
    {
        Directory.CreateDirectory(RootDirectory);
        File.WriteAllText(
            BridgeRuntimePath,
            JsonSerializer.Serialize(
                state,
                new JsonSerializerOptions { WriteIndented = true }));
    }

    public static bool TryReadBridgeRuntime(out SerpiumNetBridgeRuntime? state)
    {
        state = null;
        try
        {
            if (!File.Exists(BridgeRuntimePath))
                return false;

            state = JsonSerializer.Deserialize<SerpiumNetBridgeRuntime>(
                File.ReadAllText(BridgeRuntimePath));

            return state is not null &&
                   state.ProcessId > 0 &&
                   state.LocalPort is > 0 and <= 65535 &&
                   state.RemotePort is > 0 and <= 65535;
        }
        catch
        {
            state = null;
            return false;
        }
    }

    public static bool HasLiveBridgeProcess()
    {
        if (!TryReadBridgeRuntime(out SerpiumNetBridgeRuntime? state) || state is null)
            return false;

        try
        {
            using Process process = Process.GetProcessById(state.ProcessId);
            if (process.HasExited)
                return false;

            string? actualPath = process.MainModule?.FileName;
            return !string.IsNullOrWhiteSpace(actualPath) &&
                   Path.GetFullPath(actualPath).Equals(
                       Path.GetFullPath(state.ExecutablePath),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static void DeleteBridgeRuntime()
    {
        try
        {
            if (File.Exists(BridgeRuntimePath))
                File.Delete(BridgeRuntimePath);
        }
        catch
        {
            // Runtime metadata must never block disconnect.
        }
    }

    private static string ReadOptionalText(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path).Trim() : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ReadFirstNonEmpty(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
                return value.Trim();
        }

        return string.Empty;
    }
}

public sealed record SerpiumNetClientEnrollment(
    string BinaryPath,
    string ControlUrl,
    string AuthKey,
    bool HasPersistentState,
    string StateDirectory);

public sealed class SerpiumNetBridgeRuntime
{
    public int ProcessId { get; set; }
    public string ExecutablePath { get; set; } = string.Empty;
    public string RemoteHost { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public int LocalPort { get; set; }
    public DateTime StartedAtUtc { get; set; }
}
