using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace SerpiumVPN.Relay.Routing;

internal static class UserApplicationPolicy
{
    private static readonly HashSet<string> Infrastructure = new(StringComparer.OrdinalIgnoreCase)
    {
        "serpiumvpn", "serpiumupdater", "serpiumnet", "xray", "sing-box", "tailscale", "tailscaled",
        "svchost", "services", "system", "registry", "explorer", "dwm", "lsass", "csrss", "smss",
        "wininit", "winlogon", "sihost", "taskhostw", "runtimebroker", "applicationframehost",
        "searchhost", "searchapp", "startmenuexperiencehost", "shellexperiencehost", "widgets",
        "widgetservice", "msedgewebview2", "microsoftedgeupdate", "backgroundtaskhost", "dllhost",
        "rundll32", "cmd", "powershell", "pwsh", "conhost", "windowsterminal", "wt", "wsl", "wslhost",
        "node", "java", "javaw", "python", "pythonw", "dotnet", "msiexec", "taskmgr", "regedit",
        "browser_proxy", "chrome_proxy", "msedge_proxy",
        "windowspackagemanagerserver", "winget", "appinstaller"
    };
    private static readonly string[] AuxiliaryTokens =
        ["unins", "uninstall", "setup", "installer", "crash", "updater", "helper", "service", "broker", "telemetry", "redist"];
    // These built-in utilities may declare internetClient or send telemetry. Neither
    // makes them useful automatic VPN suggestions. Use stable identities, not labels.
    private static readonly HashSet<string> AutomaticExcludedPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.WindowsCalculator_8wekyb3d8bbwe", "Microsoft.SecHealthUI_8wekyb3d8bbwe",
        "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe",
        "Microsoft.WindowsTerminal_8wekyb3d8bbwe", "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe",
        "Microsoft.MixedReality.Portal_8wekyb3d8bbwe", "Microsoft.Microsoft3DViewer_8wekyb3d8bbwe",
        "Microsoft.ZuneMusic_8wekyb3d8bbwe", "Microsoft.GetHelp_8wekyb3d8bbwe",
        "Microsoft.MSPaint_8wekyb3d8bbwe", "Microsoft.Paint_8wekyb3d8bbwe",
        "Microsoft.WindowsNotepad_8wekyb3d8bbwe", "Microsoft.ScreenSketch_8wekyb3d8bbwe",
        "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe", "Microsoft.WindowsAlarms_8wekyb3d8bbwe",
        "Microsoft.WindowsCamera_8wekyb3d8bbwe", "Microsoft.Windows.Photos_8wekyb3d8bbwe"
    };
    private static readonly HashSet<string> AutomaticExcludedExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "calc", "calculator", "calculatorapp", "notepad", "mspaint", "wordpad", "charmap", "snippingtool"
    };
    private static readonly HashSet<string> NetworkClients = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "msedge", "brave", "opera", "vivaldi", "waterfox", "librewolf",
        "telegram", "discord", "discordcanary", "discordptb", "slack", "signal", "whatsapp", "viber",
        "zoom", "teams", "ms-teams", "skype", "steam", "epicgameslauncher", "battle.net", "galaxyclient",
        "riotclientux", "ubisoftconnect", "upc", "eadesktop", "origin", "spotify", "deezer", "tidal",
        "qbittorrent", "utorrent", "transmission-qt", "deluge", "filezilla", "winscp", "putty",
        "thunderbird", "outlook", "hxoutlook", "olk", "onedrive", "dropbox", "googledrivefs",
        "obs64", "obs32", "streamlabs", "minecraftlauncher", "robloxplayerbeta"
    };

    internal static bool IsAllowedPath(string path, string windowsDirectory, IReadOnlySet<string> services)
    {
        if (!IsAllowedManualPath(path, windowsDirectory, services)) return false;
        if (IsAutomaticUtility(path)) return false;
        string name = Path.GetFileNameWithoutExtension(path);
        if (AuxiliaryTokens.Any(token => name.Contains(token, StringComparison.OrdinalIgnoreCase))) return false;
        string[] words = Regex.Replace(name, "([a-z])([A-Z])", "$1 $2").Split([' ', '-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        return !words.Any(word => word.Equals("agent",StringComparison.OrdinalIgnoreCase) ||
                                  word.Equals("host",StringComparison.OrdinalIgnoreCase) ||
                                  word.Equals("update",StringComparison.OrdinalIgnoreCase));
    }

    internal static bool IsAutomaticUtility(string path, string applicationId = "")
    {
        int separator = applicationId.IndexOf('!');
        if (separator > 0 && AutomaticExcludedPackages.Contains(applicationId[..separator])) return true;
        if (AutomaticExcludedExecutables.Contains(Path.GetFileNameWithoutExtension(path))) return true;
        // A process or an EXE shortcut may lack AUMID. Package directories contain
        // Name_Version_Architecture_ResourceId_PublisherId, even after Store updates.
        string[] parts = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i + 1 < parts.Length; i++)
        {
            if (!parts[i].Equals("WindowsApps", StringComparison.OrdinalIgnoreCase)) continue;
            string[] package = parts[i + 1].Split('_');
            if (package.Length == 5 && AutomaticExcludedPackages.Contains(package[0] + "_" + package[4])) return true;
        }
        return false;
    }

    internal static bool IsAllowedManualPath(string path, string windowsDirectory, IReadOnlySet<string> services)
    {
        if (!Path.IsPathFullyQualified(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
        path = Path.GetFullPath(path);
        if (path.StartsWith(@"\\",StringComparison.Ordinal)) return false;
        if (services.Contains(path) || IsWithin(path, windowsDirectory)) return false;
        string[] parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Any(part => part.Equals("Common Files", StringComparison.OrdinalIgnoreCase) ||
                              part.Equals("SystemApps", StringComparison.OrdinalIgnoreCase))) return false;
        string name = Path.GetFileNameWithoutExtension(path);
        return !Infrastructure.Contains(name);
    }

    internal static bool IsKnownNetworkClient(string path, string product, string company)
    {
        string stem = Path.GetFileNameWithoutExtension(path);
        if (NetworkClients.Contains(stem)) return true;
        if (stem.Equals("browser",StringComparison.OrdinalIgnoreCase))
            return (product + " " + company).Contains("Yandex",StringComparison.OrdinalIgnoreCase);
        return false;
    }

    internal static bool ShouldInclude(bool allowed, bool userEntryPoint, bool knownClient, bool internetObserved) =>
        allowed && userEntryPoint && (knownClient || internetObserved);

    internal static bool IsInternetAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return false;
        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return bytes[0] is not (0 or 10 or 127) && bytes[0] < 224 &&
                !(bytes[0] == 169 && bytes[1] == 254) && !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
                !(bytes[0] == 192 && bytes[1] == 168) && !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        return !address.Equals(IPAddress.IPv6Any) && !address.IsIPv6LinkLocal && !address.IsIPv6Multicast &&
               !address.IsIPv6SiteLocal && (bytes[0] & 0xfe) != 0xfc;
    }

    internal static bool IsInternetFlow(JsonElement metadata) =>
        metadata.ValueKind == JsonValueKind.Object &&
        metadata.TryGetProperty("destinationIP",out var destination) && destination.ValueKind == JsonValueKind.String &&
        IPAddress.TryParse(destination.GetString(),out var address) && IsInternetAddress(address);

    internal static string Identity(string path, string product, string company)
    {
        // Metadata merges multiple registrations/version directories of one product.
        // Executable names keep distinct apps from suites (Office, Adobe, etc.) apart.
        if (!string.IsNullOrWhiteSpace(product) && !string.IsNullOrWhiteSpace(company))
            return company.Trim() + "|" + product.Trim() + "|" + Path.GetFileName(path);
        return Path.GetFullPath(path);
    }

    private static bool IsWithin(string path, string directory) => !string.IsNullOrWhiteSpace(directory) &&
        path.StartsWith(Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
}
