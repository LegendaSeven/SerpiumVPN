using System.IO;

namespace SerpiumUpdater;

internal static class LegacyPayloadCleanup
{
    // Migration only. Exact obsolete program files; no profile, settings or driver data.
    private static readonly string[] Files =
    [
        "Serpium.Engine.Abstractions.dll",
        "Engines/SampleEngine/Serpium.SampleEngine.dll",
        "Engines/SampleEngine/manifest.json",
        "Engines/SampleEngine/README.md",
        "Engines/README.md",
        "Engines/manifest.example.json",
        "Engines/.gitkeep",
        "Engines/serpium.SerpiumNet/manifest.json",
        "Engines/serpium.SerpiumNet/Runtime/Serpium.SerpiumNet.Engine.deps.json",
        "Engines/serpium.SerpiumNet/Runtime/Serpium.SerpiumNet.Engine.dll",
        "Engines/serpium.SerpiumNet/Runtime/SerpiumNet.exe",
        "Engines/serpium.TemplateSmoke/manifest.json",
        "Engines/serpium.TemplateSmoke/Runtime/TemplateSmoke.deps.json",
        "Engines/serpium.TemplateSmoke/Runtime/TemplateSmoke.dll",
        "bin_files/relay/SerpiumNet.exe",
        "bin_files/tgws/TgWsProxy.exe",
        "bin_files/tgws/TgWsProxy_windows.exe",
        "bin_files/tgws/README_SERPIUM.txt",
        "licenses/LICENSE_tg-ws-proxy.txt",
    ];

    internal static void RemoveObsoleteFiles(string installDirectory, Action<string> log)
    {
        string root = Path.GetFullPath(installDirectory).TrimEnd(Path.DirectorySeparatorChar);
        foreach (string relative in Files)
        {
            string path = Path.GetFullPath(Path.Combine(root, relative));
            if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Invalid obsolete program path.");
            // A junction in an installation must never turn migration into an external deletion.
            bool linked = false;
            for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            {
                if ((File.Exists(current) || Directory.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) { linked = true; break; }
                if (string.Equals(current, root, StringComparison.OrdinalIgnoreCase)) break;
            }
            if (linked) { log($"Skipped linked obsolete program file: {relative}"); continue; }
            try { if (File.Exists(path)) { File.Delete(path); log($"Removed obsolete program file: {relative}"); } }
            catch (IOException) { log($"Obsolete file is in use: {relative}"); }
            catch (UnauthorizedAccessException) { log($"Cannot remove obsolete program file: {relative}"); }
        }
    }
}
