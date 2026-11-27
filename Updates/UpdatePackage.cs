using System.IO;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace SerpiumVPN.Updates;

public static class UpdatePackage
{
    public const long MaxArchiveBytes = 512L * 1024 * 1024;
    public static bool IsSha256(string hash) => hash.Length == 64 && hash.All(char.IsAsciiHexDigit);

    public static string CreatePrivateDirectory(string parent, string prefix)
    {
        string path = Path.Combine(parent, prefix + Guid.NewGuid().ToString("N"));
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(acl);
        return path;
    }

    public static void Verify(string path, string expectedHash)
    {
        using var file = File.OpenRead(path);
        if (!IsSha256(expectedHash) || file.Length <= 0 || file.Length > MaxArchiveBytes ||
            !string.Equals(Convert.ToHexString(SHA256.HashData(file)), expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Контрольная сумма обновления не совпала. Установка отменена.");
        file.Position = 0;
        using var zip = new ZipArchive(file, ZipArchiveMode.Read);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        if (zip.Entries.Count > 10000) throw new InvalidDataException("В обновлении слишком много файлов.");
        foreach (var entry in zip.Entries)
        {
            string name = entry.FullName.Replace('\\', '/');
            bool directory = name.EndsWith('/');
            string[] parts = name.TrimEnd('/').Split('/');
            if (parts.Any(p => string.IsNullOrEmpty(p) || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') ||
                p.Any(c => c < 32 || "<>:\"|?*".Contains(c)) || IsDeviceName(p)) ||
                ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000 || !names.Add(name.TrimEnd('/')))
                throw new InvalidDataException("Недопустимый путь в обновлении.");
            if (parts.Any(p => new[] { "profiles", "SubscriptionDevices", ".serpium-server", "logs", "configs", "state", "Tests", "Server" }.Contains(p, StringComparer.OrdinalIgnoreCase)) ||
                name.EndsWith("serpium.runtime.json", StringComparison.OrdinalIgnoreCase) ||
                new[] { ".sdevice", ".svault", ".sroutes" }.Contains(Path.GetExtension(name), StringComparer.OrdinalIgnoreCase))
                throw new InvalidDataException("Обновление содержит пользовательские данные.");
            expanded = checked(expanded + entry.Length);
            if (expanded > 2L * 1024 * 1024 * 1024 || (directory && entry.Length != 0))
                throw new InvalidDataException("Недопустимый размер содержимого обновления.");
        }
        foreach (string required in new[] { "SerpiumVPN.exe", "SerpiumVPN.dll", "SerpiumVPN.runtimeconfig.json", "SerpiumUpdater.exe", "bin_files/relay/sing-box.exe", "bin_files/relay/xray.exe", "Assets/Serpium.App.ico" })
            if (!zip.Entries.Any(e => e.FullName.Replace('\\', '/').Equals(required, StringComparison.OrdinalIgnoreCase) && e.Length > 0))
                throw new InvalidDataException("В обновлении отсутствуют необходимые файлы приложения.");
    }

    public static void RejectLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Обновление через ссылку на другую папку не поддерживается.");
    }

    private static bool IsDeviceName(string part)
    {
        string stem = part.Split('.')[0].ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL" ||
            (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && char.IsAsciiDigit(stem[3]));
    }
}
