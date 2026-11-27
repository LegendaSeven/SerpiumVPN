using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using SerpiumVPN.Updates;

namespace SerpiumUpdater;

public static class UpdateInstaller
{
    public static void Install(string archive, string hash, string target, Action<string> log)
    {
        target = Path.GetFullPath(target);
        if (!Directory.Exists(target) || !File.Exists(Path.Combine(target, "SerpiumVPN.exe")))
            throw new IOException("Не найдена папка установленного Serpium.");
        UpdatePackage.RejectLinks(target);
        UpdatePackage.Verify(archive, hash);
        string work = UpdatePackage.CreatePrivateDirectory(Path.GetTempPath(), "Serpium-install-");
        string source = Path.Combine(work, "source"), backup = Path.Combine(work, "backup");
        bool keepBackup = false;
        var replaced = new List<(string Target, string? Backup)>();
        try
        {
            ZipFile.ExtractToDirectory(archive, source);
            var files = Directory.GetFiles(source, "*", SearchOption.AllDirectories).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            var changes = new List<(string Source, string Target, string? Backup)>();
            // Preflight and back up every changed file before replacing any live program file.
            foreach (string file in files)
            {
                string relative = Path.GetRelativePath(source, file);
                string destination = Path.Combine(target, relative);
                UpdatePackage.RejectLinks(destination);
                if (File.Exists(destination) && Identical(file, destination)) continue;
                string? saved = null;
                if (File.Exists(destination))
                {
                    saved = Path.Combine(backup, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(saved)!);
                    File.Copy(destination, saved);
                }
                changes.Add((file, destination, saved));
            }
            try
            {
                foreach (var change in changes)
                {
                    UpdatePackage.RejectLinks(change.Target);
                    Directory.CreateDirectory(Path.GetDirectoryName(change.Target)!);
                    Replace(change.Source, change.Target);
                    replaced.Add((change.Target, change.Backup));
                }
            }
            catch (Exception installError)
            {
                var failures = new List<Exception>();
                foreach (var change in replaced.AsEnumerable().Reverse())
                {
                    try
                    {
                        UpdatePackage.RejectLinks(change.Target);
                        if (change.Backup is not null) Replace(change.Backup, change.Target);
                        else File.Delete(change.Target);
                    }
                    catch (Exception rollbackError) { failures.Add(rollbackError); }
                }
                if (failures.Count > 0)
                {
                    keepBackup = true;
                    log("Recovery backup retained: " + backup);
                    throw new AggregateException("Не удалось завершить восстановление. Переустановите Serpium из установщика; профили сохранены отдельно.", failures.Prepend(installError));
                }
                throw new IOException("Обновление не установлено. Предыдущие файлы восстановлены; запустите Serpium и повторите попытку.", installError);
            }
        }
        finally
        {
            if (!keepBackup) { try { Directory.Delete(work, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
        }
    }

    private static bool Identical(string first, string second)
    {
        if (new FileInfo(first).Length != new FileInfo(second).Length) return false;
        using var a = File.OpenRead(first); using var b = File.OpenRead(second);
        return SHA256.HashData(a).AsSpan().SequenceEqual(SHA256.HashData(b));
    }
    private static void Replace(string source, string destination)
    {
        string temporary = destination + ".update-" + Guid.NewGuid().ToString("N");
        try
        {
            File.Copy(source, temporary);
            File.Move(temporary, destination, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
