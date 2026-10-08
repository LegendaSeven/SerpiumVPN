using System.IO;
using System.Security;

namespace SerpiumVPN.UI;

/// <summary>Stores only the selected vault entry ID, never a key.</summary>
public sealed class ProfileSelectionStore
{
    private readonly string _path;
    public ProfileSelectionStore(string? path = null) => _path = Path.GetFullPath(path ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SerpiumVPN", "simple-profile.txt"));
    public Guid? Load(IEnumerable<Guid> available)
    {
        try
        {
            return Guid.TryParse(File.ReadAllText(_path).Trim(), out var id) && available.Contains(id) ? id : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException) { return null; }
    }
    public bool TrySave(Guid? id)
    {
        string temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(temporary, id?.ToString("D") ?? "");
            File.Move(temporary, _path, overwrite: true);
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException) { return false; }
        finally
        {
            try { File.Delete(temporary); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException) { }
        }
    }
}
