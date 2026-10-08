using System.IO;
using System.Security;
using System.Windows;

namespace SerpiumVPN.UI;

public enum AppTheme { Midnight, SoftPink }

public static class AppThemes
{
    private const string PalettePrefix = "/SerpiumVPN;component/UI/Themes/";

    public static string DisplayName(AppTheme theme) => theme == AppTheme.SoftPink ? "Нежная Булка" : "Полуночная Змеюка";
    public static AppTheme Next(AppTheme theme) => theme == AppTheme.SoftPink ? AppTheme.Midnight : AppTheme.SoftPink;

    public static void Apply(ResourceDictionary resources, AppTheme theme)
    {
        string name = theme == AppTheme.SoftPink ? "SoftPink" : "Midnight";
        var palette = new ResourceDictionary { Source = new Uri(PalettePrefix + name + ".xaml", UriKind.Relative) };
        // Replace only our palette. Keep shared control styles and other application resources.
        var dictionaries = resources.MergedDictionaries;
        for (int i = 0; i < dictionaries.Count; i++)
        {
            string? source = dictionaries[i].Source?.OriginalString;
            if (source == PalettePrefix + "Midnight.xaml" || source == PalettePrefix + "SoftPink.xaml")
            {
                dictionaries[i] = palette;
                return;
            }
        }
        dictionaries.Add(palette);
    }
}

public sealed class ThemePreferenceStore
{
    private readonly string _path;

    public ThemePreferenceStore(string? path = null) => _path = Path.GetFullPath(path ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SerpiumVPN", "appearance.txt"));

    public AppTheme Load()
    {
        try { return File.ReadAllText(_path).Trim() == "soft-pink" ? AppTheme.SoftPink : AppTheme.Midnight; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        { return AppTheme.Midnight; }
    }

    public bool TrySave(AppTheme theme)
    {
        string temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(temporary, theme == AppTheme.SoftPink ? "soft-pink" : "midnight");
            File.Move(temporary, _path, overwrite: true);
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        { return false; }
        finally
        {
            try { File.Delete(temporary); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException) { }
        }
    }
}
