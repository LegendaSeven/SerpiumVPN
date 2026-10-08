using SerpiumVPN.UI;

namespace SerpiumVPN;

public partial class MainWindow
{
    private readonly ThemePreferenceStore _themePreferences = new();
    private AppTheme _appearanceTheme;

    private void InitializeAppearance()
    {
        _appearanceTheme = _themePreferences.Load();
        AppThemes.Apply(System.Windows.Application.Current.Resources, _appearanceTheme);
    }

    private void ThemeToggleRequested(object? sender, EventArgs e)
    {
        _appearanceTheme = AppThemes.Next(_appearanceTheme);
        AppThemes.Apply(System.Windows.Application.Current.Resources, _appearanceTheme);
        SimpleHome.SetTheme(_appearanceTheme);
        UpdateTitleBarTheme();
        if (!_themePreferences.TrySave(_appearanceTheme))
            SimpleHome.SetMessage("Тема изменена, но сохранить выбор не удалось.", isError: true);
    }
}
