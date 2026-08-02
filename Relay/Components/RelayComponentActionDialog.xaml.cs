using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using InputKey = System.Windows.Input.Key;
using InputKeyEventArgs = System.Windows.Input.KeyEventArgs;
using MediaBrush = System.Windows.Media.Brush;
using MediaBrushConverter = System.Windows.Media.BrushConverter;

namespace SerpiumVPN.Relay.Components;

public enum RelayComponentActionDialogMode
{
    Install,
    Rollback
}

public partial class RelayComponentActionDialog : Window
{
    private readonly RelayComponentActionDialogMode _mode;

    private RelayComponentActionDialog(
        RelayComponentActionDialogMode mode,
        string componentName,
        string currentVersion,
        string targetVersion)
    {
        _mode = mode;

        InitializeComponent();
        Configure(
            componentName,
            currentVersion,
            targetVersion);
    }

    public static bool ConfirmInstall(
        Window owner,
        string componentName,
        string currentVersion,
        string targetVersion)
    {
        ArgumentNullException.ThrowIfNull(owner);

        RelayComponentActionDialog dialog = new(
            RelayComponentActionDialogMode.Install,
            componentName,
            NormalizeVersion(currentVersion),
            NormalizeVersion(targetVersion))
        {
            Owner = owner
        };

        return dialog.ShowDialog() == true;
    }

    public static bool ConfirmRollback(
        Window owner,
        string componentName,
        string currentVersion,
        string targetVersion)
    {
        ArgumentNullException.ThrowIfNull(owner);

        RelayComponentActionDialog dialog = new(
            RelayComponentActionDialogMode.Rollback,
            componentName,
            NormalizeVersion(currentVersion),
            NormalizeVersion(targetVersion))
        {
            Owner = owner
        };

        return dialog.ShowDialog() == true;
    }

    private void Configure(
        string componentName,
        string currentVersion,
        string targetVersion)
    {
        bool isXray = componentName.Contains(
            "Xray",
            StringComparison.OrdinalIgnoreCase);

        ComponentBadgeText.Text = isXray ? "X" : "S";
        ComponentBadgeBorder.Background = BrushFromHex(
            isXray ? "#262040" : "#103B2A");
        ComponentBadgeBorder.BorderBrush = BrushFromHex(
            isXray ? "#6858D8" : "#208F5C");
        ComponentBadgeText.Foreground = BrushFromHex(
            isXray ? "#B7A7FF" : "#68EDAA");

        CurrentVersionText.Text = currentVersion;
        TargetVersionText.Text = targetVersion;

        if (_mode == RelayComponentActionDialogMode.Install)
        {
            ConfigureInstall(
                componentName,
                targetVersion);
        }
        else
        {
            ConfigureRollback(
                componentName,
                targetVersion);
        }
    }

    private void ConfigureInstall(
        string componentName,
        string targetVersion)
    {
        ActionTitleText.Text =
            "Установка компонента Relay";

        ActionSubtitleText.Text =
            $"{componentName} будет обновлён до {targetVersion}. " +
            "Перед заменой Serpium создаст проверенный rollback backup.";

        WarningText.Text =
            "Активный профиль Serpium Relay будет временно отключён. " +
            "После установки его можно подключить снова.";

        TargetVersionLabelText.Text =
            "Новая версия";

        ConfirmButton.Content =
            $"Установить {targetVersion}";

        ConfirmButton.Style =
            (Style)FindResource(
                "DialogPrimaryButtonStyle");

        TargetVersionBorder.Background =
            BrushFromHex("#11251C");
        TargetVersionBorder.BorderBrush =
            BrushFromHex("#287C52");
        TargetVersionLabelText.Foreground =
            BrushFromHex("#75C79B");
        TargetVersionText.Foreground =
            BrushFromHex("#71F2AA");

        FooterHintText.Text =
            "Ключи, профили, маршрутизация и компоненты Zapret не изменяются.";
    }

    private void ConfigureRollback(
        string componentName,
        string targetVersion)
    {
        ActionTitleText.Text =
            "Rollback компонента Relay";

        ActionSubtitleText.Text =
            $"{componentName} будет возвращён к версии {targetVersion} " +
            "из ранее проверенного резервного снимка.";

        WarningText.Text =
            "Активный профиль Serpium Relay будет временно отключён. " +
            "Текущий бинарник будет заменён сохранённой версией.";

        TargetVersionLabelText.Text =
            "Версия восстановления";

        ConfirmButton.Content =
            $"Вернуть {targetVersion}";

        ConfirmButton.Style =
            (Style)FindResource(
                "DialogRollbackButtonStyle");

        TargetVersionBorder.Background =
            BrushFromHex("#2A2211");
        TargetVersionBorder.BorderBrush =
            BrushFromHex("#8C6920");
        TargetVersionLabelText.Foreground =
            BrushFromHex("#D8B96E");
        TargetVersionText.Foreground =
            BrushFromHex("#FFD983");

        FooterHintText.Text =
            "Staging, ключи, профили, маршрутизация и компоненты Zapret не изменяются.";
    }

    private static string NormalizeVersion(
        string? version)
    {
        return string.IsNullOrWhiteSpace(version)
            ? "не определена"
            : version.Trim();
    }

    private static MediaBrush BrushFromHex(
        string value)
    {
        return (MediaBrush)new MediaBrushConverter()
            .ConvertFromString(value)!;
    }

    private void Confirm_Click(
        object sender,
        RoutedEventArgs e)
    {
        DialogResult = true;
    }

    private void Cancel_Click(
        object sender,
        RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Window_KeyDown(
        object sender,
        InputKeyEventArgs e)
    {
        if (e.Key != InputKey.Escape)
            return;

        e.Handled = true;
        DialogResult = false;
    }

    private void Header_MouseLeftButtonDown(
        object sender,
        MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
            return;

        try
        {
            DragMove();
        }
        catch
        {
            // Ignore a drag race if the dialog closes at the same moment.
        }
    }
}
