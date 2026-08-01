using WpfKey = System.Windows.Input.Key;
using WpfKeyEventArgs = System.Windows.Input.KeyEventArgs;
using WpfMouseButton = System.Windows.Input.MouseButton;
using WpfMouseButtonEventArgs = System.Windows.Input.MouseButtonEventArgs;
using WpfRoutedEventArgs = System.Windows.RoutedEventArgs;
using WpfWindow = System.Windows.Window;

namespace SerpiumVPN.Relay.ProfileVault;

/// <summary>
/// Serpium-styled destructive confirmation dialog.
/// The dialog receives only the safe display name already shown in the profile card.
/// No connection key or decrypted profile data is passed to it.
/// </summary>
public partial class ProfileDeleteConfirmDialog : WpfWindow
{
    public ProfileDeleteConfirmDialog(string? safeProfileName)
    {
        InitializeComponent();

        ProfileNameTextBlock.Text = string.IsNullOrWhiteSpace(safeProfileName)
            ? "Выбранный профиль"
            : safeProfileName.Trim();

        Loaded += (_, _) => CancelButton.Focus();
    }

    private void Header_MouseLeftButtonDown(object sender, WpfMouseButtonEventArgs e)
    {
        if (e.ChangedButton != WpfMouseButton.Left)
            return;

        try
        {
            DragMove();
        }
        catch (InvalidOperationException)
        {
            // The mouse button may have been released before DragMove started.
        }
    }

    private void Dialog_KeyDown(object sender, WpfKeyEventArgs e)
    {
        if (e.Key != WpfKey.Escape)
            return;

        e.Handled = true;
        CloseWithResult(false);
    }

    private void Cancel_Click(object sender, WpfRoutedEventArgs e) =>
        CloseWithResult(false);

    private void Delete_Click(object sender, WpfRoutedEventArgs e) =>
        CloseWithResult(true);

    private void CloseWithResult(bool result)
    {
        DialogResult = result;
    }
}
