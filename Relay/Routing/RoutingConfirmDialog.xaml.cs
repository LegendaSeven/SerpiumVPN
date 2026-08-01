using WpfKey = System.Windows.Input.Key;
using WpfKeyEventArgs = System.Windows.Input.KeyEventArgs;
using WpfMouseButton = System.Windows.Input.MouseButton;
using WpfMouseButtonEventArgs = System.Windows.Input.MouseButtonEventArgs;
using WpfRoutedEventArgs = System.Windows.RoutedEventArgs;
using WpfWindow = System.Windows.Window;

namespace SerpiumVPN.Relay.Routing;

public partial class RoutingConfirmDialog : WpfWindow
{
    public RoutingConfirmDialog(
        string title,
        string question,
        string safeTarget,
        string description,
        string confirmButtonText)
    {
        InitializeComponent();
        WindowTitleTextBlock.Text = "SERPIUM  ·  " + title;
        QuestionTextBlock.Text = question;
        TargetTextBlock.Text = safeTarget;
        DescriptionTextBlock.Text = description;
        ConfirmButton.Content = confirmButtonText;
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
        }
    }

    private void Dialog_KeyDown(object sender, WpfKeyEventArgs e)
    {
        if (e.Key != WpfKey.Escape)
            return;

        e.Handled = true;
        DialogResult = false;
    }

    private void Cancel_Click(object sender, WpfRoutedEventArgs e) =>
        DialogResult = false;

    private void Confirm_Click(object sender, WpfRoutedEventArgs e) =>
        DialogResult = true;
}
