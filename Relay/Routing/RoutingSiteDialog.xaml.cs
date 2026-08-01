using WpfKey = System.Windows.Input.Key;
using WpfKeyEventArgs = System.Windows.Input.KeyEventArgs;
using WpfMouseButton = System.Windows.Input.MouseButton;
using WpfMouseButtonEventArgs = System.Windows.Input.MouseButtonEventArgs;
using WpfRoutedEventArgs = System.Windows.RoutedEventArgs;
using WpfWindow = System.Windows.Window;

namespace SerpiumVPN.Relay.Routing;

public partial class RoutingSiteDialog : WpfWindow
{
    public RoutingSiteDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => SiteAddressTextBox.Focus();
    }

    public string Domain { get; private set; } = string.Empty;
    public bool IncludeSubdomains => IncludeSubdomainsCheckBox.IsChecked == true;

    private void SiteAddressTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        try
        {
            Domain = SecureRoutingRegistry.NormalizeDomain(SiteAddressTextBox.Text);
            ValidationTextBlock.Text = $"Будет добавлен домен: {Domain}";
            ValidationTextBlock.Foreground = System.Windows.Media.Brushes.LightGreen;
            AddButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            Domain = string.Empty;
            ValidationTextBlock.Text = string.IsNullOrWhiteSpace(SiteAddressTextBox.Text)
                ? string.Empty
                : ex.Message;
            ValidationTextBlock.Foreground = System.Windows.Media.Brushes.LightCoral;
            AddButton.IsEnabled = false;
        }
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

    private void Add_Click(object sender, WpfRoutedEventArgs e)
    {
        try
        {
            Domain = SecureRoutingRegistry.NormalizeDomain(SiteAddressTextBox.Text);
            DialogResult = true;
        }
        catch (Exception ex)
        {
            ValidationTextBlock.Text = ex.Message;
            ValidationTextBlock.Foreground = System.Windows.Media.Brushes.LightCoral;
            AddButton.IsEnabled = false;
        }
    }
}
