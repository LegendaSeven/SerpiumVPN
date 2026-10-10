using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using SerpiumVPN.Relay.Routing;

namespace SerpiumVPN.UI;

public sealed record SimpleWebsiteItem(Guid Id, string Domain, bool IncludeSubdomains, bool IsVpnEnabled)
{
    public string AccessibleName => Domain + " через VPN";
    public string DeleteLabel => "Удалить сайт " + Domain;
    public string Description => IncludeSubdomains ? "Включая поддомены" : "Только этот домен";
}
public sealed record WebsiteAddRequest(string Input, bool IncludeSubdomains);
public sealed record WebsiteRouteRequest(Guid Id, bool Enabled);

public partial class SimpleHomeView
{
    public ObservableCollection<SimpleWebsiteItem> Websites { get; } = new();
    public event Action<ManualApplicationTarget>? ManualApplicationAddRequested;
    public event Action<Guid>? ManualApplicationDeleteRequested;
    public event Action<WebsiteAddRequest>? WebsiteAddRequested;
    public event Action<WebsiteRouteRequest>? WebsiteRouteRequested;
    public event Action<Guid>? WebsiteDeleteRequested;

    public void SetWebsites(IEnumerable<RoutingRegistryEntry> entries)
    {
        var rows = entries.Where(item => item.Kind == RoutingTargetKind.Website)
            .OrderBy(item => item.PrimaryValue, StringComparer.CurrentCultureIgnoreCase)
            .Select(item => new SimpleWebsiteItem(item.Id, item.PrimaryValue, item.IncludeSubdomains, item.IsEnabled)).ToArray();
        if (!Websites.SequenceEqual(rows)) { Websites.Clear(); foreach (var row in rows) Websites.Add(row); }
        EmptyWebsitesText.Visibility = Websites.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }
    public void SetRoutingMessage(string text, bool error = false)
    {
        RoutingFeedback.Text = text;
        RoutingFeedback.SetResourceReference(TextBlock.ForegroundProperty, error ? "Theme.Error" : "Theme.Muted");
        RoutingFeedback.Visibility = string.IsNullOrWhiteSpace(text) ? Visibility.Collapsed : Visibility.Visible;
    }
    public void ClearWebsiteInput() => WebsiteInput.Clear();
    private void RoutingTab_Click(object sender, RoutedEventArgs e)
    {
        bool sites = sender == WebsitesTab;
        ApplicationsTab.SetCurrentValue(ToggleButton.IsCheckedProperty, !sites);
        WebsitesTab.SetCurrentValue(ToggleButton.IsCheckedProperty, sites);
        ApplicationsPanel.Visibility = sites ? Visibility.Collapsed : Visibility.Visible;
        WebsitesPanel.Visibility = sites ? Visibility.Visible : Visibility.Collapsed;
        AddApplicationButton.Visibility = sites ? Visibility.Collapsed : Visibility.Visible;
        WebsiteEditor.Visibility = sites ? Visibility.Visible : Visibility.Collapsed;
        SetRoutingMessage("");
    }
    private void AddApplication_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ApplicationPickerWindow { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() == true && dialog.SelectedTarget is { } target) ManualApplicationAddRequested?.Invoke(target);
    }
    private void DeleteApplication_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button { DataContext: SimpleApplicationItem { IsManuallyAdded: true, RuleId: { } id } })
            ManualApplicationDeleteRequested?.Invoke(id);
    }
    private void AddWebsite_Click(object sender, RoutedEventArgs e) => RequestWebsite();
    private void WebsiteInput_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter && RoutingControls.IsEnabled) { RequestWebsite(); e.Handled = true; }
    }
    private void RequestWebsite() => WebsiteAddRequested?.Invoke(new(WebsiteInput.Text, IncludeSiteSubdomains.IsChecked == true));
    private void WebsiteToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton { DataContext: SimpleWebsiteItem item } toggle)
        {
            bool desired = toggle.IsChecked == true;
            toggle.SetCurrentValue(ToggleButton.IsCheckedProperty, item.IsVpnEnabled);
            WebsiteRouteRequested?.Invoke(new(item.Id, desired));
        }
    }
    private void DeleteWebsite_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button { DataContext: SimpleWebsiteItem item }) WebsiteDeleteRequested?.Invoke(item.Id);
    }
}
