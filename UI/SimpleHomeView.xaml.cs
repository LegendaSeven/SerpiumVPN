using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using SerpiumVPN.Relay.Routing;

namespace SerpiumVPN.UI;

public sealed class SimpleApplicationItem : INotifyPropertyChanged
{
    public required string DisplayName { get; init; }
    public required string ExecutablePath { get; init; }
    public Guid? RuleId { get; init; }
    public bool IsManuallyAdded { get; init; }
    public bool IsWebApplication { get; init; }
    public string ApplicationId { get; init; } = "";
    public string[] ExecutablePaths { get; init; } = [];
    public bool HasDescription => IsWebApplication || ApplicationId.Length > 0;
    public string Description => IsWebApplication ? "Веб-приложение · " + ExecutablePath : ApplicationId.Length > 0 ? "Microsoft Store / MSIX" : "";
    public string RouteHint => IsWebApplication ? "Правило сайта «" + ExecutablePath + "» действует также в обычных вкладках браузера." : ExecutablePath;
    public string DeleteLabel => "Удалить из ручного списка: " + DisplayName;
    public string AccessibleName => DisplayName + " через VPN";
    private bool _isVpnEnabled;
    public bool IsVpnEnabled
    {
        get => _isVpnEnabled;
        set { _isVpnEnabled = value; PropertyChanged?.Invoke(this, new(nameof(IsVpnEnabled))); }
    }
    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed record SimpleProfileItem(Guid? Id, string DisplayName);

public sealed record ApplicationRouteRequest(SimpleApplicationItem Application, bool Enabled);

public partial class SimpleHomeView : System.Windows.Controls.UserControl
{
    public static IReadOnlyList<SimpleApplicationItem> BuildApplicationRows(
        IReadOnlyList<DiscoveredApplication> applications, IEnumerable<RoutingRegistryEntry> savedRules)
    {
        var eligible = new HashSet<string>(applications.Where(item => !item.IsWebApplication).Select(item => item.ExecutablePath), StringComparer.OrdinalIgnoreCase);
        var identities = new HashSet<string>(applications.Select(item => item.ApplicationId).Where(id => id.Length > 0), StringComparer.OrdinalIgnoreCase);
        var domains = applications.Where(item => item.IsWebApplication).Select(item => item.ExecutablePath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Keep active rules visible so a stricter discovery filter cannot hide a
        // previously enabled route. Manual choices also survive automatic filtering.
        var rules = savedRules.Where(item =>
            (item.Kind == RoutingTargetKind.Application && (eligible.Contains(item.PrimaryValue) || identities.Contains(item.ApplicationId) || item.IsManuallyAdded || item.IsEnabled)) ||
            (item.Kind == RoutingTargetKind.Website && (item.IsWebApplication || domains.Contains(item.PrimaryValue)))).ToArray();
        var known = new HashSet<string>(rules.Where(item => item.Kind == RoutingTargetKind.Application).SelectMany(item => item.RelatedExecutables.Append(item.PrimaryValue)), StringComparer.OrdinalIgnoreCase);
        var knownIds = rules.Select(item => item.ApplicationId).Where(id => id.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var knownSites = rules.Where(item => item.Kind == RoutingTargetKind.Website).Select(item => item.PrimaryValue).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return rules.Select(item => new SimpleApplicationItem { DisplayName = item.DisplayName, ExecutablePath = item.PrimaryValue, IsVpnEnabled = item.IsEnabled, RuleId = item.Id, IsManuallyAdded = item.IsManuallyAdded, IsWebApplication = item.Kind == RoutingTargetKind.Website, ApplicationId = item.ApplicationId, ExecutablePaths = item.RelatedExecutables })
            .Concat(applications.Where(item => item.IsWebApplication ? !knownSites.Contains(item.ExecutablePath) : !known.Contains(item.ExecutablePath) && !knownIds.Contains(item.ApplicationId))
                .Select(item => new SimpleApplicationItem { DisplayName = item.DisplayName, ExecutablePath = item.ExecutablePath, IsWebApplication = item.IsWebApplication, ApplicationId = item.ApplicationId, ExecutablePaths = item.ExecutablePaths }))
            .OrderBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToArray();
    }

    public ObservableCollection<SimpleApplicationItem> Applications { get; } = new();
    public event EventHandler? ConnectRequested;
    public event EventHandler? ThemeToggleRequested;
    public event EventHandler? ComponentUpdatesRequested;
    private bool _componentUpdatesBusy, _componentUpdatesAvailable, _connectionBusy, _connected;
    public void SetComponentUpdateState(string message,bool available,bool busy)
    {
        _componentUpdatesBusy=busy;_componentUpdatesAvailable=available;
        ComponentUpdateStatus.Text=busy ? "Проверяем компоненты…" : message;
        UpdateBadge.Visibility=available ? Visibility.Visible : Visibility.Collapsed;
        UpdatesMenuButton.ToolTip=message;
        ComponentUpdateButton.Content=available?"Обновить компоненты":"Проверить обновления";
        RefreshComponentUpdateButton();
    }
    private void RefreshComponentUpdateButton()
    {
        ComponentUpdateButton.IsEnabled=!_componentUpdatesBusy&&!_connectionBusy&&(!_componentUpdatesAvailable||!_connected);
        ComponentUpdateButton.ToolTip=_componentUpdatesAvailable&&_connected?"Отключите VPN перед обновлением.":null;
    }
    private void ComponentUpdate_Click(object sender,RoutedEventArgs e)=>ComponentUpdatesRequested?.Invoke(this,EventArgs.Empty);
    private void UpdatesMenu_Click(object sender, RoutedEventArgs e)
    {
        ComponentUpdatesPopup.IsOpen = !ComponentUpdatesPopup.IsOpen;
        if (ComponentUpdatesPopup.IsOpen) ComponentUpdateButton.Focus();
    }
    private void Popup_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != System.Windows.Input.Key.Escape) return;
        if (sender == DeleteConfirmationPopup) { CancelDelete_Click(sender, e); ProfileList.Focus(); }
        else { ComponentUpdatesPopup.IsOpen = false; UpdatesMenuButton.Focus(); }
        e.Handled = true;
    }
    public string Key => SelectedProfileId.HasValue ? string.Empty : KeyInput.Password.Trim();
    public SimpleHomeView()
    {
        InitializeComponent();
        ApplicationList.ItemsSource = Applications;
        WebsiteList.ItemsSource = Websites;
        ProfileList.ItemsSource = Profiles;
    }
    public void SetTheme(AppTheme theme)
    {
        ThemeLabel.Text = "Тема: " + AppThemes.DisplayName(theme);
        string action = "Переключить на тему «" + AppThemes.DisplayName(AppThemes.Next(theme)) + "»";
        ThemeButton.ToolTip = action;
        System.Windows.Automation.AutomationProperties.SetName(ThemeButton, ThemeLabel.Text + ". " + action);
    }
    private void Theme_Click(object sender, RoutedEventArgs e) => ThemeToggleRequested?.Invoke(this, EventArgs.Empty);
    public void SetConnectionState(bool connected, bool busy, bool ready, bool hasSavedKey, string? activity = null, bool canStop = false)
    {
        _connected=connected;_connectionBusy=busy||!ready;RefreshComponentUpdateButton();
        _hasSavedKey = hasSavedKey;
        ConnectionStatus.Text = busy ? activity ?? "Подключение…" : connected ? "Соединение активно" : "Не подключено";
        StatusDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, connected && !busy ? "Theme.Success" : "Theme.Muted");
        bool stopAvailable = busy && canStop;
        ConnectButton.Content = stopAvailable ? "Стоп" : busy ? activity ?? "Подключение…" : connected ? "Отключить" : "Подключиться";
        _connectionActionEnabled = stopAvailable || (ready && !busy);
        ConnectButton.ToolTip = stopAvailable ? "Остановить проверку и подключение" : null;
        _canEditProfiles = ready && !connected && !busy;
        if (!_canEditProfiles) DeleteConfirmationPopup.IsOpen = false;
        RefreshProfileControls();
        ApplicationList.IsEnabled = ready && !busy;
        RoutingControls.IsEnabled = ready && !busy;
        UpdateKeyHint();
    }
    public void SetMessage(string message, bool isError = false)
    {
        Feedback.SetResourceReference(TextBlock.ForegroundProperty, isError ? "Theme.Error" : "Theme.Success");
        Feedback.Text = message;
        FeedbackScroll.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        FeedbackScroll.ScrollToTop();
    }
    public void ClearKey() => KeyInput.Clear();
    public void UpdateEmptyState(string? message = null)
    {
        EmptyListText.Text = message ?? "Сетевые приложения появятся здесь автоматически.";
        EmptyListText.Visibility = Applications.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }
    private void UpdateKeyHint()
    {
        if (KeyHint is null) return;
        bool entered = HasEnteredKey;
        KeyHint.Visibility = entered ? Visibility.Collapsed : Visibility.Visible;
        KeyHint.Text = _hasSavedKey ? "•••••••• · сохранённый профиль" : "Вставьте ключ или ссылку";
        if (KeyEntryStatus is not null)
        {
            KeyEntryStatus.Visibility = entered || _hasSavedKey ? Visibility.Visible : Visibility.Collapsed;
            KeyEntryStatus.Text = entered ? "Ключ введён · ••••••••" : _hasSavedKey ? "Сохранённый профиль" : "";
        }
    }
    private bool HasEnteredKey
    {
        get { using var password = KeyInput.SecurePassword; return password.Length > 0; }
    }
    private void KeyInput_Changed(object sender, RoutedEventArgs e)
    {
        if (SelectedProfileId.HasValue && HasEnteredKey)
        {
            // A saved profile and a newly entered key are separate input modes.
            KeyInput.Clear();
            return;
        }
        UpdateKeyHint();
        if (Feedback is not null) SetMessage("");
    }
    private void Connect_Click(object sender, RoutedEventArgs e) => ConnectRequested?.Invoke(this, EventArgs.Empty);
    private void AppToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton { DataContext: SimpleApplicationItem item } toggle)
        {
            bool desired = toggle.IsChecked == true;
            // Selection is committed only after persistence/application succeeds.
            toggle.SetCurrentValue(ToggleButton.IsCheckedProperty, item.IsVpnEnabled);
            ApplicationRouteRequested?.Invoke(new(item, desired));
        }
    }
}
