using System.IO;
using System.Windows;
using System.Windows.Controls;
using SerpiumVPN.Relay.Routing;

namespace SerpiumVPN.UI;

public partial class ApplicationPickerWindow : Window
{
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Dictionary<bool, IReadOnlyList<ApplicationCatalogItem>> _cache = [];
    private IReadOnlyList<ApplicationCatalogItem> _items = [];
    private bool _running, _loading;
    private int _request;
    public ManualApplicationTarget? SelectedTarget { get; private set; }

    public ApplicationPickerWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => { SearchInput.Focus(); await LoadAsync(); };
        Closed += (_, _) => { _lifetime.Cancel(); };
    }

    private async Task LoadAsync(bool refresh = false)
    {
        int request = ++_request; bool running = _running; _loading = true;
        RefreshButton.IsEnabled = FileButton.IsEnabled = InstalledTab.IsEnabled = RunningTab.IsEnabled = false;
        AppList.IsEnabled = false; AddButton.IsEnabled = false; EmptyText.Text = "Загружаем приложения…"; EmptyText.Visibility = Visibility.Visible;
        try
        {
            if (refresh || !_cache.TryGetValue(running, out var values))
                values = await InstalledApplicationDiscovery.SelectionCatalogAsync(running, _lifetime.Token);
            if (_lifetime.IsCancellationRequested || request != _request) return;
            _cache[running] = values; _items = values; _loading = false; Filter();
        }
        catch (OperationCanceledException) { }
        catch (Exception)
        {
            if (_lifetime.IsCancellationRequested || request != _request) return;
            _items = []; _loading = false; Filter();
            Feedback.Text = "Не удалось прочитать каталог. Можно выбрать EXE или ярлык через «Из файла…».";
        }
        finally { if (request == _request && !_lifetime.IsCancellationRequested) { _loading = false; AppList.IsEnabled = true; RefreshButton.IsEnabled = FileButton.IsEnabled = InstalledTab.IsEnabled = RunningTab.IsEnabled = true; } }
    }

    private void Filter()
    {
        if (AppList is null || _loading) return;
        string search = SearchInput.Text.Trim();
        AppList.ItemsSource = _items.Where(item => item.DisplayName.Contains(search, StringComparison.CurrentCultureIgnoreCase) ||
            item.Category.Contains(search, StringComparison.CurrentCultureIgnoreCase)).ToArray();
        EmptyText.Text = "Ничего не найдено. Попробуйте «Запущенные» или «Из файла…».";
        EmptyText.Visibility = AppList.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (AppList.Items.Count == 0) Feedback.Text = "Запустите программу и обновите список «Запущенные» либо выберите её EXE. Приложения внутри общего процесса Java, Python или WSL пока не переключаются раздельно.";
    }
    private void Search_Changed(object sender, TextChangedEventArgs e) => Filter();
    private async void Tab_Click(object sender, RoutedEventArgs e)
    {
        _running = sender == RunningTab; RunningTab.IsChecked = _running; InstalledTab.IsChecked = !_running;
        WebsiteEditor.Visibility = Visibility.Collapsed; await LoadAsync();
    }
    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync(true);
    private void Selection_Changed(object sender, SelectionChangedEventArgs e)
    {
        var item = AppList.SelectedItem as ApplicationCatalogItem;
        AddButton.IsEnabled = !_loading && item?.CanSelect == true;
        WebsiteEditor.Visibility = item?.Target.RequiresWebsiteAddress == true ? Visibility.Visible : Visibility.Collapsed;
        WebsiteInput.Clear();
        Feedback.Text = item?.Target.UnsupportedReason.Length > 0 ? item.Target.UnsupportedReason : item?.Target.IsWebApplication == true ? "Тумблер будет управлять сайтом, включая обычные вкладки браузера. Другие домены сервиса добавляются отдельно." :
            item?.CanSelect == false ? "Запустите приложение и обновите список «Запущенные». Общий процесс браузера, Java, Python или WSL нельзя разделить одним правилом приложения." :
            "Новое приложение добавляется с выключенным VPN. Системные службы в список не включаются.";
    }

    private async void File_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Выберите приложение или ярлык", Filter = "Приложения и ярлыки|*.exe;*.lnk;*.url;*.appref-ms|Приложения EXE|*.exe|Ярлыки|*.lnk;*.url;*.appref-ms",
            CheckFileExists = true, Multiselect = false, DereferenceLinks = false
        };
        if (dialog.ShowDialog(this) != true) return;
        ++_request; _loading = true; FileButton.IsEnabled = false; AppList.IsEnabled = false; AddButton.IsEnabled = false;
        RefreshButton.IsEnabled = InstalledTab.IsEnabled = RunningTab.IsEnabled = false;
        try
        {
            var target = await ManualApplicationResolver.InspectAsync(dialog.FileName, _lifetime.Token);
            if (_lifetime.IsCancellationRequested) return;
            if (target.DisplayName.Length == 0) target = target with { DisplayName = Path.GetFileNameWithoutExtension(target.PrimaryValue) };
            _items = [new(target, "Выбранный файл")]; _loading = false; SearchInput.Clear(); Filter(); AppList.SelectedIndex = 0;
        }
        catch (OperationCanceledException) { }
        catch (Exception error) { Feedback.Text = error is InvalidOperationException or ArgumentException or FormatException ? error.Message : "Не удалось прочитать файл приложения."; }
        finally { _loading = false; if (!_lifetime.IsCancellationRequested) { FileButton.IsEnabled = AppList.IsEnabled = RefreshButton.IsEnabled = InstalledTab.IsEnabled = RunningTab.IsEnabled = true; } }
    }

    internal static ManualApplicationTarget CompleteTarget(ManualApplicationTarget target, string website) =>
        target.RequiresWebsiteAddress ? target with { PrimaryValue = SecureRoutingRegistry.NormalizeDomain(website), RequiresWebsiteAddress = false } : target;

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        if (_loading || AppList.SelectedItem is not ApplicationCatalogItem { CanSelect: true } item) return;
        try { SelectedTarget = CompleteTarget(item.Target, WebsiteInput.Text); DialogResult = true; }
        catch (Exception error) when (error is ArgumentException or FormatException or InvalidOperationException) { Feedback.Text = error.Message; WebsiteInput.Focus(); }
    }
}
