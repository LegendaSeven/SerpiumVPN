using System.Windows;
using System.Windows.Controls;

namespace SerpiumVPN.UI;

public enum ProgramUpdateAction { Check, Download, Install }

public partial class SimpleHomeView
{
    public event EventHandler? ProgramUpdateRequested;
    public event EventHandler? ProgramUpdateCancelRequested;
    public event EventHandler? ProgramUpdateRecheckRequested;
    public event Action<bool>? AutomaticProgramChecksChanged;
    private bool _programUpdateBusy, _programUpdateAvailable, _settingAutomaticChecks;
    private ProgramUpdateAction _programUpdateAction;

    public void SetProgramUpdateState(string version, string message, ProgramUpdateAction action,
        bool available, bool busy, int? progress = null, bool canCancel = false)
    {
        _programUpdateAction = action; _programUpdateAvailable = available; _programUpdateBusy = busy;
        ProgramVersion.Text = "Serpium · " + version;
        ProgramUpdateStatus.Text = message;
        ProgramUpdateButton.Content = action switch
        {
            ProgramUpdateAction.Download => "Скачать обновление",
            ProgramUpdateAction.Install => "Установить и перезапустить",
            _ => "Проверить обновления"
        };
        ProgramDownloadProgress.Visibility = progress.HasValue ? Visibility.Visible : Visibility.Collapsed;
        ProgramDownloadProgress.Value = progress ?? 0;
        ProgramUpdateCancelButton.Visibility = canCancel ? Visibility.Visible : Visibility.Collapsed;
        ProgramRecheckButton.Visibility = action == ProgramUpdateAction.Download && !busy ? Visibility.Visible : Visibility.Collapsed;
        RefreshProgramUpdateButton(); RefreshUpdateBadge();
    }

    public void SetAutomaticProgramChecks(bool enabled)
    {
        _settingAutomaticChecks = true;
        AutomaticProgramChecks.IsChecked = enabled;
        _settingAutomaticChecks = false;
    }
    private void RefreshProgramUpdateButton()
    {
        ProgramUpdateButton.IsEnabled = !_programUpdateBusy &&
            (_programUpdateAction != ProgramUpdateAction.Install || !_connectionBusy);
        ProgramUpdateButton.ToolTip = _programUpdateAction == ProgramUpdateAction.Install && _connected
            ? "VPN будет отключён перед перезапуском." : null;
    }
    private void RefreshUpdateBadge()
    {
        UpdateBadge.Visibility = _programUpdateAvailable || _componentUpdatesAvailable ? Visibility.Visible : Visibility.Collapsed;
        UpdatesMenuButton.ToolTip = _programUpdateAvailable ? "Доступно обновление Serpium" : "Обновления Serpium, sing-box и Xray";
    }
    private void ProgramUpdate_Click(object sender, RoutedEventArgs e) => ProgramUpdateRequested?.Invoke(this, EventArgs.Empty);
    private void ProgramUpdateCancel_Click(object sender, RoutedEventArgs e) => ProgramUpdateCancelRequested?.Invoke(this, EventArgs.Empty);
    private void ProgramRecheck_Click(object sender, RoutedEventArgs e) => ProgramUpdateRecheckRequested?.Invoke(this, EventArgs.Empty);
    private void AutomaticProgramChecks_Click(object sender, RoutedEventArgs e)
    {
        if (!_settingAutomaticChecks) AutomaticProgramChecksChanged?.Invoke(AutomaticProgramChecks.IsChecked == true);
    }
}
