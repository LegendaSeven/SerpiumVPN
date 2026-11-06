using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using SerpiumVPN.Relay.Outline;

namespace SerpiumVPN.UI;

public partial class SimpleHomeView
{
    public bool IsOutlineAutoMode { get; private set; }
    public string OutlineSource => string.IsNullOrWhiteSpace(OutlineSourceInput.Password)
        ? OutlineKeySource.DefaultSource : OutlineSourceInput.Password.Trim();

    private void ConnectionMode_Click(object sender, RoutedEventArgs e)
    {
        if (_canEditProfiles)
        {
            IsOutlineAutoMode = sender == AutoConnectionMode;
            SetProfileSelectionMode(false);
            DeleteConfirmationPopup.IsOpen = false;
            SetMessage("");
        }
        RefreshOutlineControls();
    }

    public void ShowManualConnectionMode()
    {
        IsOutlineAutoMode = false;
        OutlineSourceInput.Clear();
        RefreshOutlineControls();
    }

    private void RefreshOutlineControls()
    {
        if (OutlineAutoPanel is null) return;
        ConnectionModeControls.IsEnabled = _canEditProfiles;
        ManualConnectionMode.IsChecked = !IsOutlineAutoMode;
        AutoConnectionMode.IsChecked = IsOutlineAutoMode;
        OutlineAutoPanel.Visibility = IsOutlineAutoMode ? Visibility.Visible : Visibility.Collapsed;
        OutlineSourceInput.IsEnabled = _canEditProfiles;
        ProfilesPanel.Visibility = IsOutlineAutoMode ? Visibility.Collapsed : Visibility.Visible;
        ManualKeyPanel.Visibility = IsOutlineAutoMode ? Visibility.Collapsed : Visibility.Visible;
        if (!_connectionBusy && !_connected) ConnectButton.Content = IsOutlineAutoMode ? "Подобрать и подключиться" : "Подключиться";
    }

    private void OutlineSource_Changed(object sender, RoutedEventArgs e)
    {
        if (OutlineSourceHint is null) return;
        using var password = OutlineSourceInput.SecurePassword;
        OutlineSourceHint.Visibility = password.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        SetMessage("");
    }
}
