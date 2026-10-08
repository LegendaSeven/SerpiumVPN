using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;

namespace SerpiumVPN.UI;

public sealed class SimpleProfileRow(Guid id, string displayName) : INotifyPropertyChanged
{
    public Guid Id { get; } = id;
    public string DisplayName { get; } = displayName;
    public string MarkLabel => "Отметить «" + DisplayName + "»";
    public string DeleteLabel => "Удалить «" + DisplayName + "»";
    private bool _isMarked, _selectionMode;
    public bool IsMarked { get => _isMarked; set { _isMarked=value; PropertyChanged?.Invoke(this,new(nameof(IsMarked))); } }
    public bool SelectionMode { get => _selectionMode; set { _selectionMode=value; PropertyChanged?.Invoke(this,new(nameof(SelectionMode))); } }
    public event PropertyChangedEventHandler? PropertyChanged;
}

public partial class SimpleHomeView
{
    public ObservableCollection<SimpleProfileRow> Profiles { get; } = new();
    public event Action<ApplicationRouteRequest>? ApplicationRouteRequested;
    public event Action<Guid?>? ProfileSelectionRequested;
    public event Action<IReadOnlyList<Guid>>? ProfilesDeleteRequested;
    private bool _hasSavedKey, _updatingProfiles, _canEditProfiles, _profileSelectionMode, _connectionActionEnabled;
    private Guid? _selectedProfileId;
    private Guid[] _pendingDeleteIds = [];
    public Guid? SelectedProfileId => _selectedProfileId;

    public void SetProfiles(IEnumerable<SimpleProfileItem> profiles, Guid? selected)
    {
        _updatingProfiles = true;
        try
        {
            DeleteConfirmationPopup.IsOpen = false;
            _pendingDeleteIds = [];
            Profiles.Clear();
            foreach (var profile in profiles.Where(p=>p.Id.HasValue).DistinctBy(p=>p.Id))
                Profiles.Add(new(profile.Id!.Value,profile.DisplayName));
            _selectedProfileId = selected.HasValue && Profiles.Any(p=>p.Id==selected) ? selected : null;
            ProfileList.SelectedValue = _selectedProfileId;
            _hasSavedKey = _selectedProfileId.HasValue;
            if (_hasSavedKey) KeyInput.Clear();
            SetProfileSelectionMode(false);
            EmptyProfilesText.Visibility = Profiles.Count==0 ? Visibility.Visible : Visibility.Collapsed;
            UpdateKeyHint();
        }
        finally { _updatingProfiles=false; }
    }

    private void SetActiveProfile(Guid? id)
    {
        bool previous = _updatingProfiles;
        _updatingProfiles=true;
        try { _selectedProfileId=id; ProfileList.SelectedValue=id; _hasSavedKey=id.HasValue; if (id.HasValue) KeyInput.Clear(); }
        finally { _updatingProfiles=previous; }
        RefreshProfileControls();
        UpdateKeyHint();
    }

    private void ProfileList_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingProfiles) return;
        if (!_canEditProfiles || _profileSelectionMode)
        {
            SetActiveProfile(_selectedProfileId);
            return;
        }
        _selectedProfileId=ProfileList.SelectedValue is Guid id ? id : null;
        _hasSavedKey=_selectedProfileId.HasValue;
        // Do not let clearing a previously entered key trigger another selection change.
        _updatingProfiles=true;
        try { KeyInput.Clear(); }
        finally { _updatingProfiles=false; }
        DeleteConfirmationPopup.IsOpen=false;
        RefreshProfileControls();
        UpdateKeyHint();SetMessage("");
        ProfileSelectionRequested?.Invoke(_selectedProfileId);
    }

    private void NewProfile_Click(object sender, RoutedEventArgs e)
    {
        if (!_canEditProfiles) return;
        SetProfileSelectionMode(false);
        SetActiveProfile(null);KeyInput.Clear();SetMessage("");
        ProfileSelectionRequested?.Invoke(null);
        KeyInput.Focus();
    }

    private void SelectProfiles_Click(object sender, RoutedEventArgs e)
    {
        if (_canEditProfiles) SetProfileSelectionMode(!_profileSelectionMode);
    }

    private void SetProfileSelectionMode(bool value)
    {
        _profileSelectionMode=value;
        DeleteConfirmationPopup.IsOpen=false;
        foreach (var row in Profiles) { row.SelectionMode=value; if (!value) row.IsMarked=false; }
        SelectProfilesButton.Content=value ? "Готово" : "Выбрать";
        BatchProfileTools.Visibility=value ? Visibility.Visible : Visibility.Collapsed;
        RefreshProfileControls();
    }

    private void RefreshProfileControls()
    {
        if (ProfileList is null) return;
        ProfileList.IsEnabled=_canEditProfiles;
        ProfileList.ToolTip=_connected ? "Отключитесь, чтобы изменить профили." : null;
        NewProfileButton.IsEnabled=_canEditProfiles;
        SelectProfilesButton.IsEnabled=_canEditProfiles && Profiles.Count>0;
        SelectAllProfiles.IsEnabled=_canEditProfiles;
        KeyInput.IsEnabled=_canEditProfiles && !_profileSelectionMode && !SelectedProfileId.HasValue && !_hasSavedKey;
        ConnectButton.IsEnabled=_connectionActionEnabled && (!_profileSelectionMode || _connectionBusy);
        DeleteConfirmation.IsEnabled=_canEditProfiles;
        int marked=Profiles.Count(p=>p.IsMarked);
        MarkedProfilesCount.Text="Выбрано: " + marked;
        SelectAllProfiles.IsChecked=marked==0 ? false : marked==Profiles.Count ? true : null;
        DeleteMarkedProfilesButton.IsEnabled=_canEditProfiles && marked>0;
    }

    private void ProfileMark_Click(object sender, RoutedEventArgs e)
    {
        e.Handled=true;
        DeleteConfirmationPopup.IsOpen=false;
        RefreshProfileControls();
    }

    private void SelectAllProfiles_Click(object sender, RoutedEventArgs e)
    {
        if (!_canEditProfiles || !_profileSelectionMode) return;
        bool mark=Profiles.Any(p=>!p.IsMarked);
        foreach (var row in Profiles) row.IsMarked=mark;
        DeleteConfirmationPopup.IsOpen=false;
        RefreshProfileControls();
    }

    private void DeleteProfile_Click(object sender, RoutedEventArgs e)
    {
        e.Handled=true;
        if (sender is FrameworkElement { DataContext:SimpleProfileRow row })
            AskDelete([row.Id],sender as UIElement);
    }

    private void DeleteMarkedProfiles_Click(object sender, RoutedEventArgs e) =>
        AskDelete(Profiles.Where(p=>p.IsMarked).Select(p=>p.Id).ToArray(),DeleteMarkedProfilesButton);

    private void AskDelete(Guid[] ids, UIElement? anchor)
    {
        if (!_canEditProfiles || ids.Length==0 || ids.Any(id=>!Profiles.Any(p=>p.Id==id))) return;
        DeleteConfirmationPopup.IsOpen=false;
        _pendingDeleteIds=ids.Distinct().ToArray();
        DeleteConfirmationText.Text=ids.Length==1
            ? $"Удалить «{Profiles.First(p=>p.Id==ids[0]).DisplayName}»? Для восстановления понадобится ключ."
            : $"Удалить отмеченные профили ({ids.Length})? Для восстановления понадобятся ключи.";
        DeleteConfirmationPopup.PlacementTarget=anchor ?? ProfilesPanel;
        DeleteConfirmationPopup.IsOpen=true;
        CancelDeleteButton.Focus();
    }

    private void DeleteConfirmation_Closed(object sender, EventArgs e) => _pendingDeleteIds=[];
    private void CancelDelete_Click(object sender, RoutedEventArgs e)
    {
        _pendingDeleteIds=[];
        DeleteConfirmationPopup.IsOpen=false;
    }
    private void ConfirmDelete_Click(object sender, RoutedEventArgs e)
    {
        Guid[] ids=_pendingDeleteIds;
        CancelDelete_Click(sender,e);
        if (_canEditProfiles && ids.Length>0 && ids.All(id=>Profiles.Any(p=>p.Id==id)))
            ProfilesDeleteRequested?.Invoke(ids);
    }
}
