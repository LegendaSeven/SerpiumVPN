using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using WpfKey = System.Windows.Input.Key;
using WpfKeyEventArgs = System.Windows.Input.KeyEventArgs;
using WpfMouseButton = System.Windows.Input.MouseButton;
using WpfMouseButtonEventArgs = System.Windows.Input.MouseButtonEventArgs;
using WpfRoutedEventArgs = System.Windows.RoutedEventArgs;
using WpfWindow = System.Windows.Window;

namespace SerpiumVPN.Relay.Routing;

public partial class RoutingApplicationBundleDialog : WpfWindow
{
    private readonly ApplicationBundleDiscoveryService _discoveryService = new();
    private readonly string _primaryExecutablePath;
    private readonly string[] _existingExecutables;
    private readonly string? _existingDisplayName;
    private CancellationTokenSource? _observationCts;
    private bool _observationRunning;
    private bool _uiInitialized;
    private bool _initializationStarted;

    public RoutingApplicationBundleDialog(
        string primaryExecutablePath,
        string? existingDisplayName = null,
        IEnumerable<string>? existingExecutables = null)
    {
        _primaryExecutablePath = Path.GetFullPath(primaryExecutablePath);
        _existingExecutables = existingExecutables?
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray()
            ?? Array.Empty<string>();
        _existingDisplayName = existingDisplayName;

        // Make Candidates available to XAML bindings before InitializeComponent,
        // but do not run discovery or touch named controls in the constructor.
        DataContext = this;
        InitializeComponent();

        Loaded += Dialog_LoadedAsync;
    }

    public ObservableCollection<ApplicationBundleCandidate> Candidates { get; } = new();

    public string DisplayName =>
        DisplayNameTextBox?.Text.Trim() ?? string.Empty;

    public IReadOnlyList<string> SelectedExecutables => Candidates
        .Where(candidate => candidate.IsSelected && candidate.Exists)
        .OrderByDescending(candidate => candidate.IsPrimary)
        .ThenBy(candidate => candidate.FileName, StringComparer.CurrentCultureIgnoreCase)
        .Select(candidate => candidate.ExecutablePath)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private async void Dialog_LoadedAsync(object sender, System.Windows.RoutedEventArgs e)
    {
        if (_initializationStarted)
            return;

        _initializationStarted = true;
        Loaded -= Dialog_LoadedAsync;

        PrimaryPathTextBlock.Text = _primaryExecutablePath;
        DisplayNameTextBox.Text = ResolveFallbackDisplayName();
        ObservationStatusTextBlock.Text =
            "Анализируем папку приложения и метаданные EXE…";

        try
        {
            ApplicationBundleDiscoveryResult initial = await Task.Run(() =>
                _discoveryService.CreateInitial(
                    _primaryExecutablePath,
                    _existingExecutables,
                    _existingDisplayName));

            DisplayNameTextBox.Text = initial.DisplayName;
            PrimaryPathTextBlock.Text = initial.PrimaryExecutablePath;
            MergeCandidates(initial.Candidates);

            ObservationStatusTextBlock.Text =
                $"Статический поиск завершён. Кандидатов в группе: {Candidates.Count}.";
        }
        catch (Exception ex)
        {
            // A malformed version resource, denied directory, or unusual launcher
            // must not terminate Serpium. Keep the chosen EXE as a valid one-file group.
            EnsurePrimaryFallbackCandidate();
            ObservationStatusTextBlock.Text =
                "Автопоиск связанных EXE не завершён: " + ex.Message +
                " Основной EXE оставлен в группе; наблюдение можно запустить вручную.";
        }
        finally
        {
            _uiInitialized = true;
            DisplayNameTextBox.TextChanged += DisplayNameTextBox_TextChanged;
            UpdateUiState();
            DisplayNameTextBox.Focus();
            DisplayNameTextBox.CaretIndex = DisplayNameTextBox.Text.Length;
        }
    }

    private string ResolveFallbackDisplayName()
    {
        if (!string.IsNullOrWhiteSpace(_existingDisplayName))
            return _existingDisplayName.Trim();

        string fileName = Path.GetFileNameWithoutExtension(_primaryExecutablePath);
        return string.IsNullOrWhiteSpace(fileName) ? "Приложение" : fileName;
    }

    private void EnsurePrimaryFallbackCandidate()
    {
        if (Candidates.Any(candidate =>
                string.Equals(
                    candidate.ExecutablePath,
                    _primaryExecutablePath,
                    StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        MergeCandidates(new[]
        {
            new ApplicationBundleCandidate(
                _primaryExecutablePath,
                isPrimary: true,
                isSelected: true,
                isRecommended: true,
                isObserved: false,
                sourceDescription: "Выбранный основной EXE")
        });
    }

    private void MergeCandidates(IEnumerable<ApplicationBundleCandidate> candidates)
    {
        foreach (ApplicationBundleCandidate candidate in candidates)
        {
            ApplicationBundleCandidate? existing = Candidates.FirstOrDefault(item =>
                string.Equals(
                    item.ExecutablePath,
                    candidate.ExecutablePath,
                    StringComparison.OrdinalIgnoreCase));

            if (existing is not null)
            {
                existing.MergeEvidence(
                    candidate.IsSelected,
                    candidate.IsRecommended,
                    candidate.IsObserved,
                    candidate.SourceDescription);
                continue;
            }

            candidate.PropertyChanged += Candidate_PropertyChanged;
            Candidates.Add(candidate);
        }

        List<ApplicationBundleCandidate> ordered = Candidates
            .OrderByDescending(candidate => candidate.IsPrimary)
            .ThenByDescending(candidate => candidate.IsRecommended)
            .ThenBy(candidate => candidate.FileName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        for (int targetIndex = 0; targetIndex < ordered.Count; targetIndex++)
        {
            int currentIndex = Candidates.IndexOf(ordered[targetIndex]);
            if (currentIndex != targetIndex)
                Candidates.Move(currentIndex, targetIndex);
        }

        if (_uiInitialized)
            UpdateUiState();
    }

    private void Candidate_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_uiInitialized &&
            e.PropertyName == nameof(ApplicationBundleCandidate.IsSelected))
        {
            UpdateUiState();
        }
    }

    private void UpdateUiState()
    {
        if (!_uiInitialized ||
            CandidatesCountTextBlock is null ||
            SelectedCountTextBlock is null ||
            DisplayNameTextBox is null ||
            SaveButton is null ||
            RescanButton is null ||
            ObserveButton is null)
        {
            return;
        }

        int selectedCount = Candidates.Count(candidate =>
            candidate.IsSelected && candidate.Exists);

        CandidatesCountTextBlock.Text = $"Кандидатов: {Candidates.Count}";
        SelectedCountTextBlock.Text = $"Выбрано EXE: {selectedCount}";

        bool displayNameValid =
            !string.IsNullOrWhiteSpace(DisplayNameTextBox.Text);

        SaveButton.IsEnabled =
            !_observationRunning && displayNameValid && selectedCount > 0;
        RescanButton.IsEnabled = !_observationRunning;
    }

    private async void Rescan_ClickAsync(object sender, WpfRoutedEventArgs e)
    {
        if (_observationRunning || !_uiInitialized)
            return;

        RescanButton.IsEnabled = false;
        try
        {
            ObservationStatusTextBlock.Text =
                "Повторяем статический поиск по папкам и метаданным…";
            await Task.Yield();

            string[] selectedBeforeScan = Candidates
                .Where(candidate => candidate.IsSelected)
                .Select(candidate => candidate.ExecutablePath)
                .Concat(_existingExecutables)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            ApplicationBundleDiscoveryResult result = await Task.Run(() =>
                _discoveryService.CreateInitial(
                    _primaryExecutablePath,
                    selectedBeforeScan,
                    DisplayNameTextBox.Text));

            MergeCandidates(result.Candidates);
            ObservationStatusTextBlock.Text =
                $"Статический поиск завершён. Кандидатов в группе: {Candidates.Count}.";
        }
        catch (Exception ex)
        {
            EnsurePrimaryFallbackCandidate();
            ObservationStatusTextBlock.Text =
                "Поиск не завершён: " + ex.Message +
                " Основной EXE остаётся доступен.";
        }
        finally
        {
            RescanButton.IsEnabled = true;
            UpdateUiState();
        }
    }

    private async void Observe_ClickAsync(object sender, WpfRoutedEventArgs e)
    {
        if (!_uiInitialized)
            return;

        if (_observationRunning)
        {
            _observationCts?.Cancel();
            return;
        }

        _observationRunning = true;
        _observationCts = new CancellationTokenSource();
        ObserveButton.Content = "Остановить наблюдение";
        RescanButton.IsEnabled = false;
        UpdateUiState();

        try
        {
            Progress<ApplicationBundleObservationProgress> progress = new(update =>
            {
                ObservationStatusTextBlock.Text = update.SecondsRemaining > 0
                    ? $"{update.StatusText} Осталось: {update.SecondsRemaining} с."
                    : update.StatusText;
            });

            IReadOnlyList<ApplicationBundleCandidate> observed =
                await _discoveryService.ObserveLaunchAsync(
                    _primaryExecutablePath,
                    TimeSpan.FromSeconds(30),
                    progress,
                    _observationCts.Token);

            MergeCandidates(observed);
            ObservationStatusTextBlock.Text = observed.Count == 0
                ? "Новые связанные процессы не обнаружены. Можно повторить наблюдение."
                : $"Наблюдение завершено. Добавлено или подтверждено EXE: {observed.Count}.";
        }
        catch (Exception ex)
        {
            ObservationStatusTextBlock.Text =
                "Наблюдение остановлено: " + ex.Message;
        }
        finally
        {
            _observationRunning = false;
            _observationCts.Dispose();
            _observationCts = null;
            ObserveButton.Content = "Наблюдать запуск (30 с)";
            RescanButton.IsEnabled = true;
            UpdateUiState();
        }
    }

    private void DisplayNameTextBox_TextChanged(
        object sender,
        System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_uiInitialized)
            UpdateUiState();
    }

    private void Save_Click(object sender, WpfRoutedEventArgs e)
    {
        if (_observationRunning || !_uiInitialized)
            return;

        if (string.IsNullOrWhiteSpace(DisplayName))
        {
            ObservationStatusTextBlock.Text =
                "Введите название карточки приложения.";
            return;
        }

        if (SelectedExecutables.Count == 0)
        {
            ObservationStatusTextBlock.Text =
                "Выберите хотя бы один существующий EXE.";
            return;
        }

        DialogResult = true;
    }

    private void Cancel_Click(object sender, WpfRoutedEventArgs e)
    {
        _observationCts?.Cancel();
        DialogResult = false;
    }

    private void Dialog_KeyDown(object sender, WpfKeyEventArgs e)
    {
        if (e.Key != WpfKey.Escape)
            return;

        e.Handled = true;
        Cancel_Click(sender, new WpfRoutedEventArgs());
    }

    private void Header_MouseLeftButtonDown(
        object sender,
        WpfMouseButtonEventArgs e)
    {
        if (e.ChangedButton != WpfMouseButton.Left)
            return;

        try
        {
            DragMove();
        }
        catch (InvalidOperationException)
        {
            // Mouse button may be released before DragMove starts.
        }
    }

    private void Dialog_Closing(object? sender, CancelEventArgs e) =>
        _observationCts?.Cancel();
}
