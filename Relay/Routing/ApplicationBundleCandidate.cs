using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;

namespace SerpiumVPN.Relay.Routing;

public sealed class ApplicationBundleCandidate : INotifyPropertyChanged
{
    private bool _isSelected;

    public ApplicationBundleCandidate(
        string executablePath,
        bool isPrimary,
        bool isSelected,
        bool isRecommended,
        bool isObserved,
        string sourceDescription)
    {
        ExecutablePath = Path.GetFullPath(executablePath);
        IsPrimary = isPrimary;
        IsRecommended = isRecommended || isPrimary;
        IsObserved = isObserved;
        SourceDescription = sourceDescription;
        _isSelected = isPrimary || isSelected;

        string? productName = null;
        string? fileDescription = null;
        string? companyName = null;
        try
        {
            FileVersionInfo info = FileVersionInfo.GetVersionInfo(ExecutablePath);
            productName = info.ProductName;
            fileDescription = info.FileDescription;
            companyName = info.CompanyName;
        }
        catch
        {
            // File metadata is optional for a routing candidate.
        }

        ProductName = FirstNotEmpty(
            productName,
            fileDescription,
            Path.GetFileNameWithoutExtension(ExecutablePath));
        CompanyName = string.IsNullOrWhiteSpace(companyName)
            ? "Издатель не указан"
            : companyName.Trim();
    }

    public string ExecutablePath { get; }
    public string FileName => Path.GetFileName(ExecutablePath);
    public string ProductName { get; }
    public string CompanyName { get; }
    public string SourceDescription { get; private set; }
    public bool IsPrimary { get; }
    public bool CanToggle => !IsPrimary;
    public bool IsRecommended { get; private set; }
    public bool IsObserved { get; private set; }
    public bool Exists => File.Exists(ExecutablePath);

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            bool normalized = IsPrimary || value;
            if (_isSelected == normalized)
                return;

            _isSelected = normalized;
            OnPropertyChanged();
        }
    }

    public void MergeEvidence(
        bool isSelected,
        bool isRecommended,
        bool isObserved,
        string sourceDescription)
    {
        IsRecommended |= isRecommended;
        IsObserved |= isObserved;

        if (!string.IsNullOrWhiteSpace(sourceDescription) &&
            !SourceDescription.Contains(sourceDescription, StringComparison.OrdinalIgnoreCase))
        {
            SourceDescription = string.IsNullOrWhiteSpace(SourceDescription)
                ? sourceDescription
                : SourceDescription + " · " + sourceDescription;
            OnPropertyChanged(nameof(SourceDescription));
        }

        if (isSelected || IsPrimary)
            IsSelected = true;

        OnPropertyChanged(nameof(IsRecommended));
        OnPropertyChanged(nameof(IsObserved));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private static string FirstNotEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim()
        ?? "Приложение";
}
