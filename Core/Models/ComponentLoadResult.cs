namespace SerpiumVPN.Core;

/// <summary>
/// Summary of one component initialization pass.
/// </summary>
public sealed record ComponentLoadResult(
    int Found,
    int Loaded,
    int Failed)
{
    public bool IsSuccessful => Failed == 0;
}
