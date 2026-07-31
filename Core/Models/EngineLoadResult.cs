namespace SerpiumVPN.Core;

/// <summary>
/// Result of processing one external engine package.
/// </summary>
public sealed record EngineLoadResult(
    string EngineId,
    string PackageDirectory,
    EngineLoadStatus Status,
    string Message,
    string? EngineName = null);
