namespace SerpiumVPN.Core;

/// <summary>
/// Describes one external engine package located under the runtime Engines directory.
/// </summary>
public sealed class EngineManifest
{
    public int SchemaVersion { get; init; }

    public string Id { get; init; } = string.Empty;

    public int ApiVersion { get; init; }

    public string Assembly { get; init; } = string.Empty;

    public string? EntryType { get; init; }

    public bool Enabled { get; init; } = true;
}
