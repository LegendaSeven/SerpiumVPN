using System;
using System.Collections.Generic;
using System.Linq;

namespace SerpiumVPN.Core;

/// <summary>
/// Summary of one dynamic engine discovery pass.
/// </summary>
public sealed class EngineDiscoveryResult
{
    public static EngineDiscoveryResult Empty { get; } =
        new(Array.Empty<EngineLoadResult>());

    public EngineDiscoveryResult(IReadOnlyList<EngineLoadResult> results)
    {
        Results = results ?? throw new ArgumentNullException(nameof(results));
    }

    public IReadOnlyList<EngineLoadResult> Results { get; }

    public int Found => Results.Count;

    public int Loaded => Results.Count(result => result.Status == EngineLoadStatus.Loaded);

    public int Skipped => Results.Count(result => result.Status == EngineLoadStatus.Skipped);

    public int Failed => Results.Count(result => result.Status == EngineLoadStatus.Failed);

    public bool IsSuccessful => Failed == 0;
}
