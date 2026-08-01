namespace SerpiumVPN.Relay.Routing;

public enum RoutingTargetKind
{
    Application = 0,
    Website = 1
}

public sealed record RoutingRegistryEntry
{
    public Guid Id { get; init; }
    public RoutingTargetKind Kind { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string PrimaryValue { get; init; } = string.Empty;
    public string[] RelatedExecutables { get; init; } = Array.Empty<string>();
    public bool IncludeSubdomains { get; init; }
    public bool IsEnabled { get; init; }
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset UpdatedUtc { get; init; }

    public int ExecutableCount =>
        Kind == RoutingTargetKind.Application
            ? Math.Max(1, RelatedExecutables.Length)
            : 0;
}
