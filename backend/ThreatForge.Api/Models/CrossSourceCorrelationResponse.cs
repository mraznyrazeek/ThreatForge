
namespace ThreatForge.Api.Models;

public sealed record SourceOverlapItem
{
    public required string FirstSource { get; init; }

    public required string SecondSource { get; init; }

    public required long SharedIndicators { get; init; }
}

public sealed record CrossSourceCorrelationResponse
{
    public required long SharedCanonicalIndicators { get; init; }

    public required IReadOnlyList<SourceOverlapItem>
        SourcePairs
    { get; init; }

    public required DateTimeOffset GeneratedAtUtc { get; init; }
}
