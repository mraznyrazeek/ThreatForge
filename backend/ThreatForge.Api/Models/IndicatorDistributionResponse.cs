
namespace ThreatForge.Api.Models;

public sealed record IndicatorDistributionItem
{
    public required string IndicatorType { get; init; }

    public required long Count { get; init; }

    public required decimal Percentage { get; init; }
}

public sealed record IndicatorDistributionResponse
{
    public required long TotalIndicators { get; init; }

    public required IReadOnlyList<IndicatorDistributionItem>
        Distribution
    { get; init; }

    public required DateTimeOffset GeneratedAtUtc { get; init; }
}
