
namespace ThreatForge.Api.Models;

public sealed record DailyThreatActivityItem
{
    public required DateOnly DateUtc { get; init; }

    public required string SourceName { get; init; }

    public required long ObservationCount { get; init; }

    public required long DistinctIndicatorCount { get; init; }
}

public sealed record DailyThreatActivityResponse
{
    public required string Timezone { get; init; }

    public required long TotalObservations { get; init; }

    public required IReadOnlyList<DailyThreatActivityItem>
        DailyActivity
    { get; init; }

    public required DateTimeOffset GeneratedAtUtc { get; init; }
}
