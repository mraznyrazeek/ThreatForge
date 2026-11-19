
using System.Text.Json;

namespace ThreatForge.Api.Models;

public sealed record IndicatorDetailResponse
{
    public required long Id { get; init; }

    public required string IndicatorType { get; init; }

    public required string NormalizedValue { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public required long ObservationCount { get; init; }

    public required bool HasMoreObservations { get; init; }

    public required IReadOnlyList<IndicatorObservationItem>
        Observations
    { get; init; }
}

public sealed record IndicatorObservationItem
{
    public required long Id { get; init; }

    public required long SourceId { get; init; }

    public required string SourceName { get; init; }

    public required string SourceRecordId { get; init; }

    public required string ThreatType { get; init; }

    public string? MalwareFamily { get; init; }

    public required int ConfidenceLevel { get; init; }

    public required DateTimeOffset FirstSeenUtc { get; init; }

    public DateTimeOffset? LastSeenUtc { get; init; }

    public required string TimestampQuality { get; init; }

    public string? Reporter { get; init; }

    public string? Reference { get; init; }

    public required JsonElement Tags { get; init; }

    public required DateTimeOffset UpdatedAtUtc { get; init; }
}
