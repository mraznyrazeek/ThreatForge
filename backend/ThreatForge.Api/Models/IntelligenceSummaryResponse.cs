
namespace ThreatForge.Api.Models;

public sealed record IntelligenceSummaryResponse
{
    public required long CanonicalIndicators { get; init; }

    public required long SourceObservations { get; init; }

    public required long IntelligenceSources { get; init; }

    public required DateTimeOffset GeneratedAtUtc { get; init; }
}
