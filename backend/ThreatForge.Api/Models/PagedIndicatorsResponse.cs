
namespace ThreatForge.Api.Models;

public sealed record IndicatorListItem
{
    public required long Id { get; init; }

    public required string IndicatorType { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }
}

public sealed record PagedIndicatorsResponse
{
    public required IReadOnlyList<IndicatorListItem> Items
    {
        get;
        init;
    }

    public required int Page { get; init; }

    public required int PageSize { get; init; }

    public required long TotalItems { get; init; }

    public required long TotalPages { get; init; }

    public required bool HasNextPage { get; init; }

    public required bool HasPreviousPage { get; init; }
}
