
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public interface IThreatIndicatorService
{
    Task<PagedIndicatorsResponse> GetIndicatorsAsync(
        int page,
        int pageSize,
        string? indicatorType,
        CancellationToken cancellationToken = default);

    Task<IndicatorDetailResponse?> GetIndicatorByIdAsync(
        long id,
        CancellationToken cancellationToken = default);
}
