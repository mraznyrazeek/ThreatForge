
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public interface IIndicatorDistributionService
{
    Task<IndicatorDistributionResponse>
        GetDistributionAsync(
            CancellationToken cancellationToken = default);
}
