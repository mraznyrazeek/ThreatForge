
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public interface IIntelligenceSummaryService
{
    Task<IntelligenceSummaryResponse> GetSummaryAsync(
        CancellationToken cancellationToken = default);
}
