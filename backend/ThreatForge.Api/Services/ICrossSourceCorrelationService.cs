
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public interface ICrossSourceCorrelationService
{
    Task<CrossSourceCorrelationResponse> GetCorrelationAsync(
        CancellationToken cancellationToken = default);
}
