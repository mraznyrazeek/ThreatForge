
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public interface IDailyThreatActivityService
{
    Task<DailyThreatActivityResponse> GetDailyActivityAsync(
        CancellationToken cancellationToken = default);
}
