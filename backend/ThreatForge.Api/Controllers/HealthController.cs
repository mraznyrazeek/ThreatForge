
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ThreatForge.Api.Controllers;

[ApiController]
[Route("api/v1/health")]
[AllowAnonymous]
public sealed class HealthController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult GetHealth()
    {
        var response = new
        {
            Status = "healthy",
            Service = "ThreatForge.Api",
            Version = "1.0",
            TimestampUtc = DateTimeOffset.UtcNow
        };

        return Ok(response);
    }
}
