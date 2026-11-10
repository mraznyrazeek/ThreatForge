
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;

namespace ThreatForge.Api.Controllers;

[ApiController]
[Route("api/v1/intelligence")]
public sealed class IntelligenceController : ControllerBase
{
    private readonly IIntelligenceSummaryService _summaryService;
    private readonly ILogger<IntelligenceController> _logger;

    public IntelligenceController(
        IIntelligenceSummaryService summaryService,
        ILogger<IntelligenceController> logger)
    {
        _summaryService = summaryService;
        _logger = logger;
    }

    [HttpGet("summary")]
    [ProducesResponseType(
        typeof(IntelligenceSummaryResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<IntelligenceSummaryResponse>>
        GetSummary(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _summaryService.GetSummaryAsync(
                cancellationToken);

            return Ok(result);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (NpgsqlException)
        {
            _logger.LogError(
                "PostgreSQL intelligence summary query failed.");

            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    Status = "unavailable",
                    Message =
                        "Intelligence data is temporarily unavailable."
                });
        }
    }
}
