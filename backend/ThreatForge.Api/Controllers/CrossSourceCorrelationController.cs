
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;

namespace ThreatForge.Api.Controllers;

[ApiController]
[Route("api/v1/analytics/correlation/sources")]
public sealed class CrossSourceCorrelationController
    : ControllerBase
{
    private readonly ICrossSourceCorrelationService _service;

    private readonly ILogger<CrossSourceCorrelationController>
        _logger;

    public CrossSourceCorrelationController(
        ICrossSourceCorrelationService service,
        ILogger<CrossSourceCorrelationController> logger)
    {
        _service = service;
        _logger = logger;
    }

    [HttpGet]
    [ProducesResponseType(
        typeof(CrossSourceCorrelationResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<CrossSourceCorrelationResponse>>
        GetCorrelation(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _service.GetCorrelationAsync(
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
                "PostgreSQL cross-source correlation query failed.");

            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    Status = "unavailable",
                    Message =
                        "Source correlation is temporarily unavailable."
                });
        }
    }
}
