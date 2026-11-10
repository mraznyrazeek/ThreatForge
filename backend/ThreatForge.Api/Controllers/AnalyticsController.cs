
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;

namespace ThreatForge.Api.Controllers;

[ApiController]
[Route("api/v1/analytics")]
public sealed class AnalyticsController : ControllerBase
{
    private readonly IIndicatorDistributionService
        _distributionService;

    private readonly IMalwareFamilyService
        _malwareFamilyService;

    private readonly IDailyThreatActivityService
        _dailyActivityService;

    private readonly ILogger<AnalyticsController> _logger;

    public AnalyticsController(
        IIndicatorDistributionService distributionService,
        IMalwareFamilyService malwareFamilyService,
        IDailyThreatActivityService dailyActivityService,
        ILogger<AnalyticsController> logger)
    {
        _distributionService = distributionService;
        _malwareFamilyService = malwareFamilyService;
        _dailyActivityService = dailyActivityService;
        _logger = logger;
    }

    [HttpGet("indicators/distribution")]
    [ProducesResponseType(
        typeof(IndicatorDistributionResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<IndicatorDistributionResponse>>
        GetIndicatorDistribution(
            CancellationToken cancellationToken)
    {
        try
        {
            var result =
                await _distributionService.GetDistributionAsync(
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
                "PostgreSQL indicator distribution query failed.");

            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    Status = "unavailable",
                    Message = "Analytics data is temporarily unavailable."
                });
        }
    }

    [HttpGet("malware/families")]
    [ProducesResponseType(
        typeof(MalwareFamilyResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status400BadRequest)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<MalwareFamilyResponse>>
        GetMalwareFamilies(
            [FromQuery] int limit = 15,
            CancellationToken cancellationToken = default)
    {
        if (limit < 1 || limit > 100)
        {
            return BadRequest(new
            {
                Error = "Limit must be between 1 and 100."
            });
        }

        try
        {
            var result =
                await _malwareFamilyService.GetTopFamiliesAsync(
                    limit,
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
                "PostgreSQL malware-family query failed.");

            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    Status = "unavailable",
                    Message = "Malware analytics are temporarily unavailable."
                });
        }
    }

    [HttpGet("temporal/daily")]
    [ProducesResponseType(
        typeof(DailyThreatActivityResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<DailyThreatActivityResponse>>
        GetDailyThreatActivity(
            CancellationToken cancellationToken)
    {
        try
        {
            var result =
                await _dailyActivityService.GetDailyActivityAsync(
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
                "PostgreSQL daily activity query failed.");

            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    Status = "unavailable",
                    Message = "Temporal analytics are temporarily unavailable."
                });
        }
    }
}
