
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using ThreatForge.Api.Models;
using ThreatForge.Api.Services;

namespace ThreatForge.Api.Controllers;

[ApiController]
[Route("api/v1/intelligence/indicators")]
public sealed class ThreatIndicatorsController : ControllerBase
{
    private const int MaxSearchLength = 256;

    private readonly IThreatIndicatorService _service;
    private readonly ILogger<ThreatIndicatorsController> _logger;

    public ThreatIndicatorsController(
        IThreatIndicatorService service,
        ILogger<ThreatIndicatorsController> logger)
    {
        _service = service;
        _logger = logger;
    }

    [HttpGet]
    [ProducesResponseType(
        typeof(PagedIndicatorsResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status400BadRequest)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<PagedIndicatorsResponse>>
        GetIndicators(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery(Name = "type")]
            string? indicatorType = null,
            [FromQuery(Name = "search")]
            string? search = null,
            CancellationToken cancellationToken = default)
    {
        if (page < 1)
        {
            return BadRequest(new
            {
                Error = "Page must be greater than zero."
            });
        }

        if (pageSize < 1 || pageSize > 100)
        {
            return BadRequest(new
            {
                Error = "Page size must be between 1 and 100."
            });
        }

        if (indicatorType?.Length > 64)
        {
            return BadRequest(new
            {
                Error = "Indicator type is too long."
            });
        }

        if (search?.Length > MaxSearchLength)
        {
            return BadRequest(new
            {
                Error =
                    "Search must not exceed 256 characters."
            });
        }

        try
        {
            var result = await _service.GetIndicatorsAsync(
                page,
                pageSize,
                indicatorType,
                search,
                cancellationToken);

            return Ok(result);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (NpgsqlException ex)
        {
            _logger.LogError(
                ex,
                "PostgreSQL indicator list retrieval failed.");

            return DatabaseUnavailable();
        }
    }

    [HttpGet("{id:long}")]
    [ProducesResponseType(
        typeof(IndicatorDetailResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status400BadRequest)]
    [ProducesResponseType(
        StatusCodes.Status404NotFound)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<IndicatorDetailResponse>>
        GetIndicatorById(
            [FromRoute] long id,
            CancellationToken cancellationToken = default)
    {
        if (id < 1)
        {
            return BadRequest(new
            {
                Error = "Indicator ID must be greater than zero."
            });
        }

        try
        {
            var result = await _service.GetIndicatorByIdAsync(
                id,
                cancellationToken);

            if (result is null)
            {
                return NotFound(new
                {
                    Error = "Indicator not found."
                });
            }

            return Ok(result);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (NpgsqlException ex)
        {
            _logger.LogError(
                ex,
                "PostgreSQL indicator detail retrieval failed.");

            return DatabaseUnavailable();
        }
    }

    private ObjectResult DatabaseUnavailable()
    {
        return StatusCode(
            StatusCodes.Status503ServiceUnavailable,
            new
            {
                Status = "unavailable",
                Message =
                    "Indicator data is temporarily unavailable."
            });
    }
}
