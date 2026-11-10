
using Microsoft.AspNetCore.Mvc;
using Npgsql;

namespace ThreatForge.Api.Controllers;

[ApiController]
[Route("api/v1/health/database")]
public sealed class DatabaseHealthController : ControllerBase
{
    private readonly NpgsqlDataSource _dataSource;

    public DatabaseHealthController(
        NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(
        StatusCodes.Status503ServiceUnavailable
    )]
    public async Task<IActionResult> GetDatabaseHealth(
        CancellationToken cancellationToken)
    {
        try
        {
            await using var command = _dataSource.CreateCommand(
                "SELECT current_database()"
            );

            var actualDatabase = await command.ExecuteScalarAsync(
                cancellationToken
            );

            if (actualDatabase is not string databaseName ||
                databaseName != "threatforge_db")
            {
                return DatabaseUnavailable();
            }

            return Ok(new
            {
                Status = "healthy",
                Service = "ThreatForge.Database",
                Database = "threatforge_db",
                TimestampUtc = DateTimeOffset.UtcNow
            });
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Do not return credentials, connection
            // strings, or PostgreSQL exception details.
            return DatabaseUnavailable();
        }
    }

    private IActionResult DatabaseUnavailable()
    {
        return StatusCode(
            StatusCodes.Status503ServiceUnavailable,
            new
            {
                Status = "unavailable",
                Service = "ThreatForge.Database"
            }
        );
    }
}
