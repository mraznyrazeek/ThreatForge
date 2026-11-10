
using System.Data;
using Npgsql;
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public sealed class IntelligenceSummaryService
    : IIntelligenceSummaryService
{
    private readonly NpgsqlDataSource _dataSource;

    public IntelligenceSummaryService(
        NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task<IntelligenceSummaryResponse> GetSummaryAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _dataSource.OpenConnectionAsync(
                cancellationToken);

        // Ensure all summary values are retrieved
        // from a consistent PostgreSQL snapshot.
        await using var transaction =
            await connection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead,
                cancellationToken);

        // Enforce read-only access for this transaction.
        await using (var readOnlyCommand =
            new NpgsqlCommand(
                "SET TRANSACTION READ ONLY",
                connection,
                transaction))
        {
            await readOnlyCommand.ExecuteNonQueryAsync(
                cancellationToken);
        }

        const string sql = """
            SELECT
                (
                    SELECT COUNT(*)
                    FROM public.threat_indicators
                ) AS canonical_indicators,

                (
                    SELECT COUNT(*)
                    FROM public.indicator_observations
                ) AS source_observations,

                (
                    SELECT COUNT(*)
                    FROM public.intelligence_sources
                ) AS intelligence_sources;
            """;

        await using var command = new NpgsqlCommand(
            sql,
            connection,
            transaction);

        await using var reader =
            await command.ExecuteReaderAsync(
                cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException(
                "Intelligence summary query returned no data.");
        }

        var response = new IntelligenceSummaryResponse
        {
            CanonicalIndicators = reader.GetInt64(0),
            SourceObservations = reader.GetInt64(1),
            IntelligenceSources = reader.GetInt64(2),
            GeneratedAtUtc = DateTimeOffset.UtcNow
        };

        await reader.DisposeAsync();

        await transaction.CommitAsync(
            cancellationToken);

        return response;
    }
}
