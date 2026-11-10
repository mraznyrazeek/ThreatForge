
using System.Data;
using Npgsql;
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public sealed class CrossSourceCorrelationService
    : ICrossSourceCorrelationService
{
    private readonly NpgsqlDataSource _dataSource;

    public CrossSourceCorrelationService(
        NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task<CrossSourceCorrelationResponse>
        GetCorrelationAsync(
            CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _dataSource.OpenConnectionAsync(
                cancellationToken);

        await using var transaction =
            await connection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead,
                cancellationToken);

        await using (var readOnlyCommand = new NpgsqlCommand(
            "SET TRANSACTION READ ONLY",
            connection,
            transaction))
        {
            await readOnlyCommand.ExecuteNonQueryAsync(
                cancellationToken);
        }

        // Count canonical indicators found in at least
        // two distinct intelligence sources.
        const string sharedCountSql = """
            SELECT COUNT(*)
            FROM (
                SELECT indicator_id
                FROM public.indicator_observations
                GROUP BY indicator_id
                HAVING COUNT(DISTINCT source_id) > 1
            ) AS shared;
            """;

        long sharedCanonicalIndicators;

        await using (var countCommand = new NpgsqlCommand(
            sharedCountSql,
            connection,
            transaction))
        {
            var count = await countCommand.ExecuteScalarAsync(
                cancellationToken);

            sharedCanonicalIndicators = Convert.ToInt64(count);
        }

        // Deduplicate observations within each source
        // before calculating overlaps between sources.
        const string overlapSql = """
            WITH distinct_source_indicators AS (
                SELECT DISTINCT
                    source_id,
                    indicator_id
                FROM public.indicator_observations
            )
            SELECT
                a.name AS first_source,
                b.name AS second_source,
                COUNT(*) AS shared_indicators
            FROM distinct_source_indicators x
            JOIN distinct_source_indicators y
                ON x.indicator_id = y.indicator_id
               AND x.source_id < y.source_id
            JOIN public.intelligence_sources a
                ON a.id = x.source_id
            JOIN public.intelligence_sources b
                ON b.id = y.source_id
            GROUP BY
                a.id,
                a.name,
                b.id,
                b.name
            ORDER BY
                shared_indicators DESC,
                first_source ASC,
                second_source ASC;
            """;

        var sourcePairs = new List<SourceOverlapItem>();

        await using (var command = new NpgsqlCommand(
            overlapSql,
            connection,
            transaction))
        {
            await using var reader =
                await command.ExecuteReaderAsync(
                    cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                sourcePairs.Add(new SourceOverlapItem
                {
                    FirstSource = reader.GetString(0),
                    SecondSource = reader.GetString(1),
                    SharedIndicators = reader.GetInt64(2)
                });
            }
        }

        await transaction.CommitAsync(cancellationToken);

        return new CrossSourceCorrelationResponse
        {
            SharedCanonicalIndicators =
                sharedCanonicalIndicators,

            SourcePairs = sourcePairs,

            GeneratedAtUtc = DateTimeOffset.UtcNow
        };
    }
}
