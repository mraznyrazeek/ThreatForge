
using System.Data;
using Npgsql;
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public sealed class DailyThreatActivityService
    : IDailyThreatActivityService
{
    private readonly NpgsqlDataSource _dataSource;

    public DailyThreatActivityService(
        NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task<DailyThreatActivityResponse>
        GetDailyActivityAsync(
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

        const string sql = """
            SELECT
                (o.first_seen AT TIME ZONE 'UTC')::date
                    AS first_seen_date,
                s.name AS source_name,
                COUNT(*) AS observation_count,
                COUNT(DISTINCT o.indicator_id)
                    AS distinct_indicator_count
            FROM public.indicator_observations AS o
            INNER JOIN public.intelligence_sources AS s
                ON s.id = o.source_id
            GROUP BY
                (o.first_seen AT TIME ZONE 'UTC')::date,
                s.name
            ORDER BY
                first_seen_date ASC,
                source_name ASC;
            """;

        var activity = new List<DailyThreatActivityItem>();

        await using (var command = new NpgsqlCommand(
            sql,
            connection,
            transaction))
        {
            await using var reader =
                await command.ExecuteReaderAsync(
                    cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                activity.Add(new DailyThreatActivityItem
                {
                    DateUtc = reader.GetFieldValue<DateOnly>(0),
                    SourceName = reader.GetString(1),
                    ObservationCount = reader.GetInt64(2),
                    DistinctIndicatorCount = reader.GetInt64(3)
                });
            }
        }

        long totalObservations = activity.Sum(
            item => item.ObservationCount);

        await transaction.CommitAsync(cancellationToken);

        return new DailyThreatActivityResponse
        {
            Timezone = "UTC",
            TotalObservations = totalObservations,
            DailyActivity = activity,
            GeneratedAtUtc = DateTimeOffset.UtcNow
        };
    }
}
