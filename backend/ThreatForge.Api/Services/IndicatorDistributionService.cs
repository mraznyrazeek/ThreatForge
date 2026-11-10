
using System.Data;
using Npgsql;
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public sealed class IndicatorDistributionService
    : IIndicatorDistributionService
{
    private readonly NpgsqlDataSource _dataSource;

    public IndicatorDistributionService(
        NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task<IndicatorDistributionResponse>
        GetDistributionAsync(
            CancellationToken cancellationToken = default)
    {
        await using var connection =
            await _dataSource.OpenConnectionAsync(
                cancellationToken);

        await using var transaction =
            await connection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead,
                cancellationToken);

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
                indicator_type,
                COUNT(*) AS indicator_count
            FROM public.threat_indicators
            GROUP BY indicator_type
            ORDER BY indicator_count DESC, indicator_type ASC;
            """;

        var counts = new List<(string Type, long Count)>();

        await using (var command = new NpgsqlCommand(
            sql,
            connection,
            transaction))
        {
            await using var reader =
                await command.ExecuteReaderAsync(
                    cancellationToken);

            while (await reader.ReadAsync(
                cancellationToken))
            {
                counts.Add((
                    Type: reader.GetString(0),
                    Count: reader.GetInt64(1)
                ));
            }
        }

        await transaction.CommitAsync(
            cancellationToken);

        long total = counts.Sum(item => item.Count);

        var distribution = counts
            .Select(item => new IndicatorDistributionItem
            {
                IndicatorType = item.Type,
                Count = item.Count,
                Percentage = total == 0
                    ? 0m
                    : Math.Round(
                        (decimal)item.Count / total * 100m,
                        2,
                        MidpointRounding.AwayFromZero)
            })
            .ToList();

        return new IndicatorDistributionResponse
        {
            TotalIndicators = total,
            Distribution = distribution,
            GeneratedAtUtc = DateTimeOffset.UtcNow
        };
    }
}
