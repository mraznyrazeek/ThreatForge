
using System.Data;
using Npgsql;
using NpgsqlTypes;
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public sealed class ThreatIndicatorService
    : IThreatIndicatorService
{
    private readonly NpgsqlDataSource _dataSource;

    public ThreatIndicatorService(
        NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task<PagedIndicatorsResponse> GetIndicatorsAsync(
        int page,
        int pageSize,
        string? indicatorType,
        CancellationToken cancellationToken = default)
    {
        if (page < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(page));
        }

        if (pageSize < 1 || pageSize > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize));
        }

        if (indicatorType?.Length > 64)
        {
            throw new ArgumentException(
                "Indicator type exceeds the allowed length.",
                nameof(indicatorType));
        }

        var normalizedType = string.IsNullOrWhiteSpace(
            indicatorType)
            ? null
            : indicatorType.Trim();

        long offset = ((long)page - 1) * pageSize;

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

        // Build SQL only from fixed application strings.
        // The filter value is always parameterized.
        var whereClause = normalizedType is null
            ? ""
            : "WHERE indicator_type = @indicator_type";

        var countSql = $"""
            SELECT COUNT(*)
            FROM public.threat_indicators
            {whereClause};
            """;

        long totalItems;

        await using (var countCommand =
            new NpgsqlCommand(
                countSql,
                connection,
                transaction))
        {
            AddTypeParameter(countCommand, normalizedType);

            totalItems = (long)(
                await countCommand.ExecuteScalarAsync(
                    cancellationToken)
                ?? 0L);
        }

        var querySql = $"""
            SELECT
                id,
                indicator_type,
                created_at
            FROM public.threat_indicators
            {whereClause}
            ORDER BY id ASC
            LIMIT @page_size
            OFFSET @offset;
            """;

        var items = new List<IndicatorListItem>();

        await using (var command =
            new NpgsqlCommand(
                querySql,
                connection,
                transaction))
        {
            AddTypeParameter(command, normalizedType);

            command.Parameters.Add(
                "page_size",
                NpgsqlDbType.Integer
            ).Value = pageSize;

            command.Parameters.Add(
                "offset",
                NpgsqlDbType.Bigint
            ).Value = offset;

            await using var reader =
                await command.ExecuteReaderAsync(
                    cancellationToken);

            while (await reader.ReadAsync(
                cancellationToken))
            {
                var createdAt = reader.GetDateTime(2);

                items.Add(new IndicatorListItem
                {
                    Id = reader.GetInt64(0),
                    IndicatorType = reader.GetString(1),
                    CreatedAtUtc = new DateTimeOffset(
                        createdAt.ToUniversalTime())
                });
            }
        }

        await transaction.CommitAsync(
            cancellationToken);

        long totalPages =
            totalItems / pageSize +
            (totalItems % pageSize == 0 ? 0 : 1);

        return new PagedIndicatorsResponse
        {
            Items = items,
            Page = page,
            PageSize = pageSize,
            TotalItems = totalItems,
            TotalPages = totalPages,
            HasNextPage = page < totalPages,
            HasPreviousPage = page > 1
        };
    }

    private static void AddTypeParameter(
        NpgsqlCommand command,
        string? indicatorType)
    {
        if (indicatorType is null)
        {
            return;
        }

        command.Parameters.Add(
            "indicator_type",
            NpgsqlDbType.Varchar
        ).Value = indicatorType;
    }
}
