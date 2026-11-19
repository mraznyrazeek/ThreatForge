
using System.Data;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using ThreatForge.Api.Models;

namespace ThreatForge.Api.Services;

public sealed class ThreatIndicatorService
    : IThreatIndicatorService
{
    private const int MaxDetailObservations = 100;
    private const int MaxSearchLength = 256;

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
        string? search,
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

        if (search?.Length > MaxSearchLength)
        {
            throw new ArgumentException(
                "Search exceeds the allowed length.",
                nameof(search));
        }

        var normalizedType = string.IsNullOrWhiteSpace(
            indicatorType)
            ? null
            : indicatorType.Trim();

        var normalizedSearch = string.IsNullOrWhiteSpace(
            search)
            ? null
            : search.Trim();

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

        var conditions = new List<string>();

        if (normalizedType is not null)
        {
            conditions.Add(
                "i.indicator_type = @indicator_type");
        }

        if (normalizedSearch is not null)
        {
            conditions.Add(
                """
                strpos(
                    lower(i.normalized_value),
                    lower(@search)
                ) > 0
                """);
        }

        var whereClause = conditions.Count == 0
            ? ""
            : "WHERE " + string.Join(
                " AND ",
                conditions);

        var countSql = $"""
            SELECT COUNT(*)
            FROM public.threat_indicators AS i
            {whereClause};
            """;

        long totalItems;

        await using (var countCommand =
            new NpgsqlCommand(
                countSql,
                connection,
                transaction))
        {
            AddTypeParameter(
                countCommand,
                normalizedType);

            AddSearchParameter(
                countCommand,
                normalizedSearch);

            totalItems = (long)(
                await countCommand.ExecuteScalarAsync(
                    cancellationToken)
                ?? 0L);
        }

        var querySql = $"""
            WITH paged_indicators AS
            (
                SELECT
                    i.id,
                    i.indicator_type,
                    i.normalized_value,
                    i.created_at
                FROM public.threat_indicators AS i
                {whereClause}
                ORDER BY i.id ASC
                LIMIT @page_size
                OFFSET @offset
            )
            SELECT
                p.id,
                p.indicator_type,
                p.normalized_value,
                p.created_at,
                (
                    SELECT COUNT(*)
                    FROM public.indicator_observations AS o
                    WHERE o.indicator_id = p.id
                ) AS observation_count
            FROM paged_indicators AS p
            ORDER BY p.id ASC;
            """;

        var items = new List<IndicatorListItem>();

        await using (var command =
            new NpgsqlCommand(
                querySql,
                connection,
                transaction))
        {
            AddTypeParameter(
                command,
                normalizedType);

            AddSearchParameter(
                command,
                normalizedSearch);

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
                items.Add(new IndicatorListItem
                {
                    Id = reader.GetInt64(0),

                    IndicatorType = reader.GetString(1),

                    NormalizedValue = reader.GetString(2),

                    CreatedAtUtc = ToUtc(
                        reader.GetDateTime(3)),

                    ObservationCount = reader.GetInt64(4)
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

    public async Task<IndicatorDetailResponse?>
        GetIndicatorByIdAsync(
            long id,
            CancellationToken cancellationToken = default)
    {
        if (id < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(id));
        }

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

        const string indicatorSql = """
            SELECT
                i.id,
                i.indicator_type,
                i.normalized_value,
                i.created_at,
                (
                    SELECT COUNT(*)
                    FROM public.indicator_observations AS o
                    WHERE o.indicator_id = i.id
                ) AS observation_count
            FROM public.threat_indicators AS i
            WHERE i.id = @indicator_id;
            """;

        long indicatorId;
        string indicatorType;
        string normalizedValue;
        DateTimeOffset createdAtUtc;
        long observationCount;

        await using (var command =
            new NpgsqlCommand(
                indicatorSql,
                connection,
                transaction))
        {
            AddIndicatorIdParameter(command, id);

            await using var reader =
                await command.ExecuteReaderAsync(
                    cancellationToken);

            if (!await reader.ReadAsync(
                cancellationToken))
            {
                return null;
            }

            indicatorId = reader.GetInt64(0);
            indicatorType = reader.GetString(1);
            normalizedValue = reader.GetString(2);
            createdAtUtc = ToUtc(reader.GetDateTime(3));
            observationCount = reader.GetInt64(4);
        }

        const string observationSql = """
            SELECT
                o.id,
                o.source_id,
                s.name,
                o.source_record_id,
                o.threat_type,
                o.malware_family,
                o.confidence_level,
                o.first_seen,
                o.last_seen,
                o.timestamp_quality,
                o.reporter,
                o.reference,
                o.tags,
                o.updated_at
            FROM public.indicator_observations AS o
            INNER JOIN public.intelligence_sources AS s
                ON s.id = o.source_id
            WHERE o.indicator_id = @indicator_id
            ORDER BY o.id ASC
            LIMIT @observation_limit;
            """;

        var observations =
            new List<IndicatorObservationItem>();

        await using (var command =
            new NpgsqlCommand(
                observationSql,
                connection,
                transaction))
        {
            AddIndicatorIdParameter(command, id);

            command.Parameters.Add(
                "observation_limit",
                NpgsqlDbType.Integer
            ).Value = MaxDetailObservations + 1;

            await using var reader =
                await command.ExecuteReaderAsync(
                    cancellationToken);

            while (await reader.ReadAsync(
                cancellationToken))
            {
                var tagsJson = reader.GetString(12);

                var tags = JsonSerializer
                    .Deserialize<JsonElement>(tagsJson);

                observations.Add(
                    new IndicatorObservationItem
                    {
                        Id = reader.GetInt64(0),

                        SourceId = reader.GetInt64(1),

                        SourceName = reader.GetString(2),

                        SourceRecordId =
                            reader.GetString(3),

                        ThreatType = reader.GetString(4),

                        MalwareFamily = reader.IsDBNull(5)
                            ? null
                            : reader.GetString(5),

                        ConfidenceLevel =
                            reader.GetInt32(6),

                        FirstSeenUtc = ToUtc(
                            reader.GetDateTime(7)),

                        LastSeenUtc = reader.IsDBNull(8)
                            ? null
                            : ToUtc(reader.GetDateTime(8)),

                        TimestampQuality =
                            reader.GetString(9),

                        Reporter = reader.IsDBNull(10)
                            ? null
                            : reader.GetString(10),

                        Reference = reader.IsDBNull(11)
                            ? null
                            : reader.GetString(11),

                        Tags = tags,

                        UpdatedAtUtc = ToUtc(
                            reader.GetDateTime(13))
                    });
            }
        }

        await transaction.CommitAsync(
            cancellationToken);

        var hasMoreObservations =
            observations.Count > MaxDetailObservations;

        if (hasMoreObservations)
        {
            observations.RemoveAt(
                observations.Count - 1);
        }

        return new IndicatorDetailResponse
        {
            Id = indicatorId,
            IndicatorType = indicatorType,
            NormalizedValue = normalizedValue,
            CreatedAtUtc = createdAtUtc,
            ObservationCount = observationCount,
            HasMoreObservations = hasMoreObservations,
            Observations = observations
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

    private static void AddSearchParameter(
        NpgsqlCommand command,
        string? search)
    {
        if (search is null)
        {
            return;
        }

        command.Parameters.Add(
            "search",
            NpgsqlDbType.Text
        ).Value = search;
    }

    private static void AddIndicatorIdParameter(
        NpgsqlCommand command,
        long id)
    {
        command.Parameters.Add(
            "indicator_id",
            NpgsqlDbType.Bigint
        ).Value = id;
    }

    private static DateTimeOffset ToUtc(
        DateTime value)
    {
        return new DateTimeOffset(
            value.ToUniversalTime());
    }
}
