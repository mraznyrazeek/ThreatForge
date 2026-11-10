# ThreatForge — M7.3 Threat Indicator Retrieval, Filtering and Pagination

**Milestone:** M7 — ASP.NET Core REST API  
**Phase:** M7.3 — Threat Indicator Retrieval, Filtering and Pagination  
**Validation date:** 10 November 2026  
**Framework:** ASP.NET Core 10 / Npgsql 10.0.3  
**Status:** Functionally validated

## 1. Objective

Implement a database-backed HTTP endpoint for retrieving canonical threat indicators with server-side pagination and optional IOC-type filtering.

The endpoint is designed to support future ThreatForge frontend tables while restricting output to non-sensitive indicator metadata.

## 2. API Endpoint

**GET `/api/v1/intelligence/indicators`**

### Query Parameters

| Parameter | Type | Default | Validation |
|---|---|---|---|
| `page` | Integer | 1 | Must be greater than zero |
| `pageSize` | Integer | 20 | Between 1 and 100 |
| `type` | String | None | Optional exact-match indicator type; maximum 64 characters |

Examples:

```text
GET /api/v1/intelligence/indicators
GET /api/v1/intelligence/indicators?page=2&pageSize=5
GET /api/v1/intelligence/indicators?type=sha256_hash&page=1&pageSize=5
```

Free-text IOC-value searching is not implemented in this phase.

## 3. Response Structure

Each returned indicator includes:

- `id` — Canonical indicator ID
- `indicatorType` — IOC classification
- `createdAtUtc` — UTC creation timestamp

Pagination metadata includes:

- `page`
- `pageSize`
- `totalItems`
- `totalPages`
- `hasNextPage`
- `hasPreviousPage`

Raw indicator values and SHA-256 value digests are excluded from the current API response.

## 4. Architecture

The implementation follows a controller → service → PostgreSQL architecture.

**Implementation files:**

- `Controllers/ThreatIndicatorsController.cs`
- `Models/PagedIndicatorsResponse.cs`
- `Services/IThreatIndicatorService.cs`
- `Services/ThreatIndicatorService.cs`

The service is registered using ASP.NET Core dependency injection and accesses PostgreSQL through Npgsql.

## 5. Database Access and Security

The service queries the existing `public.threat_indicators` table.

Database operations use a repeatable-read transaction configured as read-only.

Pagination is ordered by the canonical indicator ID to provide deterministic ordering within a request.

Optional indicator-type filtering uses a bound SQL parameter rather than inserting user input into SQL text.

The API limits the page size to 100 records.

The existing primary-key index supports ID-ordered retrieval. The `(indicator_type, value_sha256)` unique index supports canonical identity constraints, but is not specifically optimized for filtering by indicator type followed by ordering by ID. Query performance should be measured as data volume grows.

Offset pagination is suitable for this initial implementation. Keyset pagination may be preferable for large datasets and deep pagination.

## 6. Live PostgreSQL Validation

The development database returned the following results:

| Test | Observed result |
|---|---|
| Default page, size 5 | HTTP 200 |
| Total canonical indicators | 11,370 |
| Total pages, size 5 | 2,274 |
| SHA-256 filter | 4,303 matching indicators |
| SHA-256 pages, size 5 | 861 |
| Second page | Next five indicator IDs |
| Page size 500 | HTTP 400 |

The results match previously verified Python analytics counts.

## 7. Automated Testing

The ASP.NET Core solution compiled successfully.

Nine M7.3 integration tests passed, covering successful retrieval, pagination metadata, query-parameter forwarding, invalid pagination values, excessive type length, empty results, and second-page metadata.

**Complete .NET test suite: 18 passed, 0 failed, 0 skipped.**

The integration tests use a synthetic service implementation and do not access the live PostgreSQL database.

## 8. Limitations

- Free-text search by IOC value is not yet available.
- Authentication and authorization have not yet been implemented.
- Offset pagination can become inefficient for large page numbers.
- Different requests may observe different database snapshots if ingestion occurs between requests.
- Database query-performance benchmarks are not yet available.
- Dedicated repository-level SQL integration tests and database failure tests remain future work.

## 9. Next Phase

**M7.4 — Analytics Endpoints and API Security**

Expose validated threat-intelligence analytics to API consumers using structured response contracts, bounded request parameters, and appropriate security controls.

Retain Python as the data-engineering and advanced analytics layer while keeping ASP.NET Core responsible for the HTTP interface.