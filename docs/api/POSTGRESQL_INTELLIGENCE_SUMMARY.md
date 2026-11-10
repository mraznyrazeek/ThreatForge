# ThreatForge — M7.2 PostgreSQL Connectivity and Intelligence Summary

**Milestone:** M7 — ASP.NET Core REST API  
**Phase:** M7.2 — PostgreSQL Connectivity and Intelligence Summary  
**Validation date:** 10 November 2026  
**Status:** Validated

## 1. Objective

Connect the ASP.NET Core 10 backend to ThreatForge's existing PostgreSQL database and expose read-only intelligence summary metrics through HTTP.

The API reuses the database populated by the Python data-engineering pipeline, without changing its ingestion or persistence logic.

## 2. Technology

- C# / ASP.NET Core 10
- Npgsql 10.0.3
- PostgreSQL (`threatforge_db`)
- ASP.NET Core dependency injection
- ASP.NET Core User Secrets for local development credentials
- xUnit and WebApplicationFactory for integration testing

## 3. Database Configuration

The application registers an `NpgsqlDataSource` using dependency injection.

Local credentials are loaded through ASP.NET Core User Secrets and are excluded from the Git repository.

The configuration checks that the target database is `threatforge_db`.

The connection pool is initialized through Npgsql and reused across database operations.

## 4. Implemented Endpoints

### GET /api/v1/health

Checks application liveness.

Returns HTTP 200 when the ASP.NET Core application is running.

### GET /api/v1/health/database

Checks PostgreSQL connectivity and verifies the active database name.

Returns HTTP 200 for a successful database connection and HTTP 503 when the controller detects database unavailability.

This is a database connectivity check rather than a comprehensive system-readiness assessment.

### GET /api/v1/intelligence/summary

Returns aggregated intelligence statistics from PostgreSQL:

| Response field | Description |
|---|---|
| `canonicalIndicators` | Count of canonical threat indicators |
| `sourceObservations` | Count of source observations |
| `intelligenceSources` | Count of registered intelligence sources |
| `generatedAtUtc` | UTC time of response generation |

The summary service runs within a PostgreSQL repeatable-read transaction with read-only access.

## 5. Live Database Verification

The intelligence summary endpoint returned:

| Metric | Value |
|---|---:|
| Canonical indicators | 11,370 |
| Source observations | 11,376 |
| Intelligence sources | 2 |

These values matched the latest validated Python analytics dataset.

The numbers are dynamic and may change after subsequent intelligence ingestion.

## 6. Automated Testing

Nine .NET integration tests passed.

Five existing tests validate application health, metadata, timestamps, routing, and JSON responses.

Four additional tests validate the intelligence summary endpoint using a synthetic service implementation.

**Results: 9 passed, 0 failed, 0 skipped.**

The automated tests do not require a running PostgreSQL database. The separate live HTTP request confirms actual PostgreSQL integration.

## 7. Security and Limitations

- Database credentials are not committed to Git.
- Database aggregation uses read-only SQL.
- API responses expose summary counts, not raw IOC values.
- Error responses should not expose PostgreSQL credentials or connection strings.
- Authentication and authorization are not yet implemented.
- Database health error handling and structured monitoring will be expanded in later milestones.
- Production deployments require appropriately restricted database permissions, HTTPS, and secure secret management.
- The Python analytics service remains the reference implementation for advanced analytics.

## 8. Next Milestone — M7.3

Implement threat-indicator search, filtering, and pagination using read-only PostgreSQL queries and validated HTTP request parameters.

The API will support exploring indicators without exposing database credentials or allowing arbitrary SQL execution.