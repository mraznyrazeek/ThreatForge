# ThreatForge — M7.1 ASP.NET Core API Foundation

**Milestone:** M7 — Backend REST API  
**Phase:** M7.1 — API Foundation  
**Date:** 10 November 2026  
**Framework:** ASP.NET Core / .NET 10  
**Status:** Validated

## 1. Objective

Establish a working ASP.NET Core Web API foundation for ThreatForge, using C# and a controller-based application architecture.

The backend will eventually expose PostgreSQL-backed threat intelligence, aggregated analytics, search, and filtering functionality.

## 2. Project Structure

- `ThreatForge.sln` — .NET solution
- `backend/ThreatForge.Api/` — ASP.NET Core Web API
- `backend/ThreatForge.Api/Controllers/` — HTTP controllers
- `backend/ThreatForge.Api.Tests/` — xUnit integration tests

The API operates independently from the Python data-engineering environment.

## 3. Implemented Endpoint

### GET /api/v1/health

Returns HTTP 200 with JSON containing:

- `status`: `healthy`
- `service`: `ThreatForge.Api`
- `version`: `1.0`
- `timestampUtc`: Current UTC timestamp

This endpoint verifies application liveness and routing. It does not currently test database connectivity.

## 4. Technology

- C# and .NET 10
- ASP.NET Core Web API
- Controller-based routing
- Kestrel HTTP server
- Built-in dependency injection
- OpenAPI support for development
- xUnit
- Microsoft.AspNetCore.Mvc.Testing

## 5. Validation

The solution compiled successfully using `dotnet build ThreatForge.sln`.

The live health endpoint returned HTTP 200 and the expected JSON response.

Five automated integration tests passed, verifying:

1. HTTP 200 response
2. Service metadata
3. UTC timestamp
4. HTTP 404 for an unknown endpoint
5. JSON response content type

**Test result: 5 passed, 0 failed, 0 skipped.**

## 6. Scope and Limitations

- The backend currently exposes application health only.
- PostgreSQL integration has not yet been implemented.
- The health endpoint is a liveness check, not a readiness check.
- Authentication and authorization are not yet implemented.
- Local development uses HTTP; production deployment will require HTTPS.
- No threat-indicator records are exposed by this milestone.

## 7. Next Phase

**M7.2 — PostgreSQL Connectivity and Intelligence Summary**

Introduce Npgsql, typed configuration, database services, and a read-only endpoint that retrieves real intelligence summary metrics from the existing PostgreSQL database.

The backend must not duplicate or interfere with the Python ingestion pipeline.