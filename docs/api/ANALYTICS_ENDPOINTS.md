# ThreatForge — Analytics API Endpoints

## Milestone

M7.4 — PostgreSQL-Backed Analytics API

## Overview

ThreatForge exposes analytical intelligence through an ASP.NET Core
Web API backed by PostgreSQL.

The API provides aggregated intelligence and does not intentionally
expose raw malicious indicator values through these endpoints.

## Analytics Endpoints

### 1. Indicator Type Distribution

GET /api/v1/analytics/indicators/distribution

Provides a distribution of canonical threat indicators by IOC type.

### 2. Malware Family Distribution

GET /api/v1/analytics/malware/families?limit=5

Provides malware-family distribution analytics.

The limit parameter is validated, with a maximum supported value
of 100.

### 3. Daily Threat Activity

GET /api/v1/analytics/temporal/daily

Provides daily activity derived from stored intelligence
observations.

Reported activity should not be interpreted as the total number
of real-world attacks or infections.

### 4. Cross-Source Correlation

GET /api/v1/analytics/correlation/sources

Provides correlation statistics across intelligence sources,
based on canonical indicator relationships.

## Architecture

The ASP.NET Core implementation uses:

- API controllers for HTTP request handling
- Response models for structured output
- Service interfaces for dependency injection
- Npgsql services for PostgreSQL queries
- PostgreSQL as the authoritative data store

Service registrations are maintained in:

backend/ThreatForge.Api/Program.cs

## Database Access Security

The API uses a dedicated PostgreSQL role:

threatforge_api_reader

The role has:

- CONNECT permission on threatforge_db
- USAGE permission on the public schema
- SELECT permission on:
  - public.threat_indicators
  - public.indicator_observations
  - public.intelligence_sources

INSERT, UPDATE, and DELETE permissions were verified as unavailable
on these three tables.

The Python ingestion pipeline continues using its existing
threatforge_app role.

Database credentials are stored outside source control using
ASP.NET Core User Secrets in the local development environment.

## Validation

Verified during M7.4:

- Eight of eight HTTP endpoints returned HTTP 200.
- Forty-five .NET automated tests passed.
- ASP.NET Core database health returned HTTP 200.
- PostgreSQL activity inspection confirmed that ThreatForge.Api
  connected as threatforge_api_reader.
- SELECT was permitted and INSERT, UPDATE, and DELETE were denied
  on all three required intelligence tables.

## Security Limitations

Database read-only permissions protect against writes through
the configured API database role. They do not replace HTTP-level
authentication or authorization.

Before production deployment, the application requires an
appropriate authentication and authorization strategy, secure
production secrets management, and further security testing.

## Interpretation Limitations

Threat intelligence analytics represent records and observations
received from configured sources. They must not be interpreted
as a complete measurement of worldwide cybersecurity activity.
