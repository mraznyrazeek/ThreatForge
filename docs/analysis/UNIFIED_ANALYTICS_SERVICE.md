# ThreatForge — M6.4 Unified Intelligence Analytics Service

**Milestone:** M6 — Threat Intelligence Analytics  
**Phase:** M6.4 — Dashboard-Ready Analytics  
**Assessment date:** 10 November 2026  
**Status:** Validated  
**Database:** PostgreSQL (`threatforge_db`)

## 1. Objective

Provide a reusable, read-only Python analytics service that combines database profiling, indicator distribution, malware-family analysis, temporal activity, and cross-source correlation into one structured JSON-compatible response.

The service is intended to support future ThreatForge REST API endpoints and dashboard components.

## 2. Implementation

**Main module:** `data-engineering/src/processing/intelligence_analytics_service.py`

The service reuses existing analytics functions from:

- `profile_intelligence_database.py`
- `analyze_indicator_distribution.py`
- `analyze_temporal_intelligence.py`

This avoids duplicating SQL queries and maintains consistency across analytics components.

## 3. Analytics Response Structure

The service returns the following top-level sections:

| Section | Contents |
|---|---|
| `schema_version` | Analytics response contract version |
| `dataset` | Canonical indicator, observation, and source counts |
| `sources` | Source-level observation totals |
| `indicators` | Global and source-specific IOC distributions |
| `threats` | Threat classifications, malware rankings, metadata coverage |
| `temporal` | Daily first-seen counts, timestamp quality, observation intervals |
| `correlation` | Cross-source overlap and repeated source indicators |
| `data_quality` | Completeness and referential-integrity measurements |
| `interpretation` | Context and analytical limitations |

## 4. Verified Dataset

The live PostgreSQL validation produced:

| Metric | Value |
|---|---:|
| Canonical indicators | 11,370 |
| Source observations | 11,376 |
| Intelligence sources | 2 |
| Indicator categories | 6 |
| Top malware-family labels returned | 15 |
| Daily source/date records | 10 |
| Shared canonical indicators | 2 |
| Missing indicator relationships | 0 |

These values represent a verified snapshot of the development database and are not hardcoded into the service.

## 5. Database Consistency and Safety

The service uses a PostgreSQL transaction configured with `REPEATABLE READ` isolation and `READ ONLY` access.

This allows its multiple aggregation queries to operate against a consistent database snapshot during a request, including when other processes may be ingesting new intelligence.

Additional safeguards include:

- Validation of the selected development database.
- Bounded malware-family ranking limits.
- Reconciliation of aggregate counts.
- Detection of broken source and indicator relationships.
- Sanitized error reporting.
- No raw indicator values in the designed analytics response.
- No modification of stored threat-intelligence records.

## 6. JSON Compatibility

The service converts Python dates and timestamps to ISO-8601 strings and Decimal values to JSON numbers.

The output can be consumed by applications without parsing terminal reports.

The current response format uses schema version `1.0`. Changes to response fields or semantics should be reviewed for downstream compatibility.

## 7. Usage

Run from `data-engineering`:

```bash
DB_NAME=threatforge_db \
python src/processing/intelligence_analytics_service.py \
  --top-families 15
```

For a local JSON file:

```bash
DB_NAME=threatforge_db \
python src/processing/intelligence_analytics_service.py \
  --top-families 