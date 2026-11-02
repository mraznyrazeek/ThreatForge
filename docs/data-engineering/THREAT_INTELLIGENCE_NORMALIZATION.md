
# ThreatForge — Threat Intelligence Normalization

**Milestone:** M2 — Threat Intelligence Integration
**Status:** Validated Prototype
**Date:** November 2, 2026

## 1. Purpose

Define a consistent internal representation of cybersecurity
threat indicators collected from external intelligence providers.

The normalization layer separates canonical indicator identity
from individual source observations.

## 2. Current Implementation

Models:
- ThreatIndicator
- SourceObservation
- IndicatorType
- TimestampQuality

Source adapter:
- normalize_threatfox.py

Validation:
- Pydantic V2 models
- pytest automated tests

## 3. Supported Indicator Types

- Domain
- URL
- IPv4:port
- Bracketed IPv6:port
- MD5 hash
- SHA-1 hash
- SHA-256 hash

Indicator formats are validated before being accepted.

Domains and file hashes receive basic case normalization.

Advanced URL canonicalization and internationalized-domain
normalization are not yet implemented.

## 4. Identity Model

Canonical indicator identity:

    (indicator_type, normalized_value)

Source observation identity:

    (source_name, source_record_id)

Multiple observations may reference the same indicator.

Source IDs must not be treated as universal indicator IDs.

## 5. Timestamp Quality Policy

ThreatForge preserves original source timestamps.

Three classifications are defined:

### Consistent

last_seen is present and is greater than or equal to first_seen.

### Missing Last Seen

last_seen is null.

The record remains valid without inventing a timestamp.

### Reversed Interval

last_seen precedes first_seen.

Source timestamps are preserved and the interval is flagged.

Reversed timestamps are rejected by default. The ThreatFox
adapter explicitly permits them for quality-aware processing.

## 6. Observed ThreatFox Timestamp Issues

A diagnostic API response contained:

- Total records: 2,256
- Missing first_seen: 0
- Missing last_seen: 1,885
- Invalid timestamp formats: 0
- Reversed intervals: 10

Reversed interval differences:

- Less than 1 minute: 6
- 1 minute to 1 hour: 3
- 1 hour to 1 day: 1

Maximum reversed interval: 36,578 seconds.

These are source-data anomalies, not confirmed provider defects.

## 7. Live Normalization Validation

A subsequent ThreatFox API response contained:

- Records received: 2,245
- Successfully normalized: 2,245
- Validation failures: 0
- Normalization success rate: 100.00%

Timestamp quality distribution:

- Missing last_seen: 1,874
- Consistent: 361
- Reversed interval: 10

All ten reversed intervals were accepted with their original
timestamps preserved and quality classifications available.

This result applies only to the tested API response.

## 8. Automated Testing

Full test suite executed:

    python -m pytest data-engineering/tests/ -v

Results:

- 59 tests passed
- 0 tests failed
- Execution time: 0.09 seconds

Testing covers:

- Indicator validation and normalization
- Confidence score boundaries
- Timestamp validation
- Source identity
- Reversed timestamp preservation
- Batch normalization
- Invalid record handling
- Duplicate canonical indicator identity

All adapter test fixtures are synthetic.

## 9. Known Limitations

- No PostgreSQL persistence yet.
- No permanent rejected-record storage.
- No historical ingestion tracking.
- No multi-source correlation.
- No ingestion timestamp in the observation model.
- Timestamp quality is not yet automatically serialized.
- Validation covers selected indicator formats and scenarios.
- Tests do not establish production readiness.

## 10. Next Engineering Priorities

1. Define explicit persistence serialization contracts.
2. Add ingestion metadata and source provenance.
3. Preserve rejected records for controlled reprocessing.
4. Design PostgreSQL tables and constraints.
5. Implement idempotent persistence.
6. Add database integration tests.

## Conclusion

ThreatForge now has validated foundational models and a working
ThreatFox normalization adapter.

The prototype preserves reported timestamp anomalies without
silently correcting source data.

The next stage will establish reliable persistence and
historical intelligence tracking.
