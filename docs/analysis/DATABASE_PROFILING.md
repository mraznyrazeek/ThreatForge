# ThreatForge — M6.1 Database Profiling Report

**Milestone:** M6 — Threat Intelligence Analytics  
**Phase:** M6.1 — Database Exploration and Data Quality  
**Database:** PostgreSQL (`threatforge_db`)  
**Assessment date:** 10 November 2026  
**Status:** Validated

## 1. Objective

Evaluate the structure, completeness, consistency, source coverage, and temporal limitations of ThreatForge's stored threat-intelligence data before developing the analytics engine.

All profiling operations were read-only.

## 2. Database Inventory

| Table | Records |
|---|---:|
| intelligence_sources | 2 |
| threat_indicators | 11,370 |
| indicator_observations | 11,376 |
| observation_history | 8 |
| ingestion_runs | 31 |
| rejected_records | 4 |

## 3. Intelligence Source Coverage

| Source | Observations | Distinct indicators |
|---|---:|---:|
| ThreatFox | 10,376 | 10,372 |
| URLhaus | 1,000 | 1,000 |
| Total | 11,376 | 11,370 globally |

Two canonical indicators occur in both intelligence sources.

Four source-indicator combinations have multiple observations, producing four additional same-source observations.

## 4. Data Completeness

| Quality measure | Count |
|---|---:|
| Missing malware family | 1,000 |
| Missing last_seen | 9,163 |
| Missing reporter | 0 |
| Missing reference | 7,522 |
| Confidence value of zero | 1,000 |
| Positive confidence value | 10,376 |
| Reversed timestamp intervals | 36 |

URLhaus currently uses confidence level `0` as a placeholder for **unrated intelligence**, rather than an assessment of zero maliciousness.

Missing fields should not automatically be classified as collection errors. They may reflect differences in provider schemas.

## 5. Temporal Coverage

**ThreatFox**
- Earliest `first_seen`: 2 November 2026
- Latest `first_seen`: 9 November 2026
- Timestamp quality: 2,177 consistent; 8,163 missing `last_seen`; 36 reversed intervals

**URLhaus**
- Earliest `first_seen`: 8 November 2026
- Latest `first_seen`: 9 November 2026
- All 1,000 observations lack `last_seen`

Dates are summarized at calendar-day precision. Database-returned timestamps were timezone-aware.

The dataset reflects recent provider intelligence rather than comprehensive historical or worldwide cyberattack activity.

## 6. Integrity and Rejection Handling

- Missing indicator relationships: 0
- Missing source relationships: 0
- Recorded rejections: 4
- Rejection reason: `validation_failed`
- Ingestion run #29 rejection counters reconcile with stored rejection records

The four rejected records require a separate field-level validation investigation. Their specific failed constraints have not yet been identified.

## 7. Analytical Implications

- Treat source observations and canonical indicators as different measures.
- Account for repeated source observations when calculating distributions.
- Do not calculate activity durations from missing or reversed timestamp intervals.
- Do not compare URLhaus placeholder confidence values directly with ThreatFox confidence ratings.
- Clearly distinguish source feed prevalence from global threat prevalence.
- Use UTC-normalized dates for consistent temporal aggregation.
- Label incomplete historical coverage when interpreting trends.

## 8. Validation

- Live read-only PostgreSQL profiling completed successfully.
- Nine M6.1 profiling tests passed.
- Entire project test suite: **196 passed, 0 failed**.

## 9. Next Development Phase

**M6.2 — Indicator Distribution and Malware Analysis**

Develop read-only analytics for indicator types, malware families, threat classifications, source comparisons, and dashboard-ready aggregation results.