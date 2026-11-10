# ThreatForge — M6.3 Temporal Intelligence and Cross-Source Correlation

**Milestone:** M6 — Threat Intelligence Analytics  
**Phase:** M6.3 — Temporal Analysis and Cross-Source Correlation  
**Assessment date:** 10 November 2026  
**Database:** PostgreSQL (`threatforge_db`)  
**Status:** Validated

## 1. Objective

Analyze the temporal distribution of threat-intelligence observations, assess timestamp reliability, measure valid first-to-last observation intervals, and identify indicators reported by multiple intelligence sources.

All analytics were performed using read-only PostgreSQL queries.

## 2. Dataset Overview

| Metric | Count |
|---|---:|
| Canonical indicators | 11,370 |
| Source observations | 11,376 |
| ThreatFox observations | 10,376 |
| URLhaus observations | 1,000 |
| Intelligence sources | 2 |

The dataset reflects recently collected provider intelligence and does not represent all cybersecurity incidents worldwide.

## 3. Daily First-Seen Observations (UTC)

| Date | ThreatFox | URLhaus | Combined |
|---|---:|---:|---:|
| 2026-11-02 | 740 | 0 | 740 |
| 2026-11-03 | 1,590 | 0 | 1,590 |
| 2026-11-04 | 1,232 | 0 | 1,232 |
| 2026-11-05 | 1,506 | 0 | 1,506 |
| 2026-11-06 | 1,754 | 0 | 1,754 |
| 2026-11-07 | 1,262 | 0 | 1,262 |
| 2026-11-08 | 1,286 | 179 | 1,465 |
| 2026-11-09 | 1,006 | 821 | 1,827 |
| **Total** | **10,376** | **1,000** | **11,376** |

ThreatFox's highest daily count occurred on 6 November 2026, with 1,754 observations.

The highest combined count occurred on 9 November, with 1,827 observations. This is influenced by differing source coverage and must not be interpreted as evidence of a worldwide increase in attacks.

Zero URLhaus observations before 8 November indicate no records for those dates in our collected dataset, rather than proof of no malicious activity.

## 4. Timestamp Quality

| Source | Consistent intervals | Missing last_seen | Reversed intervals |
|---|---:|---:|---:|
| ThreatFox | 2,177 | 8,163 | 36 |
| URLhaus | 0 | 1,000 | 0 |
| **Total** | **2,177** | **9,163** | **36** |

Most observations lack `last_seen`, limiting the use of duration-based analysis.

The 36 reversed intervals were excluded from valid interval calculations.

## 5. Observation Interval Analysis

For the 2,177 ThreatFox records where `last_seen` was present and not earlier than `first_seen`, the mean reported observation interval was **30.09 hours**.

URLhaus had no valid intervals because all 1,000 observations lacked `last_seen`.

This interval measures the difference between reported first and last observation timestamps. It must not be interpreted as attack duration, malware execution time, or confirmed indicator lifetime.

## 6. Cross-Source Correlation

Two canonical indicators were observed in both ThreatFox and URLhaus.

This demonstrates cross-source overlap based on the shared canonical indicator identity.

The presence of the same indicator in two feeds does not by itself establish independent verification of all associated threat classifications.

## 7. Repeated Indicators Within Sources

ThreatFox contained four repeated source-indicator groups, accounting for four additional observations.

These are multiple source observations referring to the same canonical indicator. They are distinct from accidental duplicate ingestion of the same source record.

## 8. Interpretation and Limitations

- All daily analyses use UTC calendar dates.
- First-seen observations are not equivalent to real-world attacks.
- The short collection window does not support reliable long-term threat