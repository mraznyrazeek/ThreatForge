# ThreatForge — M6.2 Indicator Distribution and Malware Analysis

**Milestone:** M6 — Threat Intelligence Analytics  
**Phase:** M6.2 — Indicator Distribution and Malware Analysis  
**Assessment date:** 10 November 2026  
**Database:** PostgreSQL (`threatforge_db`)  
**Status:** Validated

## 1. Objective

Analyze the composition of ThreatForge's collected threat-intelligence dataset, including canonical indicator types, source-specific observations, threat classifications, malware-family rankings, and metadata coverage.

All analytics were performed using read-only PostgreSQL queries.

## 2. Dataset Overview

| Metric | Count |
|---|---:|
| Canonical indicators | 11,370 |
| Source observations | 11,376 |
| Intelligence sources | 2 |

The dataset contains recent intelligence from ThreatFox and URLhaus. Results describe the collected feeds, not the global prevalence of malicious activity.

## 3. Global Indicator Distribution

| Indicator type | Canonical indicators | Share |
|---|---:|---:|
| SHA-256 hash | 4,303 | 37.85% |
| Domain | 2,319 | 20.40% |
| URL | 2,163 | 19.02% |
| IP:port | 1,367 | 12.02% |
| MD5 hash | 611 | 5.37% |
| SHA-1 hash | 607 | 5.34% |

SHA-256 hashes are the largest indicator category in the current dataset. These counts represent deduplicated canonical indicators.

## 4. Source-Level Indicator Distribution

ThreatFox contributes 10,376 observations covering six indicator types, while URLhaus contributes 1,000 URL observations.

ThreatFox observation counts:

| Indicator type | Observations |
|---|---:|
| SHA-256 hash | 4,303 |
| Domain | 2,322 |
| IP:port | 1,368 |
| URL | 1,165 |
| MD5 hash | 611 |
| SHA-1 hash | 607 |

URLhaus contributes 1,000 URL observations.

Two canonical indicators are shared across sources, and four additional observations result from repeated indicators within ThreatFox.

## 5. Threat-Type Distribution

| Source | Threat type | Observations |
|---|---|---:|
| ThreatFox | payload | 5,521 |
| ThreatFox | botnet_cc | 2,709 |
| ThreatFox | payload_delivery | 2,145 |
| ThreatFox | cc_skimming | 1 |
| URLhaus | malware_download | 1,000 |

These categories use normalized source classifications and should not automatically be treated as interchangeable across providers.

## 6. Most Frequently Reported Malware Families

Top 10 malware-family labels in the current observations:

| Rank | Malware-family label | Observations |
|---|---|---:|
| 1 | osx.amos | 1,615 |
| 2 | unknown_loader | 1,436 |
| 3 | win.vidar | 825 |
| 4 | elf.mirai | 741 |
| 5 | js.clearfake | 641 |
| 6 | unknown | 565 |
| 7 | win.vshell | 360 |
| 8 | js.iclickfix | 304 |
| 9 | win.warden_stealer | 277 |
| 10 | win.salatstealer | 227 |

Generic labels such as `unknown_loader` and `unknown` are not confirmed specific malware-family identifications.

## 7. Malware Metadata Coverage

| Source | Observations with malware-family labels | Coverage |
|---|---:|---:|
| ThreatFox | 10,376 | 100% |
| URLhaus | 0 | 0% |

The current URLhaus normalization does not populate malware-family metadata. This is a source/pipeline coverage limitation rather than evidence that these URLs have no malware association.

## 8. Interpretation and Limitations

- Canonical indicators and source observations must be counted separately.
- Malware rankings are based on observed source records rather than confirmed infections.
- Source collection mechanisms and metadata vary, making direct comparisons potentially misleading.
- The dataset represents a limited recent period, not comprehensive historical threat activity.
- Observation frequency does not establish an attack rate or global malware prevalence.

## 9. Validation

- Read-only PostgreSQL analysis completed successfully.
- Indicator and threat-type totals reconciled against the database.
- All 19 M6.2 automated tests passed.
- Full project test suite: **215 passed, 0 failed**.

## 10. Next Phase

**M6.3 — Temporal Analysis and Cross-Source Correlation**

Analyze first-seen activity by UTC date, temporal data-quality constraints, repeated source observations, and relationships between intelligence sources.