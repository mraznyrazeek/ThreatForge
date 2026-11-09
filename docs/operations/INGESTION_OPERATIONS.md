
# ThreatForge — Ingestion Operations

## Milestone

M5 — Multi-Source Threat Intelligence Ingestion

Status: Core local-development implementation validated.

## 1. Overview

ThreatForge collects cybersecurity threat intelligence from:

- ThreatFox: general indicators of compromise.
- URLhaus: malicious URL intelligence.

Both sources feed a shared PostgreSQL intelligence model.

The system supports:

- Source-specific API collection
- Pydantic normalization and validation
- Canonical indicator deduplication
- Source observation tracking
- Historical observation snapshots
- Sanitized rejection handling
- Ingestion-run lifecycle management
- Unified multi-source orchestration
- Local scheduled execution
- PostgreSQL operational monitoring
- Manual stale-run reconciliation

## 2. Development environment

Operating system: macOS

Python: 3.15.0

Database:
- Development: threatforge_db
- Testing: threatforge_test_db

Configuration: repository-root .env file

Never commit API keys, database passwords, runtime
lock files, or operational logs.

Commands below are executed from data-engineering
with the project virtual environment activated.

## 3. Manual ingestion

### Unified dry run

python src/processing/run_intelligence_pipeline.py --limit 5

No PostgreSQL writes are performed.

### Controlled live ingestion

DB_NAME=threatforge_db \
python src/processing/run_intelligence_pipeline.py \
--limit 5 --execute

Processes up to five records per source.

### ThreatFox only

DB_NAME=threatforge_db \
python src/processing/ingest_threatfox_batch.py \
--days 1 --limit 5 --execute

### URLhaus only

DB_NAME=threatforge_db \
python src/processing/ingest_urlhaus_batch.py \
--limit 5 --execute

All live execution is restricted to the designated
development database.

## 4. Scheduled execution

Runner:

src/processing/run_scheduled_ingestion.py

Manual dry run:

python src/processing/run_scheduled_ingestion.py --limit 5

Manual controlled execution:

DB_NAME=threatforge_db \
python src/processing/run_scheduled_ingestion.py \
--limit 5 --execute

The runner uses a filesystem lock to prevent
overlapping scheduled invocations.

It attempts to terminate its child process group
on interruption or timeout.

## 5. macOS launchd

LaunchAgent label:

com.threatforge.ingestion

Local configuration:

~/Library/LaunchAgents/com.threatforge.ingestion.plist

Configured interval: 21600 seconds (6 hours)

Current automatic execution mode: DRY RUN

Recurring unattended PostgreSQL writes are not
currently enabled.

Check scheduler status:

launchctl print \
"gui/$(id -u)/com.threatforge.ingestion"

Inspect scheduler logs:

cat .runtime/scheduler.stdout.log
cat .runtime/scheduler.stderr.log

The Mac must be available for local scheduling.
A cloud or server scheduler is a future deployment task.

## 6. Monitoring

Run:

DB_NAME=threatforge_db \
python src/processing/monitor_ingestion.py

Monitoring reports:

- Observation counts by intelligence source
- Ingestion-run statuses
- Recent run-level processing counts
- Potentially stale running jobs

Monitoring is read-only.

## 7. Interrupted-run recovery

Inspect potentially stale runs:

DB_NAME=threatforge_db \
python src/processing/reconcile_ingestion_runs.py

A stale status alone does not establish that a
process has stopped.

Before manual recovery:

1. Stop or disable the scheduled LaunchAgent.
2. Check for active ingestion processes.
3. Verify the original job is no longer active.
4. Review the target ingestion run.
5. Confirm recovery is appropriate.

Only then use the recovery utility's explicit
--run-id, --apply, and --confirm-run-id options.

Recovery must never be applied automatically
solely because a run exceeds an age threshold.

The utility marks an eligible running record as
failed without deleting persisted observations
or historical snapshots.

## 8. Automated testing

Run all tests against the dedicated test database:

DB_NAME=threatforge_test_db \
python -m pytest tests/ -q -W error

Last verified result: 166 tests passed.

The test database must remain isolated from
live development intelligence.

## 9. Verified development results

Verification date: 2026-11-09

Sources: 2
ThreatFox observations: 50
URLhaus observations: 13
Total observations: 63

Completed ingestion runs: 6
Potentially stale runs: 0

A controlled multi-source execution through the
scheduled runner completed successfully, with
both source ingestion runs marked completed.

These are development validation results,
not live operational guarantees.

## 10. Known limitations

- Unattended PostgreSQL writes are not enabled.
- Monitoring currently reports status and aggregate
  counts rather than detailed per-source failure traces.
- Stale-run reconciliation is manual.
- Abrupt machine shutdown can leave an incomplete run.
- Scheduler reliability depends on local Mac availability.
- Scheduling and failure recovery need further validation
  before production deployment.
- Intelligence confidence and provider-specific data
  semantics require review before analytical ranking.

## 11. Next milestone

M6 — Threat Intelligence Analytics

Planned capabilities:

- Indicator type distributions
- Malware-family activity
- Source-specific intelligence trends
- Temporal threat activity
- Ingestion performance and data quality
- Analytics queries for a future REST API
- Dashboard-ready aggregated data

M5's core local-development scope is complete.
Production scheduling and operational hardening
remain future deployment tasks.
