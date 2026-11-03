
"""
ThreatForge - ThreatFox Batch Ingestion with Run Tracking

Pipeline:
    ThreatFox API
        -> Pydantic normalization
        -> PostgreSQL observation persistence
        -> Ingestion run lifecycle tracking

Features:
- Dry run by default.
- Explicit --execute required for database writes.
- Maximum initial batch size of 10 records.
- Verify development database identity.
- Report inserted, updated, and unchanged observations.
- Persist ingestion run start/completion/failure.
- Record received, normalized, and rejected counts.
- Store only approved operational failure categories.

Processing counts:
    records_received:
        Number of API records selected for this batch.

    records_normalized:
        Number of records successfully normalized.

    records_rejected:
        Number of records rejected by normalization.

Persistence failures are reported separately and cause
the ingestion run to finish with status='failed'.

Observation history, rejected-record storage, and
latest_ingestion_run_id updates are future steps.

No raw IOC values or credentials are printed.
"""

import argparse
import os
import sys

from collections import Counter
from pathlib import Path

import requests
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine
from sqlalchemy.exc import SQLAlchemyError


SRC_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[3]

sys.path.insert(0, str(SRC_DIR / "collectors"))
sys.path.insert(0, str(SRC_DIR / "models"))
sys.path.insert(0, str(SRC_DIR / "processing"))

from threatfox_collector import (  # noqa: E402
    fetch_recent_iocs,
    load_configuration,
)

from normalize_threatfox import normalize_records  # noqa: E402

from persist_observation import persist_observation  # noqa: E402

from ingestion_run_service import (  # noqa: E402
    IngestionFailureCategory,
    start_ingestion_run,
    complete_ingestion_run,
    fail_ingestion_run,
)


SOURCE_NAME = "ThreatFox"
DEVELOPMENT_DATABASE = "threatforge_db"
MAX_INITIAL_BATCH_SIZE = 10

SUCCESS_ACTIONS = (
    "inserted",
    "updated",
    "unchanged",
)


# ---------------------------------------------------------
# Command-line arguments
# ---------------------------------------------------------

def parse_arguments():
    """Parse controlled ingestion options."""

    parser = argparse.ArgumentParser(
        description="Controlled ThreatFox batch ingestion"
    )

    parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="ThreatFox lookback period in days",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum API records to process (1-10)",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Enable PostgreSQL writes and run tracking",
    )

    args = parser.parse_args()

    if args.days < 1:
        parser.error("--days must be at least 1")

    if not 1 <= args.limit <= MAX_INITIAL_BATCH_SIZE:
        parser.error(
            f"--limit must be between 1 and "
            f"{MAX_INITIAL_BATCH_SIZE}"
        )

    return args


# ---------------------------------------------------------
# Database configuration
# ---------------------------------------------------------

def build_database_url() -> URL:
    """Build the development database connection URL."""

    load_dotenv(
        PROJECT_ROOT / ".env",
        override=False,
    )

    database_name = os.environ.get("DB_NAME")

    if database_name != DEVELOPMENT_DATABASE:
        raise ValueError(
            "Live ingestion requires DB_NAME=threatforge_db"
        )

    for variable in ("DB_USER", "DB_PASSWORD"):
        if not os.environ.get(variable):
            raise ValueError(
                f"Missing database configuration: {variable}"
            )

    return URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=database_name,
    )


def create_verified_engine() -> Engine:
    """Verify the real database before enabling writes."""

    engine = create_engine(
        build_database_url(),
        pool_pre_ping=True,
    )

    try:
        with engine.connect() as connection:
            actual_database = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()

        if actual_database != DEVELOPMENT_DATABASE:
            raise ValueError(
                "Connected to an unexpected database"
            )

        return engine

    except Exception:
        engine.dispose()
        raise


# ---------------------------------------------------------
# ThreatFox collection
# ---------------------------------------------------------

def collect_batch(days: int, limit: int):
    """Fetch recent records and return a limited selection."""

    api_key, api_url = load_configuration()

    response = fetch_recent_iocs(
        api_key=api_key,
        api_url=api_url,
        days=days,
    )

    if not isinstance(response, dict):
        raise ValueError(
            "Expected ThreatFox response object"
        )

    if response.get("query_status") != "ok":
        raise ValueError(
            "ThreatFox returned non-OK query status"
        )

    records = response.get("data")

    if not isinstance(records, list):
        raise ValueError(
            "ThreatFox response data must be a list"
        )

    selected = records[:limit]

    if any(
        not isinstance(record, dict)
        for record in selected
    ):
        raise ValueError(
            "Selected records contain non-object entries"
        )

    return selected, len(records)


# ---------------------------------------------------------
# Observation persistence
# ---------------------------------------------------------

def persist_batch(engine: Engine, observations):
    """
    Persist validated observations individually.

    Each observation is committed separately by the
    existing persistence service.

    Partial failures do not roll back earlier successes.
    """

    counts = Counter({
        "inserted": 0,
        "updated": 0,
        "unchanged": 0,
        "identity_conflicts": 0,
        "database_failures": 0,
    })

    for observation in observations:
        try:
            result = persist_observation(
                engine=engine,
                observation=observation,
            )

            if result.action not in SUCCESS_ACTIONS:
                raise RuntimeError(
                    "Unknown persistence action"
                )

            counts[result.action] += 1

        except ValueError:
            counts["identity_conflicts"] += 1

        except SQLAlchemyError:
            counts["database_failures"] += 1

    return counts


def print_persistence_results(counts: Counter):
    """Display persistence totals without IOC values."""

    print("\n=== POSTGRESQL PERSISTENCE RESULTS ===")

    print(f"Inserted observations: {counts['inserted']}")
    print(f"Updated observations: {counts['updated']}")
    print(f"Unchanged observations: {counts['unchanged']}")

    print(
        f"Source identity conflicts: "
        f"{counts['identity_conflicts']}"
    )

    print(
        f"Database failures: "
        f"{counts['database_failures']}"
    )

    successful = sum(
        counts[action]
        for action in SUCCESS_ACTIONS
    )

    failures = (
        counts["identity_conflicts"]
        + counts["database_failures"]
    )

    return successful, failures


# ---------------------------------------------------------
# Ingestion-run failure reporting
# ---------------------------------------------------------

def classify_failure(phase: str):
    """Map the processing phase to an approved category."""

    if phase == "collection":
        return IngestionFailureCategory.API_FAILURE

    if phase == "normalization":
        return IngestionFailureCategory.NORMALIZATION_FAILURE

    if phase == "persistence":
        return IngestionFailureCategory.PERSISTENCE_FAILURE

    return IngestionFailureCategory.UNEXPECTED_FAILURE


def record_failed_run(
    engine: Engine | None,
    run_id: int | None,
    category: IngestionFailureCategory,
    received: int,
    normalized: int,
    rejected: int,
):
    """
    Attempt to mark a started run as failed.

    The failure update has its own transaction.
    If PostgreSQL is unavailable, do not conceal
    the original ingestion failure.
    """

    if engine is None or run_id is None:
        return

    try:
        result = fail_ingestion_run(
            engine=engine,
            run_id=run_id,
            failure_category=category,
            records_received=received,
            records_normalized=normalized,
            records_rejected=rejected,
        )

        print("\n=== INGESTION RUN TRACKING ===")
        print(f"Run ID: {result.run_id}")
        print(f"Status: {result.status}")
        print(f"Failure category: {category.value}")

    except (SQLAlchemyError, ValueError, TypeError) as exc:
        print(
            "Could not finalize failed ingestion run: "
            f"{type(exc).__name__}"
        )
        print(
            "The run may remain in 'running' status "
            "and require operational reconciliation."
        )


# ---------------------------------------------------------
# Main workflow
# ---------------------------------------------------------

def main() -> int:
    """Execute controlled ThreatFox batch ingestion."""

    args = parse_arguments()

    print("\n=== THREATFORGE BATCH INGESTION ===")

    print(
        "Mode: "
        + (
            "EXECUTE - PostgreSQL writes enabled"
            if args.execute
            else "DRY RUN - No database writes"
        )
    )

    print(f"Lookback days: {args.days}")
    print(f"Maximum records: {args.limit}")

    engine = None
    run_id = None

    phase = "configuration"

    received_count = 0
    normalized_count = 0
    rejected_count = 0

    try:
        # Create a run only in execution mode.
        # Dry runs never create database records.

        if args.execute:
            engine = create_verified_engine()

            print(
                f"Verified database: {DEVELOPMENT_DATABASE}"
            )

            started = start_ingestion_run(
                engine=engine,
                source_name=SOURCE_NAME,
            )

            run_id = started.run_id

            print("\n=== INGESTION RUN STARTED ===")
            print(f"Run ID: {run_id}")
            print(f"Status: {started.status}")

        # 1. Collect records.

        phase = "collection"

        records, total_available = collect_batch(
            days=args.days,
            limit=args.limit,
        )

        received_count = len(records)

        print("\n=== COLLECTION RESULTS ===")
        print(f"API records available: {total_available}")
        print(f"Records selected: {received_count}")

        # 2. Normalize selected records.

        phase = "normalization"

        if records:
            observations, diagnostics = normalize_records(
                records
            )
        else:
            observations = []
            diagnostics = {
                "failure_types": Counter(),
            }

        normalized_count = len(observations)

        rejected_count = (
            received_count - normalized_count
        )

        print("\n=== NORMALIZATION RESULTS ===")
        print(
            f"Successfully normalized: {normalized_count}"
        )
        print(
            f"Rejected during normalization: {rejected_count}"
        )

        for category, count in sorted(
            diagnostics["failure_types"].items()
        ):
            print(
                f"Validation failure {category}: {count}"
            )

        # Dry runs stop before persistence and run tracking.

        if not args.execute:
            print("\n=== DRY RUN COMPLETE ===")
            print("No PostgreSQL records were modified.")

            return 0 if rejected_count == 0 else 2

        # 3. Persist validated observations.

        phase = "persistence"

        counts = persist_batch(
            engine=engine,
            observations=observations,
        )

        successful, persistence_failures = (
            print_persistence_results(counts)
        )

        print("\n=== INGESTION SUMMARY ===")
        print(f"Selected records: {received_count}")
        print(f"Normalized records: {normalized_count}")
        print(f"Normalization rejections: {rejected_count}")
        print(f"Successful persistence: {successful}")
        print(f"Persistence failures: {persistence_failures}")

        # The current schema tracks normalized and
        # normalization-rejected counts separately.
        #
        # A persistence failure marks the run as failed
        # even if some records were successfully saved.

        if persistence_failures:
            phase = "finalization"

            failed = fail_ingestion_run(
                engine=engine,
                run_id=run_id,
                failure_category=(
                    IngestionFailureCategory.PERSISTENCE_FAILURE
                ),
                records_received=received_count,
                records_normalized=normalized_count,
                records_rejected=rejected_count,
            )

            run_id = None

            print("\n=== INGESTION RUN TRACKING ===")
            print(f"Run ID: {failed.run_id}")
            print(f"Status: {failed.status}")
            print("Failure category: persistence_failure")

            return 2

        # 4. Complete the ingestion run.
        #
        # Normalization rejections are counted but do
        # not automatically mean the pipeline failed.
        # A run can complete with rejected input records.

        phase = "finalization"

        completed = complete_ingestion_run(
            engine=engine,
            run_id=run_id,
            records_received=received_count,
            records_normalized=normalized_count,
            records_rejected=rejected_count,
        )

        run_id = None

        print("\n=== INGESTION RUN TRACKING ===")
        print(f"Run ID: {completed.run_id}")
        print(f"Status: {completed.status}")
        print(f"Records received: {completed.records_received}")
        print(f"Records normalized: {completed.records_normalized}")
        print(f"Records rejected: {completed.records_rejected}")

        print("\nControlled batch completed successfully.")

        return 0 if rejected_count == 0 else 2

    except requests.RequestException as exc:
        print(
            "ThreatFox API failure: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            IngestionFailureCategory.API_FAILURE,
            received_count,
            normalized_count,
            rejected_count,
        )

        return 1

    except (ValueError, TypeError, KeyError) as exc:
        print(
            "Ingestion configuration or data failure: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            classify_failure(phase),
            received_count,
            normalized_count,
            rejected_count,
        )

        return 1

    except SQLAlchemyError as exc:
        print(
            "PostgreSQL operation failure: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            classify_failure(phase),
            received_count,
            normalized_count,
            rejected_count,
        )

        return 1

    except Exception as exc:
        # Unexpected exceptions must not silently leave
        # successfully started runs unreported.
        #
        # Only the exception type is printed.

        print(
            "Unexpected ingestion failure: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            classify_failure(phase),
            received_count,
            normalized_count,
            rejected_count,
        )

        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
