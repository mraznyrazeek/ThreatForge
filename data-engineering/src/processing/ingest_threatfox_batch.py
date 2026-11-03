
"""
ThreatForge - Controlled ThreatFox Batch Ingestion

Pipeline:
    ThreatFox API
        -> Pydantic normalization
        -> PostgreSQL observation persistence
        -> Ingestion-run lifecycle tracking

Features:
- Dry run by default.
- Explicit --execute required for database writes.
- Initial batches limited to 10 records.
- Verified development database destination.
- Inserted, updated, and unchanged classifications.
- Transactional observation persistence.
- Observation-to-ingestion-run linkage.
- Ingestion-run completion and failure tracking.
- Safe aggregate operational diagnostics.

The latest_ingestion_run_id is updated for every
successfully processed observation, including unchanged
intelligence records.

The database trigger preserves updated_at when only
the ingestion-run linkage changes.

Observation history and rejected-record persistence
will be implemented in subsequent steps.

No raw IOC values or API credentials are printed.
"""

import argparse
import os
import sys

from collections import Counter
from pathlib import Path

import requests

from dotenv import load_dotenv

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, URL
from sqlalchemy.exc import SQLAlchemyError


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

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
    complete_ingestion_run,
    fail_ingestion_run,
    start_ingestion_run,
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
    """Parse controlled ingestion arguments."""

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
        help="Maximum records to process (1-10)",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Enable PostgreSQL persistence and run tracking",
    )

    args = parser.parse_args()

    if args.days < 1:
        parser.error("--days must be at least 1")

    if not 1 <= args.limit <= MAX_INITIAL_BATCH_SIZE:
        parser.error(
            "Batch limit must be between 1 and "
            f"{MAX_INITIAL_BATCH_SIZE}"
        )

    return args


# ---------------------------------------------------------
# Database configuration
# ---------------------------------------------------------

def build_database_url() -> URL:
    """
    Build the development database URL.

    Explicit environment variables override .env defaults.
    """

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
    """Connect and verify the actual database identity."""

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

def collect_batch(
    days: int,
    limit: int,
) -> tuple[list[dict], int]:
    """Fetch and select a limited batch of ThreatFox records."""

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
            "ThreatFox returned a non-OK query status"
        )

    records = response.get("data")

    if not isinstance(records, list):
        raise ValueError(
            "ThreatFox response data must be a list"
        )

    selected_records = records[:limit]

    if any(
        not isinstance(record, dict)
        for record in selected_records
    ):
        raise ValueError(
            "Selected batch contains non-object records"
        )

    return selected_records, len(records)


# ---------------------------------------------------------
# Observation persistence with run linkage
# ---------------------------------------------------------

def persist_batch(
    engine: Engine,
    observations: list,
    ingestion_run_id: int,
) -> Counter:
    """
    Persist observations and link them to an active run.

    Each persistence operation manages its own transaction.

    The ingestion-run reference is saved atomically with
    the observation insertion or metadata update.

    A failure on one observation does not roll back
    previously committed observations.
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
                ingestion_run_id=ingestion_run_id,
            )

            if result.action not in SUCCESS_ACTIONS:
                raise RuntimeError(
                    "Unexpected persistence action"
                )

            counts[result.action] += 1

        except ValueError:
            counts["identity_conflicts"] += 1

        except SQLAlchemyError:
            counts["database_failures"] += 1

    return counts


def print_persistence_results(
    counts: Counter,
) -> tuple[int, int]:
    """Print aggregate persistence results."""

    print("\n=== POSTGRESQL PERSISTENCE RESULTS ===")

    print(f"Inserted observations: {counts['inserted']}")
    print(f"Updated observations: {counts['updated']}")
    print(f"Unchanged observations: {counts['unchanged']}")

    print(
        "Source identity conflicts: "
        f"{counts['identity_conflicts']}"
    )

    print(
        "Database failures: "
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
# Failure classification
# ---------------------------------------------------------

def classify_failure(
    phase: str,
) -> IngestionFailureCategory:
    """Return an approved operational failure category."""

    if phase == "configuration":
        return IngestionFailureCategory.CONFIGURATION_FAILURE

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
) -> None:
    """
    Attempt to finalize an unsuccessful ingestion run.

    Use only approved error categories.

    Do not store raw exception text, provider responses,
    API credentials, or IOC values.
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
            "The run may remain in running status "
            "and require reconciliation."
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
        # 1. Start an ingestion run only in execute mode.

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

        # 2. Collect ThreatFox records.

        phase = "collection"

        records, total_available = collect_batch(
            days=args.days,
            limit=args.limit,
        )

        received_count = len(records)

        print("\n=== COLLECTION RESULTS ===")
        print(f"API records available: {total_available}")
        print(f"Records selected: {received_count}")

        # 3. Normalize selected records.

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
        rejected_count = received_count - normalized_count

        print("\n=== NORMALIZATION RESULTS ===")
        print(
            "Successfully normalized: "
            f"{normalized_count}"
        )
        print(
            "Rejected during normalization: "
            f"{rejected_count}"
        )

        for category, count in sorted(
            diagnostics["failure_types"].items()
        ):
            print(
                f"Validation failure {category}: {count}"
            )

        # Dry runs do not write to PostgreSQL.

        if not args.execute:
            print("\n=== DRY RUN COMPLETE ===")
            print("No PostgreSQL records were modified.")

            return 0 if rejected_count == 0 else 2

        # 4. Persist and link observations to this run.

        phase = "persistence"

        counts = persist_batch(
            engine=engine,
            observations=observations,
            ingestion_run_id=run_id,
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

        # Persistence failures cause the run to fail,
        # even when other observations were committed.

        phase = "finalization"

        if persistence_failures:
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

        # 5. Finalize the successful run.
        #
        # Normalization-rejected records are counted.
        # They do not automatically make the run fail.

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
        print(
            "Records received: "
            f"{completed.records_received}"
        )
        print(
            "Records normalized: "
            f"{completed.records_normalized}"
        )
        print(
            "Records rejected: "
            f"{completed.records_rejected}"
        )

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
