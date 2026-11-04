
"""
ThreatForge - Controlled ThreatFox Batch Ingestion

Pipeline:
    ThreatFox API
        -> Record normalization
        -> Sanitized rejection tracking
        -> Observation persistence
        -> Ingestion-run lifecycle tracking

Safety:
- Dry-run by default.
- --execute required for database writes.
- Maximum 10 records per invocation.
- Live execution restricted to threatforge_db.
- No raw IOC values, raw payloads, or secrets logged.
- Rejection records contain approved categories and reason codes.
- Observation history is maintained by persist_observation.
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
from persist_rejected_record import (  # noqa: E402
    persist_rejected_record,
)
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


def parse_arguments():
    """Parse controlled batch-ingestion arguments."""

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
        help="Enable PostgreSQL writes",
    )

    args = parser.parse_args()

    if args.days < 1:
        parser.error("--days must be at least 1")

    if not 1 <= args.limit <= MAX_INITIAL_BATCH_SIZE:
        parser.error(
            f"--limit must be between 1 and {MAX_INITIAL_BATCH_SIZE}"
        )

    return args


def build_database_url() -> URL:
    """Build a URL for the development database only."""

    load_dotenv(
        PROJECT_ROOT / ".env",
        override=False,
    )

    if os.environ.get("DB_NAME") != DEVELOPMENT_DATABASE:
        raise ValueError(
            "Live ingestion requires DB_NAME=threatforge_db"
        )

    for key in ("DB_USER", "DB_PASSWORD"):
        if not os.environ.get(key):
            raise ValueError(
                f"Missing database configuration: {key}"
            )

    return URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=DEVELOPMENT_DATABASE,
    )


def create_verified_engine() -> Engine:
    """Verify the actual target database before writing."""

    engine = create_engine(
        build_database_url(),
        pool_pre_ping=True,
    )

    try:
        with engine.connect() as connection:
            actual = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()

            if actual != DEVELOPMENT_DATABASE:
                raise ValueError(
                    "Unexpected connected database"
                )

        return engine

    except Exception:
        engine.dispose()
        raise


def collect_batch(
    days: int,
    limit: int,
) -> tuple[list[dict], int]:
    """Collect and select a controlled ThreatFox batch."""

    api_key, api_url = load_configuration()

    response = fetch_recent_iocs(
        api_key=api_key,
        api_url=api_url,
        days=days,
    )

    if not isinstance(response, dict):
        raise ValueError(
            "ThreatFox response must be an object"
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

    selected = records[:limit]

    if any(not isinstance(item, dict) for item in selected):
        raise ValueError(
            "Selected batch contains non-object records"
        )

    return selected, len(records)


def normalize_batch(
    records: list[dict],
    *,
    engine: Engine | None = None,
    source_id: int | None = None,
    ingestion_run_id: int | None = None,
) -> tuple[list, Counter]:
    """
    Normalize records individually so that each rejected
    input can be counted and safely recorded.

    No raw rejected payloads or validation messages
    are persisted.

    Database rejection writes occur only when all
    three tracking arguments are supplied.
    """

    observations = []

    counts = Counter({
        "normalized": 0,
        "rejected": 0,
        "rejections_recorded": 0,
    })

    tracking_values = (
        engine,
        source_id,
        ingestion_run_id,
    )

    tracking_enabled = all(
        value is not None
        for value in tracking_values
    )

    if any(value is not None for value in tracking_values):
        if not tracking_enabled:
            raise ValueError(
                "Normalization tracking requires engine, "
                "source_id and ingestion_run_id together"
            )

    for record in records:
        normalized, _diagnostics = normalize_records(
            [record]
        )

        if len(normalized) == 1:
            observations.append(normalized[0])
            counts["normalized"] += 1
            continue

        if len(normalized) != 0:
            raise ValueError(
                "Unexpected normalization result count"
            )

        counts["rejected"] += 1

        if tracking_enabled:
            persist_rejected_record(
                engine,
                source_id=source_id,
                ingestion_run_id=ingestion_run_id,
                rejection_category="normalization_failure",
                reason_code="validation_failed",
            )

            counts["rejections_recorded"] += 1

    return observations, counts


def get_run_source_id(
    engine: Engine,
    ingestion_run_id: int,
) -> int:
    """Resolve the source ID for an existing ingestion run."""

    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                SELECT source_id
                FROM ingestion_runs
                WHERE id = :run_id
                """
            ),
            {"run_id": ingestion_run_id},
        ).scalar_one()


def persist_batch(
    engine: Engine,
    observations: list,
    ingestion_run_id: int,
) -> Counter:
    """
    Persist normalized observations under an active run.

    Record sanitized metadata for identity conflicts
    and database failures.

    Previously successful observations remain committed
    if another observation fails.
    """

    counts = Counter({
        "inserted": 0,
        "updated": 0,
        "unchanged": 0,
        "identity_conflicts": 0,
        "database_failures": 0,
        "rejections_recorded": 0,
    })

    source_id = None

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
            if source_id is None:
                source_id = get_run_source_id(
                    engine,
                    ingestion_run_id,
                )

            persist_rejected_record(
                engine,
                source_id=source_id,
                ingestion_run_id=ingestion_run_id,
                rejection_category="identity_conflict",
                reason_code="source_identity_conflict",
            )

            counts["identity_conflicts"] += 1
            counts["rejections_recorded"] += 1

        except SQLAlchemyError:
            if source_id is None:
                source_id = get_run_source_id(
                    engine,
                    ingestion_run_id,
                )

            persist_rejected_record(
                engine,
                source_id=source_id,
                ingestion_run_id=ingestion_run_id,
                rejection_category="persistence_failure",
                reason_code="database_operation_failed",
            )

            counts["database_failures"] += 1
            counts["rejections_recorded"] += 1

    return counts


def print_persistence_results(counts: Counter) -> tuple[int, int]:
    """Print aggregate persistence outcomes."""

    print("\n=== POSTGRESQL PERSISTENCE RESULTS ===")
    print(f"Inserted observations: {counts['inserted']}")
    print(f"Updated observations: {counts['updated']}")
    print(f"Unchanged observations: {counts['unchanged']}")
    print(
        f"Source identity conflicts: {counts['identity_conflicts']}"
    )
    print(f"Database failures: {counts['database_failures']}")
    print(
        "Persistence rejections recorded: "
        f"{counts['rejections_recorded']}"
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


def classify_failure(phase: str) -> IngestionFailureCategory:
    """Map pipeline phases to safe failure categories."""

    categories = {
        "configuration": (
            IngestionFailureCategory.CONFIGURATION_FAILURE
        ),
        "collection": IngestionFailureCategory.API_FAILURE,
        "normalization": (
            IngestionFailureCategory.NORMALIZATION_FAILURE
        ),
        "persistence": (
            IngestionFailureCategory.PERSISTENCE_FAILURE
        ),
    }

    return categories.get(
        phase,
        IngestionFailureCategory.UNEXPECTED_FAILURE,
    )


def record_failed_run(
    engine: Engine | None,
    run_id: int | None,
    category: IngestionFailureCategory,
    received: int,
    normalized: int,
    rejected: int,
) -> None:
    """Attempt to finalize a failed ingestion run safely."""

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

    except Exception as exc:
        print(
            "Could not finalize failed ingestion run: "
            f"{type(exc).__name__}"
        )
        print(
            "Run may require reconciliation."
        )


def main() -> int:
    """Execute the controlled ThreatFox ingestion workflow."""

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
    source_id = None

    phase = "configuration"

    received_count = 0
    normalized_count = 0
    rejected_count = 0

    try:
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
            source_id = started.source_id

            print("\n=== INGESTION RUN STARTED ===")
            print(f"Run ID: {run_id}")
            print(f"Status: {started.status}")

        phase = "collection"

        records, total_available = collect_batch(
            days=args.days,
            limit=args.limit,
        )

        received_count = len(records)

        print("\n=== COLLECTION RESULTS ===")
        print(f"API records available: {total_available}")
        print(f"Records selected: {received_count}")

        phase = "normalization"

        observations, normalization_counts = normalize_batch(
            records,
            engine=engine if args.execute else None,
            source_id=source_id if args.execute else None,
            ingestion_run_id=run_id if args.execute else None,
        )

        normalized_count = normalization_counts["normalized"]
        rejected_count = normalization_counts["rejected"]

        print("\n=== NORMALIZATION RESULTS ===")
        print(
            f"Successfully normalized: {normalized_count}"
        )
        print(
            f"Rejected during normalization: {rejected_count}"
        )
        print(
            "Normalization rejections recorded: "
            f"{normalization_counts['rejections_recorded']}"
        )

        if not args.execute:
            print("\n=== DRY RUN COMPLETE ===")
            print("No PostgreSQL records were modified.")

            return 0 if rejected_count == 0 else 2

        phase = "persistence"

        persistence_counts = persist_batch(
            engine=engine,
            observations=observations,
            ingestion_run_id=run_id,
        )

        successful, persistence_failures = (
            print_persistence_results(persistence_counts)
        )

        print("\n=== INGESTION SUMMARY ===")
        print(f"Selected records: {received_count}")
        print(f"Normalized records: {normalized_count}")
        print(f"Normalization rejections: {rejected_count}")
        print(f"Successful persistence: {successful}")
        print(f"Persistence failures: {persistence_failures}")
        print(
            "Total rejection records stored: "
            f"{normalization_counts['rejections_recorded'] + persistence_counts['rejections_recorded']}"
        )

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

            return 2

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
            f"Records received: {completed.records_received}"
        )
        print(
            f"Records normalized: {completed.records_normalized}"
        )
        print(
            f"Records rejected: {completed.records_rejected}"
        )

        print("\nControlled batch completed successfully.")

        return 0 if rejected_count == 0 else 2

    except requests.RequestException as exc:
        print(
            f"ThreatFox API failure: {type(exc).__name__}"
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

    except Exception as exc:
        print(
            "Ingestion processing failure: "
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
