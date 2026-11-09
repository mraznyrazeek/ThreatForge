
"""
ThreatForge - Controlled URLhaus Batch Ingestion

Pipeline:
    URLhaus API
        -> Record normalization
        -> Sanitized rejection tracking
        -> Existing observation persistence
        -> Existing ingestion-run lifecycle tracking

Safety:
- Dry-run by default.
- --execute required for PostgreSQL writes.
- Maximum 10 records per invocation.
- Live execution restricted to threatforge_db.
- No raw malicious URLs, API keys, or payloads logged.
- Reuses the tested M4 persistence infrastructure.
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

import requests

SRC_DIR = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(SRC_DIR / "collectors"))
sys.path.insert(0, str(SRC_DIR / "processing"))

from urlhaus_collector import (  # noqa: E402
    fetch_recent_urls,
    load_configuration,
)
from normalize_urlhaus import normalize_records  # noqa: E402
from persist_rejected_record import (  # noqa: E402
    persist_rejected_record,
)
from ingestion_run_service import (  # noqa: E402
    IngestionFailureCategory,
    start_ingestion_run,
    complete_ingestion_run,
    fail_ingestion_run,
)
from ingest_threatfox_batch import (  # noqa: E402
    create_verified_engine,
    persist_batch,
    print_persistence_results,
    record_failed_run,
    classify_failure,
)

SOURCE_NAME = "URLhaus"
MAX_BATCH_SIZE = 10


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Controlled URLhaus batch ingestion"
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

    if not 1 <= args.limit <= MAX_BATCH_SIZE:
        parser.error(
            f"--limit must be between 1 and {MAX_BATCH_SIZE}"
        )

    return args


def collect_batch(limit: int):
    """Retrieve recent URLhaus records and select a small batch."""

    api_key, api_url = load_configuration()

    response = fetch_recent_urls(
        api_key=api_key,
        api_url=api_url,
    )

    if not isinstance(response, dict):
        raise ValueError("URLhaus response must be an object")

    if response.get("query_status") != "ok":
        raise ValueError("URLhaus returned non-OK status")

    records = response.get("urls")

    if not isinstance(records, list):
        raise ValueError("URLhaus response must contain a URL list")

    selected = records[:limit]

    if any(not isinstance(record, dict) for record in selected):
        raise ValueError("Selected batch contains non-object records")

    return selected, len(records)


def normalize_batch(
    records,
    *,
    engine=None,
    source_id=None,
    ingestion_run_id=None,
):
    """
    Normalize URLhaus records individually.

    Record sanitized normalization rejections when database
    tracking is enabled. Raw provider records are not stored.
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
        value is not None for value in tracking_values
    )

    if any(value is not None for value in tracking_values):
        if not tracking_enabled:
            raise ValueError(
                "Normalization tracking requires engine, "
                "source_id and ingestion_run_id together"
            )

    for record in records:
        normalized, _diagnostics = normalize_records([record])

        if len(normalized) == 1:
            observation = normalized[0]

            if observation.source_name != SOURCE_NAME:
                raise ValueError(
                    "Normalizer returned an unexpected source"
                )

            observations.append(observation)
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


def main() -> int:
    args = parse_arguments()

    print("\n=== THREATFORGE URLHAUS BATCH INGESTION ===")

    print(
        "Mode: "
        + (
            "EXECUTE - PostgreSQL writes enabled"
            if args.execute
            else "DRY RUN - No database writes"
        )
    )

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

            print("Verified database: threatforge_db")

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
        print(f"Successfully normalized: {normalized_count}")
        print(f"Rejected during normalization: {rejected_count}")
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

        print("\nControlled URLhaus batch completed.")

        return 0 if rejected_count == 0 else 2

    except requests.RequestException as exc:
        print(
            "URLhaus API failure: "
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
