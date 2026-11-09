
"""
ThreatForge - Controlled Bulk Intelligence Ingestion

Expands data collection from ThreatFox and URLhaus
without modifying the existing scheduled pipelines.

Features:
- Select one intelligence source per invocation.
- Dry-run by default.
- Explicit --execute required for PostgreSQL writes.
- Maximum 1,000 selected records per invocation.
- Reuses tested normalization and persistence functions.
- Preserves ingestion-run tracking and observation history.
- Uses sanitized rejection tracking.
- No raw IOC values or credentials printed.

Run from data-engineering.
"""

import argparse
import sys
from pathlib import Path

import requests


SRC_DIR = Path(__file__).resolve().parents[1]

for directory in ("collectors", "models", "processing"):
    sys.path.insert(0, str(SRC_DIR / directory))


from threatfox_collector import (  # noqa: E402
    load_configuration as load_threatfox,
    fetch_recent_iocs,
)

from urlhaus_collector import (  # noqa: E402
    load_configuration as load_urlhaus,
    fetch_recent_urls,
)

from ingest_threatfox_batch import (  # noqa: E402
    create_verified_engine,
    normalize_batch as normalize_threatfox_batch,
    persist_batch,
    print_persistence_results,
    record_failed_run,
    classify_failure,
)

from ingest_urlhaus_batch import (  # noqa: E402
    normalize_batch as normalize_urlhaus_batch,
)

from ingestion_run_service import (  # noqa: E402
    IngestionFailureCategory,
    start_ingestion_run,
    complete_ingestion_run,
    fail_ingestion_run,
)


SOURCE_NAMES = {
    "threatfox": "ThreatFox",
    "urlhaus": "URLhaus",
}

MAX_BULK_SIZE = 1000


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Controlled ThreatForge bulk ingestion"
    )

    parser.add_argument(
        "--source",
        required=True,
        choices=tuple(SOURCE_NAMES),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="ThreatFox lookback period (1-7 days)",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Enable PostgreSQL writes",
    )

    args = parser.parse_args()

    if not 1 <= args.limit <= MAX_BULK_SIZE:
        parser.error("--limit must be between 1 and 1000")

    if not 1 <= args.days <= 7:
        parser.error("--days must be between 1 and 7")

    return args


def collect_records(source, limit, days):
    """
    Collect available records and select a bounded batch.

    The APIs may return more records than the selected limit.
    Only the selected records are normalized or persisted.
    """

    if source == "threatfox":
        key, url = load_threatfox()

        response = fetch_recent_iocs(
            api_key=key,
            api_url=url,
            days=days,
        )

        field = "data"

    elif source == "urlhaus":
        key, url = load_urlhaus()

        response = fetch_recent_urls(
            api_key=key,
            api_url=url,
        )

        field = "urls"

    else:
        raise ValueError("Unsupported intelligence source")

    if not isinstance(response, dict):
        raise ValueError("Unexpected API response format")

    if response.get("query_status") != "ok":
        raise ValueError("Source API returned non-OK status")

    records = response.get(field)

    if not isinstance(records, list):
        raise ValueError("API response records must be a list")

    selected = records[:limit]

    if any(not isinstance(item, dict) for item in selected):
        raise ValueError("Selected records contain invalid objects")

    return selected, len(records)


def normalize_selected_records(
    source,
    records,
    engine=None,
    source_id=None,
    run_id=None,
):
    arguments = {
        "engine": engine,
        "source_id": source_id,
        "ingestion_run_id": run_id,
    }

    if source == "threatfox":
        return normalize_threatfox_batch(
            records,
            **arguments,
        )

    if source == "urlhaus":
        return normalize_urlhaus_batch(
            records,
            **arguments,
        )

    raise ValueError("Unsupported normalization source")


def main():
    args = parse_arguments()

    source_name = SOURCE_NAMES[args.source]

    print("\n=== THREATFORGE BULK INGESTION ===")
    print(f"Source: {source_name}")
    print(f"Maximum selected records: {args.limit}")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN'}")

    if args.source == "threatfox":
        print(f"ThreatFox lookback: {args.days} days")

    engine = None
    run_id = None
    source_id = None

    received = 0
    normalized = 0
    rejected = 0

    phase = "configuration"

    try:
        if args.execute:
            engine = create_verified_engine()

            started = start_ingestion_run(
                engine=engine,
                source_name=source_name,
            )

            run_id = started.run_id
            source_id = started.source_id

            print("\n=== INGESTION RUN ===")
            print(f"Run ID: {run_id}")
            print("Database: threatforge_db")

        phase = "collection"

        records, available = collect_records(
            args.source,
            args.limit,
            args.days,
        )

        received = len(records)

        print("\n=== COLLECTION ===")
        print(f"API records available: {available}")
        print(f"Selected for processing: {received}")

        phase = "normalization"

        observations, counts = normalize_selected_records(
            source=args.source,
            records=records,
            engine=engine,
            source_id=source_id,
            run_id=run_id,
        )

        normalized = counts["normalized"]
        rejected = counts["rejected"]

        if normalized + rejected != received:
            raise ValueError(
                "Normalization counts do not match input"
            )

        print("\n=== NORMALIZATION ===")
        print(f"Normalized: {normalized}")
        print(f"Rejected: {rejected}")
        print(
            "Rejections recorded: "
            f"{counts['rejections_recorded']}"
        )

        if not args.execute:
            print("\n=== BULK DRY RUN COMPLETE ===")
            print("No PostgreSQL records were modified.")
            return 0 if rejected == 0 else 2

        phase = "persistence"

        persistence_counts = persist_batch(
            engine=engine,
            observations=observations,
            ingestion_run_id=run_id,
        )

        successful, failures = print_persistence_results(
            persistence_counts
        )

        if successful + failures != normalized:
            raise RuntimeError(
                "Persistence outcomes do not match normalized count"
            )

        phase = "finalization"

        if failures:
            failed = fail_ingestion_run(
                engine=engine,
                run_id=run_id,
                failure_category=(
                    IngestionFailureCategory.PERSISTENCE_FAILURE
                ),
                records_received=received,
                records_normalized=normalized,
                records_rejected=rejected,
            )

            run_id = None

            print("\n=== BULK INGESTION FAILED ===")
            print(f"Run ID: {failed.run_id}")
            print("Reason: persistence failures")
            return 2

        completed = complete_ingestion_run(
            engine=engine,
            run_id=run_id,
            records_received=received,
            records_normalized=normalized,
            records_rejected=rejected,
        )

        run_id = None

        print("\n=== BULK INGESTION COMPLETE ===")
        print(f"Run ID: {completed.run_id}")
        print(f"Status: {completed.status}")
        print(f"Records received: {received}")
        print(f"Successfully persisted: {successful}")
        print(f"Normalization rejections: {rejected}")

        return 0 if rejected == 0 else 2

    except requests.RequestException as exc:
        print(
            "Bulk collection failed: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            IngestionFailureCategory.API_FAILURE,
            received,
            normalized,
            rejected,
        )
        return 1

    except Exception as exc:
        print(
            "Bulk ingestion failed: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            classify_failure(phase),
            received,
            normalized,
            rejected,
        )
        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
