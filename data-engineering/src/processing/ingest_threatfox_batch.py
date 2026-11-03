
"""
ThreatForge - Controlled ThreatFox Batch Ingestion

Connects:
    ThreatFox API
        -> Pydantic normalization
        -> PostgreSQL persistence

Features:
- Dry run by default.
- Explicit --execute required for database writes.
- Initial batch limited to 10 records.
- Verify the development database before writing.
- Report inserted, updated, and unchanged observations.
- Report normalization and persistence failures.
- Keep individual observation writes transactional.

No raw IOC values or API credentials are printed.

Ingestion runs, observation history, and rejected-record
persistence will be implemented in later steps.
"""

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

import requests
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
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


DEVELOPMENT_DATABASE = "threatforge_db"
MAX_INITIAL_BATCH_SIZE = 10

SUCCESS_ACTIONS = (
    "inserted",
    "updated",
    "unchanged",
)


def parse_arguments():
    """Parse the controlled ingestion arguments."""

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
        help="Enable PostgreSQL persistence",
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


def build_database_url() -> URL:
    """
    Construct the development database URL.

    Explicit environment variables take priority
    over the project .env file.
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


def create_verified_engine():
    """Connect and verify the actual PostgreSQL database."""

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


def collect_batch(days: int, limit: int):
    """Fetch and select a limited number of ThreatFox records."""

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
            "ThreatFox response data is not a list"
        )

    selected_records = records[:limit]

    if any(
        not isinstance(record, dict)
        for record in selected_records
    ):
        raise ValueError(
            "Selected records contain a non-object entry"
        )

    return selected_records, len(records)


def persist_batch(engine, observations):
    """
    Persist validated observations individually.

    Each operation uses its own database transaction.

    Return actual persistence action counts.
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
                raise ValueError(
                    "Unexpected persistence action"
                )

            counts[result.action] += 1

        except ValueError:
            counts["identity_conflicts"] += 1

        except SQLAlchemyError:
            counts["database_failures"] += 1

    return counts


def print_persistence_summary(
    counts: Counter,
    normalized_count: int,
    rejected_count: int,
):
    """Print aggregate persistence results without IOC values."""

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

    unsuccessful = (
        rejected_count
        + counts["identity_conflicts"]
        + counts["database_failures"]
    )

    print("\n=== INGESTION SUMMARY ===")

    print(
        f"Normalized observations: {normalized_count}"
    )
    print(f"Successful operations: {successful}")
    print(f"Unsuccessful records: {unsuccessful}")

    return unsuccessful


def main() -> int:
    """Run the controlled ThreatFox ingestion workflow."""

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

    try:
        if args.execute:
            engine = create_verified_engine()

            print(
                f"Verified database: {DEVELOPMENT_DATABASE}"
            )

        records, total_available = collect_batch(
            days=args.days,
            limit=args.limit,
        )

        print("\n=== COLLECTION RESULTS ===")
        print(f"API records available: {total_available}")
        print(f"Records selected: {len(records)}")

        if not records:
            print("No records available for processing.")
            return 0

        observations, diagnostics = normalize_records(
            records
        )

        normalized_count = len(observations)
        rejected_count = (
            len(records) - normalized_count
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

        if not args.execute:
            print("\n=== DRY RUN COMPLETE ===")
            print("No PostgreSQL records were modified.")

            return 0 if rejected_count == 0 else 2

        if not observations:
            print(
                "No valid observations to persist."
            )
            return 2

        counts = persist_batch(
            engine=engine,
            observations=observations,
        )

        failures = print_persistence_summary(
            counts=counts,
            normalized_count=normalized_count,
            rejected_count=rejected_count,
        )

        if failures:
            print(
                "Batch completed with unsuccessful records."
            )
            return 2

        print(
            "Controlled batch completed successfully."
        )

        return 0

    except requests.RequestException as exc:
        print(
            "ThreatFox API failure: "
            f"{type(exc).__name__}"
        )
        return 1

    except (ValueError, TypeError, KeyError) as exc:
        print(
            "Configuration or data failure: "
            f"{type(exc).__name__}"
        )
        return 1

    except SQLAlchemyError as exc:
        print(
            "PostgreSQL failure: "
            f"{type(exc).__name__}"
        )
        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
