
"""
ThreatForge - M6.1 Database Profiling

Read-only PostgreSQL profiling of threat intelligence.

Reports:
- Database table counts
- Source coverage
- Metadata completeness
- Confidence rating coverage
- Temporal coverage
- Timestamp quality
- Cross-source indicator overlap
- Repeated indicator observations
- Referential integrity

No raw IOCs, credentials or payloads are displayed.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env", override=False)

EXPECTED_DATABASE = "threatforge_db"

TABLE_NAMES = (
    "intelligence_sources",
    "threat_indicators",
    "indicator_observations",
    "observation_history",
    "ingestion_runs",
    "rejected_records",
)


def create_read_only_engine():
    """Connect only to the intended development database."""

    database = os.environ.get("DB_NAME")

    if database != EXPECTED_DATABASE:
        raise RuntimeError(
            "Set DB_NAME=threatforge_db to run profiling"
        )

    url = URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=database,
    )

    engine = create_engine(
        url,
        pool_pre_ping=True,
    )

    try:
        with engine.connect() as conn:
            actual_database = conn.execute(
                text("SELECT current_database()")
            ).scalar_one()

            if actual_database != EXPECTED_DATABASE:
                raise RuntimeError(
                    "Unexpected PostgreSQL database"
                )
    except Exception:
        engine.dispose()
        raise

    return engine


def get_table_counts(conn):
    """Count records across the six core tables."""

    counts = {}

    for name in TABLE_NAMES:
        counts[name] = conn.execute(
            text(f"SELECT COUNT(*) FROM public.{name}")
        ).scalar_one()

    return counts


def get_source_coverage(conn):
    """Count observations and distinct indicators per source."""

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                COUNT(o.id) AS observations,
                COUNT(DISTINCT o.indicator_id)
                    AS distinct_indicators
            FROM public.intelligence_sources s
            LEFT JOIN public.indicator_observations o
                ON o.source_id = s.id
            GROUP BY s.id, s.name
            ORDER BY s.name
        """)
    ).mappings().all()


def get_data_quality(conn):
    """Profile nullable fields and inconsistent timestamps."""

    return conn.execute(
        text("""
            SELECT
                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE malware_family IS NULL
                       OR BTRIM(malware_family) = ''
                ) AS missing_malware_family,

                COUNT(*) FILTER (
                    WHERE last_seen IS NULL
                ) AS missing_last_seen,

                COUNT(*) FILTER (
                    WHERE reporter IS NULL
                       OR BTRIM(reporter) = ''
                ) AS missing_reporter,

                COUNT(*) FILTER (
                    WHERE reference IS NULL
                       OR BTRIM(reference) = ''
                ) AS missing_reference,

                COUNT(*) FILTER (
                    WHERE confidence_level = 0
                ) AS zero_confidence_count,

                COUNT(*) FILTER (
                    WHERE confidence_level > 0
                ) AS positive_confidence_count,

                COUNT(*) FILTER (
                    WHERE last_seen IS NOT NULL
                      AND last_seen < first_seen
                ) AS reversed_timestamps

            FROM public.indicator_observations
        """)
    ).mappings().one()


def get_confidence_by_source(conn):
    """
    Report confidence coverage by intelligence source.

    URLhaus confidence=0 is currently an unrated
    placeholder rather than an actual risk assessment.
    """

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                COUNT(o.id) AS observations,

                COUNT(*) FILTER (
                    WHERE o.confidence_level = 0
                ) AS zero_confidence,

                COUNT(*) FILTER (
                    WHERE o.confidence_level > 0
                ) AS positive_confidence

            FROM public.indicator_observations o
            JOIN public.intelligence_sources s
                ON s.id = o.source_id
            GROUP BY s.name
            ORDER BY s.name
        """)
    ).mappings().all()


def get_temporal_coverage(conn):
    """Report first-seen and last-seen date coverage."""

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                COUNT(o.id) AS observations,
                MIN(o.first_seen) AS earliest_first_seen,
                MAX(o.first_seen) AS latest_first_seen,
                MIN(o.last_seen) AS earliest_last_seen,
                MAX(o.last_seen) AS latest_last_seen

            FROM public.intelligence_sources s
            LEFT JOIN public.indicator_observations o
                ON o.source_id = s.id
            GROUP BY s.id, s.name
            ORDER BY s.name
        """)
    ).mappings().all()


def get_timestamp_quality(conn):
    """Count timestamp-quality classifications by source."""

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                o.timestamp_quality,
                COUNT(*) AS total

            FROM public.indicator_observations o
            JOIN public.intelligence_sources s
                ON s.id = o.source_id

            GROUP BY
                s.name,
                o.timestamp_quality

            ORDER BY
                s.name,
                o.timestamp_quality
        """)
    ).mappings().all()


def get_indicator_overlap(conn):
    """
    Count canonical indicators appearing in multiple sources.

    Uses a safe derived-table alias instead of the
    PostgreSQL OVERLAPS keyword.
    """

    return conn.execute(
        text("""
            SELECT COUNT(*) AS multi_source_indicators
            FROM (
                SELECT
                    indicator_id
                FROM public.indicator_observations
                GROUP BY indicator_id
                HAVING COUNT(DISTINCT source_id) > 1
            ) AS shared_indicators
        """)
    ).scalar_one()


def get_repeated_source_indicators(conn):
    """
    Count source/indicator pairs with multiple observations.

    These may represent multiple provider records that
    normalize to the same canonical indicator.
    """

    return conn.execute(
        text("""
            SELECT
                COUNT(*) AS repeated_source_indicator_pairs,
                COALESCE(
                    SUM(observation_count - 1),
                    0
                ) AS additional_observations

            FROM (
                SELECT
                    source_id,
                    indicator_id,
                    COUNT(*) AS observation_count

                FROM public.indicator_observations

                GROUP BY
                    source_id,
                    indicator_id

                HAVING COUNT(*) > 1
            ) AS repeated_pairs
        """)
    ).mappings().one()


def get_integrity_checks(conn):
    """Check source and indicator relationships."""

    return conn.execute(
        text("""
            SELECT
                COUNT(*) FILTER (
                    WHERE i.id IS NULL
                ) AS missing_indicator_links,

                COUNT(*) FILTER (
                    WHERE s.id IS NULL
                ) AS missing_source_links

            FROM public.indicator_observations o

            LEFT JOIN public.threat_indicators i
                ON i.id = o.indicator_id

            LEFT JOIN public.intelligence_sources s
                ON s.id = o.source_id
        """)
    ).mappings().one()


def format_timestamp(value):
    """Format database timestamps safely."""

    if value is None:
        return "N/A"

    return value.isoformat()


def print_report(conn):
    """Print the complete read-only database profile."""

    print("=== THREATFORGE M6.1 DATABASE PROFILE ===")
    print("Database: threatforge_db")
    print("Mode: READ ONLY")

    print("\n=== TABLE COUNTS ===")

    counts = get_table_counts(conn)

    for table_name, count in counts.items():
        print(f"{table_name}: {count}")

    print("\n=== SOURCE COVERAGE ===")

    for row in get_source_coverage(conn):
        print(
            f"{row['source_name']}: "
            f"observations={row['observations']}, "
            f"distinct_indicators={row['distinct_indicators']}"
        )

    print("\n=== DATA COMPLETENESS ===")

    quality = get_data_quality(conn)

    for key, value in quality.items():
        print(f"{key}: {value}")

    print("\n=== CONFIDENCE COVERAGE BY SOURCE ===")

    for row in get_confidence_by_source(conn):
        print(
            f"{row['source_name']}: "
            f"observations={row['observations']}, "
            f"zero={row['zero_confidence']}, "
            f"positive={row['positive_confidence']}"
        )

    print(
        "Note: URLhaus confidence=0 means unrated "
        "under the current normalization policy."
    )

    print("\n=== TEMPORAL COVERAGE ===")

    for row in get_temporal_coverage(conn):
        print(f"\nSource: {row['source_name']}")
        print(f"Observations: {row['observations']}")

        print(
            "Earliest first_seen:",
            format_timestamp(row["earliest_first_seen"]),
        )

        print(
            "Latest first_seen:",
            format_timestamp(row["latest_first_seen"]),
        )

        print(
            "Earliest last_seen:",
            format_timestamp(row["earliest_last_seen"]),
        )

        print(
            "Latest last_seen:",
            format_timestamp(row["latest_last_seen"]),
        )

    print("\n=== TIMESTAMP QUALITY ===")

    for row in get_timestamp_quality(conn):
        print(
            f"{row['source_name']} | "
            f"{row['timestamp_quality']}: "
            f"{row['total']}"
        )

    print("\n=== CROSS-SOURCE OVERLAP ===")

    overlap = get_indicator_overlap(conn)

    print(
        "Indicators reported by multiple sources:",
        overlap,
    )

    print("\n=== REPEATED INDICATORS WITHIN SOURCES ===")

    repeated = get_repeated_source_indicators(conn)

    print(
        "Repeated source-indicator pairs:",
        repeated["repeated_source_indicator_pairs"],
    )

    print(
        "Additional observations within those pairs:",
        repeated["additional_observations"],
    )

    print("\n=== REFERENTIAL INTEGRITY ===")

    integrity = get_integrity_checks(conn)

    for key, value in integrity.items():
        print(f"{key}: {value}")

    print("\n=== PROFILE COMPLETE ===")
    print("No database records were modified.")
    print("No IOC values or credentials were displayed.")


def main():
    """Execute all profiling queries in a read-only transaction."""

    engine = None

    try:
        engine = create_read_only_engine()

        with engine.connect() as conn:
            conn.execute(
                text("SET TRANSACTION READ ONLY")
            )

            print_report(conn)

        return 0

    except Exception as exc:
        # Avoid exposing database credentials or raw SQL
        # parameters through exception messages.
        print(
            "Database profiling failed: "
            f"{type(exc).__name__}"
        )
        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
