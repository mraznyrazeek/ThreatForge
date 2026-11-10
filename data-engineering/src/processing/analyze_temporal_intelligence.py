
"""
ThreatForge - M6.3 Temporal Intelligence Analysis

Read-only analytics for:
- Daily first-seen observations by source
- Timestamp quality and reliability
- Valid first_seen to last_seen intervals
- Cross-source indicator correlation
- Repeated indicators within the same source
- Aggregation reconciliation

Important:
These are provider-reported observations, not global
cyberattack counts. UTC calendar dates are used.

No raw IOC values or credentials are displayed.

Run from data-engineering.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env", override=False)

EXPECTED_DATABASE = "threatforge_db"


def create_analytics_engine():
    """Connect to the verified development database."""

    database = os.environ.get("DB_NAME")

    if database != EXPECTED_DATABASE:
        raise RuntimeError(
            "Set DB_NAME=threatforge_db before running analytics"
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


def get_source_totals(conn):
    """Count all stored observations by source."""

    return conn.execute(
        text("""
            SELECT
                s.id AS source_id,
                s.name AS source_name,
                COUNT(o.id) AS observation_count

            FROM public.intelligence_sources s

            LEFT JOIN public.indicator_observations o
                ON o.source_id = s.id

            GROUP BY s.id, s.name
            ORDER BY s.name
        """)
    ).mappings().all()


def get_daily_first_seen(conn):
    """
    Count observations by provider-reported first-seen
    date, normalized to UTC calendar dates.

    These counts do not represent attack rates.
    """

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,

                (
                    o.first_seen AT TIME ZONE 'UTC'
                )::date AS first_seen_date,

                COUNT(*) AS observation_count,

                COUNT(DISTINCT o.indicator_id)
                    AS distinct_indicator_count

            FROM public.indicator_observations o

            JOIN public.intelligence_sources s
                ON s.id = o.source_id

            GROUP BY
                s.name,
                (o.first_seen AT TIME ZONE 'UTC')::date

            ORDER BY
                first_seen_date,
                source_name
        """)
    ).mappings().all()


def get_timestamp_quality(conn):
    """Count timestamp-quality labels for each source."""

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                o.timestamp_quality,
                COUNT(*) AS observation_count

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


def get_valid_interval_statistics(conn):
    """
    Calculate observation interval statistics only
    when last_seen >= first_seen.

    An interval is not an infection duration or
    necessarily the lifetime of an indicator.
    """

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,

                COUNT(o.id) AS total_observations,

                COUNT(o.id) FILTER (
                    WHERE o.last_seen IS NULL
                ) AS missing_last_seen,

                COUNT(o.id) FILTER (
                    WHERE o.last_seen < o.first_seen
                ) AS reversed_intervals,

                COUNT(o.id) FILTER (
                    WHERE o.last_seen IS NOT NULL
                      AND o.last_seen >= o.first_seen
                ) AS valid_intervals,

                ROUND(
                    AVG(
                        EXTRACT(
                            EPOCH FROM (
                                o.last_seen - o.first_seen
                            )
                        ) / 3600.0
                    ) FILTER (
                        WHERE o.last_seen IS NOT NULL
                          AND o.last_seen >= o.first_seen
                    )::numeric,
                    2
                ) AS avg_interval_hours

            FROM public.intelligence_sources s

            LEFT JOIN public.indicator_observations o
                ON o.source_id = s.id

            GROUP BY
                s.id,
                s.name

            ORDER BY s.name
        """)
    ).mappings().all()


def get_cross_source_overlaps(conn):
    """
    Count canonical indicators shared by different
    source pairs, without returning indicator values.
    """

    return conn.execute(
        text("""
            SELECT
                a.name AS first_source,
                b.name AS second_source,

                COUNT(DISTINCT x.indicator_id)
                    AS shared_indicators

            FROM public.indicator_observations x

            JOIN public.indicator_observations y
                ON x.indicator_id = y.indicator_id
               AND x.source_id < y.source_id

            JOIN public.intelligence_sources a
                ON a.id = x.source_id

            JOIN public.intelligence_sources b
                ON b.id = y.source_id

            GROUP BY
                a.id,
                a.name,
                b.id,
                b.name

            ORDER BY
                shared_indicators DESC,
                first_source,
                second_source
        """)
    ).mappings().all()


def get_repeated_source_indicators(conn):
    """
    Identify source-level duplicate indicator groups.

    Counts repeated source-indicator combinations,
    not duplicate ingestion of identical source records.
    """

    return conn.execute(
        text("""
            SELECT
                source_name,
                COUNT(*) AS repeated_indicator_groups,

                COALESCE(
                    SUM(observation_count - 1),
                    0
                ) AS additional_observations

            FROM (
                SELECT
                    s.name AS source_name,
                    o.indicator_id,
                    COUNT(*) AS observation_count

                FROM public.indicator_observations o

                JOIN public.intelligence_sources s
                    ON s.id = o.source_id

                GROUP BY
                    s.name,
                    o.indicator_id

                HAVING COUNT(*) > 1
            ) AS repeated_groups

            GROUP BY source_name
            ORDER BY source_name
        """)
    ).mappings().all()


def print_analysis(conn):
    """Print temporal and correlation results."""

    print("=== THREATFORGE M6.3 TEMPORAL ANALYSIS ===")
    print("Database: threatforge_db")
    print("Mode: READ ONLY")
    print("Calendar timezone: UTC")

    source_rows = get_source_totals(conn)

    expected_by_source = {
        row["source_name"]: row["observation_count"]
        for row in source_rows
    }

    expected_total = sum(expected_by_source.values())

    print("\n=== SOURCE TOTALS ===")

    for source, total in expected_by_source.items():
        print(f"{source}: {total}")

    print(f"Overall observations: {expected_total}")

    print("\n=== DAILY FIRST-SEEN OBSERVATIONS (UTC) ===")

    daily_rows = get_daily_first_seen(conn)

    daily_by_source = {
        name: 0 for name in expected_by_source
    }

    for row in daily_rows:
        source = row["source_name"]
        count = row["observation_count"]

        daily_by_source[source] += count

        print(
            f"{row['first_seen_date']} | "
            f"{source} | "
            f"observations={count} | "
            f"distinct_indicators="
            f"{row['distinct_indicator_count']}"
        )

    if daily_by_source != expected_by_source:
        raise RuntimeError(
            "Daily observation totals do not reconcile"
        )

    print("\n=== TIMESTAMP QUALITY BY SOURCE ===")

    quality_by_source = {
        name: 0 for name in expected_by_source
    }

    for row in get_timestamp_quality(conn):
        source = row["source_name"]
        count = row["observation_count"]

        quality_by_source[source] += count

        print(
            f"{source} | "
            f"{row['timestamp_quality']}: {count}"
        )

    if quality_by_source != expected_by_source:
        raise RuntimeError(
            "Timestamp-quality totals do not reconcile"
        )

    print("\n=== OBSERVATION INTERVAL QUALITY ===")

    interval_rows = get_valid_interval_statistics(conn)

    for row in interval_rows:
        total = row["total_observations"]
        missing = row["missing_last_seen"]
        reversed_count = row["reversed_intervals"]
        valid = row["valid_intervals"]

        if missing + reversed_count + valid != total:
            raise RuntimeError(
                "Observation interval counts do not reconcile"
            )

        print(f"\nSource: {row['source_name']}")
        print(f"Total observations: {total}")
        print(f"Valid intervals: {valid}")
        print(f"Missing last_seen: {missing}")
        print(f"Reversed intervals: {reversed_count}")

        average = row["avg_interval_hours"]

        print(
            "Mean valid interval (hours): "
            f"{average if average is not None else 'N/A'}"
        )

    print("\n=== CROSS-SOURCE CORRELATION ===")

    overlaps = get_cross_source_overlaps(conn)

    if overlaps:
        for row in overlaps:
            print(
                f"{row['first_source']} & "
                f"{row['second_source']}: "
                f"{row['shared_indicators']} "
                "shared canonical indicators"
            )
    else:
        print("No shared canonical indicators found.")

    print("\n=== REPEATED INDICATORS WITHIN SOURCES ===")

    repeated_rows = get_repeated_source_indicators(conn)

    if repeated_rows:
        for row in repeated_rows:
            print(
                f"{row['source_name']}: "
                f"repeated_groups="
                f"{row['repeated_indicator_groups']}, "
                f"additional_observations="
                f"{row['additional_observations']}"
            )
    else:
        print("No repeated source-indicator groups.")

    print("\n=== ANALYSIS COMPLETE ===")
    print("Daily and timestamp-quality counts reconciled.")
    print("Observation intervals validated.")
    print("No PostgreSQL records were modified.")
    print("No raw indicator values were displayed.")
    print(
        "Interpretation: These are provider-reported "
        "first-seen dates, not global attack counts."
    )


def main():
    engine = None

    try:
        engine = create_analytics_engine()

        with engine.connect() as conn:
            conn.execute(
                text("SET TRANSACTION READ ONLY")
            )

            print_analysis(conn)

        return 0

    except Exception as exc:
        print(
            "Temporal analysis failed: "
            f"{type(exc).__name__}"
        )
        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
