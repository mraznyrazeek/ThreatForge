
"""
ThreatForge - M6.2 Indicator and Malware Distribution Analysis

Read-only analytics for:
1. Global canonical indicator distribution
2. Indicator distribution by intelligence source
3. Threat-type distribution
4. Top malware families
5. Per-source malware metadata coverage

Counts describe records in ThreatForge's collected feeds,
not worldwide prevalence of malware or cyberattacks.

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
TOP_FAMILIES = 15


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


def get_total_counts(conn):
    """Return global indicator and observation counts."""

    return conn.execute(
        text("""
            SELECT
                (
                    SELECT COUNT(*)
                    FROM public.threat_indicators
                ) AS canonical_indicators,

                (
                    SELECT COUNT(*)
                    FROM public.indicator_observations
                ) AS source_observations
        """)
    ).mappings().one()


def get_global_indicator_distribution(conn):
    """
    Count canonical indicators by IOC type.

    Each canonical indicator is counted once.
    """

    return conn.execute(
        text("""
            SELECT
                indicator_type,
                COUNT(*) AS indicator_count

            FROM public.threat_indicators

            GROUP BY indicator_type

            ORDER BY indicator_count DESC,
                     indicator_type
        """)
    ).mappings().all()


def get_source_indicator_distribution(conn):
    """
    Count observations and distinct indicators
    for each indicator type within each provider.
    """

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                i.indicator_type,

                COUNT(o.id) AS observation_count,

                COUNT(DISTINCT o.indicator_id)
                    AS distinct_indicator_count

            FROM public.indicator_observations o

            JOIN public.threat_indicators i
                ON i.id = o.indicator_id

            JOIN public.intelligence_sources s
                ON s.id = o.source_id

            GROUP BY
                s.name,
                i.indicator_type

            ORDER BY
                s.name,
                observation_count DESC,
                i.indicator_type
        """)
    ).mappings().all()


def get_threat_type_distribution(conn):
    """
    Count threat classifications by source.

    Threat-type labels come from the normalized
    provider observations.
    """

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,
                o.threat_type,
                COUNT(*) AS observation_count

            FROM public.indicator_observations o

            JOIN public.intelligence_sources s
                ON s.id = o.source_id

            GROUP BY
                s.name,
                o.threat_type

            ORDER BY
                s.name,
                observation_count DESC,
                o.threat_type
        """)
    ).mappings().all()


def get_top_malware_families(conn, limit=TOP_FAMILIES):
    """
    Rank malware family labels among observations
    where malware-family metadata is present.

    An observation is counted once. These counts
    do not represent unique infections or attacks.
    """

    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError("Limit must be an integer")

    if not 1 <= limit <= 100:
        raise ValueError("Limit must be between 1 and 100")

    return conn.execute(
        text("""
            SELECT
                malware_family,
                COUNT(*) AS observation_count,
                COUNT(DISTINCT indicator_id)
                    AS distinct_indicators

            FROM public.indicator_observations

            WHERE malware_family IS NOT NULL
              AND BTRIM(malware_family) <> ''

            GROUP BY malware_family

            ORDER BY observation_count DESC,
                     malware_family

            LIMIT :limit
        """),
        {"limit": limit},
    ).mappings().all()


def get_malware_coverage_by_source(conn):
    """
    Count observations with and without usable
    malware-family metadata.
    """

    return conn.execute(
        text("""
            SELECT
                s.name AS source_name,

                COUNT(o.id) AS total_observations,

                COUNT(o.id) FILTER (
                    WHERE o.malware_family IS NOT NULL
                      AND BTRIM(o.malware_family) <> ''
                ) AS with_malware_family,

                COUNT(o.id) FILTER (
                    WHERE o.malware_family IS NULL
                       OR BTRIM(o.malware_family) = ''
                ) AS without_malware_family

            FROM public.intelligence_sources s

            LEFT JOIN public.indicator_observations o
                ON o.source_id = s.id

            GROUP BY
                s.id,
                s.name

            ORDER BY s.name
        """)
    ).mappings().all()


def percentage(part, whole):
    """Calculate a percentage safely."""

    if whole == 0:
        return 0.0

    return round((part / whole) * 100, 2)


def print_analysis(conn):
    """Generate the full distribution report."""

    print("=== THREATFORGE M6.2 DISTRIBUTION ANALYSIS ===")
    print("Database: threatforge_db")
    print("Mode: READ ONLY")

    totals = get_total_counts(conn)

    canonical_total = totals["canonical_indicators"]
    observation_total = totals["source_observations"]

    print("\n=== DATASET OVERVIEW ===")
    print(f"Canonical indicators: {canonical_total}")
    print(f"Source observations: {observation_total}")

    print("\n=== GLOBAL INDICATOR DISTRIBUTION ===")

    global_rows = get_global_indicator_distribution(conn)

    global_sum = 0

    for row in global_rows:
        count = row["indicator_count"]
        global_sum += count

        print(
            f"{row['indicator_type']}: "
            f"{count} "
            f"({percentage(count, canonical_total)}%)"
        )

    if global_sum != canonical_total:
        raise RuntimeError(
            "Global indicator totals do not reconcile"
        )

    print("\n=== INDICATOR DISTRIBUTION BY SOURCE ===")

    source_rows = get_source_indicator_distribution(conn)

    source_observation_sum = 0

    for row in source_rows:
        count = row["observation_count"]
        source_observation_sum += count

        print(
            f"{row['source_name']} | "
            f"{row['indicator_type']} | "
            f"observations={count} | "
            f"distinct_indicators="
            f"{row['distinct_indicator_count']}"
        )

    if source_observation_sum != observation_total:
        raise RuntimeError(
            "Source indicator totals do not reconcile"
        )

    print("\n=== THREAT TYPE DISTRIBUTION ===")

    threat_rows = get_threat_type_distribution(conn)

    threat_sum = 0

    for row in threat_rows:
        count = row["observation_count"]
        threat_sum += count

        print(
            f"{row['source_name']} | "
            f"{row['threat_type']}: {count}"
        )

    if threat_sum != observation_total:
        raise RuntimeError(
            "Threat-type totals do not reconcile"
        )

    print("\n=== TOP MALWARE FAMILIES ===")

    for rank, row in enumerate(
        get_top_malware_families(conn),
        start=1,
    ):
        print(
            f"{rank}. {row['malware_family']} | "
            f"observations={row['observation_count']} | "
            f"distinct_indicators="
            f"{row['distinct_indicators']}"
        )

    print("\n=== MALWARE METADATA COVERAGE ===")

    coverage_rows = get_malware_coverage_by_source(conn)

    coverage_total = 0

    for row in coverage_rows:
        total = row["total_observations"]
        present = row["with_malware_family"]
        missing = row["without_malware_family"]

        coverage_total += total

        if present + missing != total:
            raise RuntimeError(
                "Malware metadata counts do not reconcile"
            )

        print(
            f"{row['source_name']}: "
            f"total={total}, "
            f"with_family={present}, "
            f"without_family={missing}, "
            f"coverage={percentage(present, total)}%"
        )

    if coverage_total != observation_total:
        raise RuntimeError(
            "Source coverage totals do not reconcile"
        )

    print("\n=== ANALYSIS COMPLETE ===")
    print("All distribution totals reconciled.")
    print("No PostgreSQL records were modified.")
    print("No raw IOC values or credentials displayed.")
    print(
        "Interpretation: Counts reflect collected "
        "provider observations, not global attack rates."
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
        # Avoid printing database errors that might
        # contain credentials or indicator values.
        print(
            "Indicator analysis failed: "
            f"{type(exc).__name__}"
        )

        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
