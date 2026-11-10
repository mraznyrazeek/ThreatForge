
"""
ThreatForge - M6.4 Unified Intelligence Analytics Service

Combines the existing M6 analytics modules into one
structured, JSON-compatible result.

Includes:
- Dataset summary
- Source coverage
- Canonical indicator distribution
- Indicator distribution by source
- Threat-type distribution
- Top malware-family labels
- Malware metadata coverage
- Daily first-seen observations (UTC)
- Timestamp quality
- Valid observation interval statistics
- Cross-source overlap
- Same-source repeated indicators
- Data-quality metrics

Safety:
- Verified development database only
- Repeatable-read, read-only PostgreSQL transaction
- Aggregated analytics only; no raw IOC values
- No database writes or external API requests

Run from data-engineering.
"""

import argparse
import json
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import text

from analyze_indicator_distribution import (
    create_analytics_engine,
    get_total_counts,
    get_global_indicator_distribution,
    get_source_indicator_distribution,
    get_threat_type_distribution,
    get_top_malware_families,
    get_malware_coverage_by_source,
)

from analyze_temporal_intelligence import (
    get_source_totals,
    get_daily_first_seen,
    get_timestamp_quality,
    get_valid_interval_statistics,
    get_cross_source_overlaps,
    get_repeated_source_indicators,
)

from profile_intelligence_database import (
    get_data_quality,
    get_indicator_overlap,
    get_integrity_checks,
)


SERVICE_VERSION = "1.0"
MAX_TOP_FAMILIES = 100


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ThreatForge unified analytics service"
    )

    parser.add_argument(
        "--top-families",
        type=int,
        default=15,
        help="Number of malware-family labels (1-100)",
    )

    args = parser.parse_args()

    validate_top_families(args.top_families)

    return args


def validate_top_families(value):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_TOP_FAMILIES
    ):
        raise ValueError(
            "top_families must be an integer between 1 and 100"
        )

    return value


def json_safe(value):
    """
    Convert database results into JSON-compatible values.

    All timestamps and dates become ISO-8601 strings.
    Decimals are converted to JSON numbers.
    """

    if isinstance(value, Decimal):
        return float(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            json_safe(item)
            for item in value
        ]

    return value


def convert_rows(rows):
    """Convert SQLAlchemy mappings to ordinary dictionaries."""

    return [
        json_safe(dict(row))
        for row in rows
    ]


def require_equal(actual, expected, description):
    """
    Reject inconsistent aggregates rather than returning
    misleading analytics to downstream applications.
    """

    if actual != expected:
        raise RuntimeError(
            f"Analytics reconciliation failed: {description}"
        )


def build_analytics(conn, top_families=15):
    """
    Construct a dashboard-ready analytics result.

    The caller must supply a connection already inside
    a read-only, consistent PostgreSQL transaction.
    """

    validate_top_families(top_families)

    # -----------------------------------------------------
    # Dataset totals
    # -----------------------------------------------------

    totals = dict(get_total_counts(conn))

    canonical_count = totals["canonical_indicators"]
    observation_count = totals["source_observations"]

    source_totals = convert_rows(
        get_source_totals(conn)
    )

    require_equal(
        sum(
            row["observation_count"]
            for row in source_totals
        ),
        observation_count,
        "source observation totals",
    )

    # -----------------------------------------------------
    # Indicator analytics
    # -----------------------------------------------------

    global_indicators = convert_rows(
        get_global_indicator_distribution(conn)
    )

    require_equal(
        sum(
            row["indicator_count"]
            for row in global_indicators
        ),
        canonical_count,
        "canonical indicator distribution",
    )

    source_indicators = convert_rows(
        get_source_indicator_distribution(conn)
    )

    require_equal(
        sum(
            row["observation_count"]
            for row in source_indicators
        ),
        observation_count,
        "source indicator distribution",
    )

    threat_types = convert_rows(
        get_threat_type_distribution(conn)
    )

    require_equal(
        sum(
            row["observation_count"]
            for row in threat_types
        ),
        observation_count,
        "threat-type distribution",
    )

    malware_families = convert_rows(
        get_top_malware_families(
            conn,
            limit=top_families,
        )
    )

    malware_coverage = convert_rows(
        get_malware_coverage_by_source(conn)
    )

    for row in malware_coverage:
        require_equal(
            (
                row["with_malware_family"]
                + row["without_malware_family"]
            ),
            row["total_observations"],
            "malware-family coverage",
        )

    require_equal(
        sum(
            row["total_observations"]
            for row in malware_coverage
        ),
        observation_count,
        "total malware metadata coverage",
    )

    # -----------------------------------------------------
    # Temporal analytics
    # -----------------------------------------------------

    daily_activity = convert_rows(
        get_daily_first_seen(conn)
    )

    timestamp_quality = convert_rows(
        get_timestamp_quality(conn)
    )

    intervals = convert_rows(
        get_valid_interval_statistics(conn)
    )

    source_counts = {
        row["source_name"]: row["observation_count"]
        for row in source_totals
    }

    for description, rows, count_field in (
        (
            "daily first-seen activity",
            daily_activity,
            "observation_count",
        ),
        (
            "timestamp-quality distribution",
            timestamp_quality,
            "observation_count",
        ),
    ):
        for source, expected in source_counts.items():
            actual = sum(
                row[count_field]
                for row in rows
                if row["source_name"] == source
            )

            require_equal(
                actual,
                expected,
                f"{description}: {source}",
            )

    for row in intervals:
        require_equal(
            (
                row["valid_intervals"]
                + row["missing_last_seen"]
                + row["reversed_intervals"]
            ),
            row["total_observations"],
            "interval completeness",
        )

        require_equal(
            row["total_observations"],
            source_counts[row["source_name"]],
            "source interval total",
        )

    # -----------------------------------------------------
    # Correlation analytics
    # -----------------------------------------------------

    shared_indicator_count = get_indicator_overlap(conn)

    overlaps = convert_rows(
        get_cross_source_overlaps(conn)
    )

    repeated = convert_rows(
        get_repeated_source_indicators(conn)
    )

    # With exactly two source records registered,
    # there is only one possible source pair.
    if len(source_totals) == 2:
        require_equal(
            sum(
                row["shared_indicators"]
                for row in overlaps
            ),
            shared_indicator_count,
            "cross-source overlap",
        )

    # -----------------------------------------------------
    # Data quality
    # -----------------------------------------------------

    quality = json_safe(
        dict(get_data_quality(conn))
    )

    integrity = json_safe(
        dict(get_integrity_checks(conn))
    )

    require_equal(
        quality["total"],
        observation_count,
        "data-quality observation total",
    )

    require_equal(
        (
            quality["zero_confidence_count"]
            + quality["positive_confidence_count"]
        ),
        observation_count,
        "confidence coverage",
    )

    require_equal(
        sum(
            row["missing_last_seen"]
            for row in intervals
        ),
        quality["missing_last_seen"],
        "missing last-seen coverage",
    )

    require_equal(
        sum(
            row["reversed_intervals"]
            for row in intervals
        ),
        quality["reversed_timestamps"],
        "reversed timestamp coverage",
    )

    require_equal(
        integrity["missing_indicator_links"],
        0,
        "indicator relationships",
    )

    require_equal(
        integrity["missing_source_links"],
        0,
        "source relationships",
    )

    # -----------------------------------------------------
    # Final structured result
    # -----------------------------------------------------

    return {
        "schema_version": SERVICE_VERSION,

        "dataset": {
            "canonical_indicators": canonical_count,
            "source_observations": observation_count,
            "source_count": len(source_totals),
        },

        "sources": source_totals,

        "indicators": {
            "global_distribution": global_indicators,
            "by_source": source_indicators,
        },

        "threats": {
            "type_distribution": threat_types,
            "top_malware_families": malware_families,
            "malware_metadata_coverage": malware_coverage,
        },

        "temporal": {
            "timezone": "UTC",
            "daily_first_seen": daily_activity,
            "timestamp_quality": timestamp_quality,
            "observation_intervals": intervals,
        },

        "correlation": {
            "shared_canonical_indicators": (
                shared_indicator_count
            ),
            "source_pair_overlaps": overlaps,
            "repeated_source_indicators": repeated,
        },

        "data_quality": {
            "completeness": quality,
            "referential_integrity": integrity,
        },

        "interpretation": {
            "scope": "Collected provider intelligence",
            "first_seen": (
                "Provider-reported first-seen dates, "
                "not attack counts"
            ),
            "intervals": (
                "Observation intervals are not "
                "infection durations"
            ),
            "confidence": (
                "URLhaus confidence=0 represents "
                "unrated intelligence"
            ),
            "malware": (
                "Malware-family labels reflect source "
                "reports, not verified infection counts"
            ),
        },
    }


def fetch_analytics(top_families=15):
    """
    Public entry point for the future backend API.

    Opens one consistent, read-only PostgreSQL
    transaction, builds the analytics, and returns
    ordinary JSON-compatible Python data.
    """

    validate_top_families(top_families)

    engine = None

    try:
        engine = create_analytics_engine()

        with engine.connect() as conn:
            conn.execute(
                text(
                    "SET TRANSACTION ISOLATION LEVEL "
                    "REPEATABLE READ READ ONLY"
                )
            )

            result = build_analytics(
                conn,
                top_families=top_families,
            )

            # All analytics are computed within the
            # same database snapshot.

            return json_safe(result)

    finally:
        if engine is not None:
            engine.dispose()


def main():
    try:
        args = parse_arguments()

        analytics = fetch_analytics(
            top_families=args.top_families
        )

        # Machine-readable output suitable for
        # downstream API development and validation.
        print(
            json.dumps(
                analytics,
                indent=2,
                allow_nan=False,
            )
        )

        return 0

    except Exception as exc:
        # Avoid printing connection strings, SQL
        # parameters or provider data on failure.
        print(
            "ThreatForge analytics service failed: "
            f"{type(exc).__name__}"
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
