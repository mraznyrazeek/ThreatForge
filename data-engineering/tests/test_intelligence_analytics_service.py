
"""
ThreatForge - M6.4 Unified Analytics Service Tests

Tests the unified JSON analytics contract using
deterministic synthetic data and mocked database calls.

No live API requests or PostgreSQL writes.
"""

import json
import sys
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import intelligence_analytics_service as service  # noqa: E402


@pytest.mark.parametrize(
    "value",
    [1, 15, 100],
)
def test_valid_top_family_limits(value):
    assert service.validate_top_families(value) == value


@pytest.mark.parametrize(
    "value",
    [0, -1, 101, True, 1.5, "15", None],
)
def test_invalid_top_family_limits(value):
    with pytest.raises(ValueError):
        service.validate_top_families(value)


def test_json_safe_serialization():
    payload = {
        "date": date(2026, 11, 9),
        "timestamp": datetime(
            2026, 11, 9, 18, 0,
            tzinfo=timezone.utc,
        ),
        "average": Decimal("30.09"),
        "values": [Decimal("2.5"), None],
    }

    converted = service.json_safe(payload)

    assert converted["date"] == "2026-11-09"
    assert converted["timestamp"] == "2026-11-09T18:00:00+00:00"
    assert converted["average"] == 30.09
    assert converted["values"] == [2.5, None]

    json.dumps(converted, allow_nan=False)


def test_convert_rows():
    rows = [
        {
            "first_seen_date": date(2026, 11, 9),
            "observation_count": 3,
        }
    ]

    result = service.convert_rows(rows)

    assert result == [
        {
            "first_seen_date": "2026-11-09",
            "observation_count": 3,
        }
    ]


def test_reconciliation_success():
    service.require_equal(10, 10, "test")


def test_reconciliation_failure():
    with pytest.raises(
        RuntimeError,
        match="reconciliation failed",
    ):
        service.require_equal(9, 10, "test")


@pytest.fixture
def mock_analytics(monkeypatch):
    """
    Four synthetic observations:
    ThreatFox: 3
    URLhaus: 1

    Three canonical indicators, one shared
    across the two sources.
    """

    data = {
        "source_totals": [
            {
                "source_id": 1,
                "source_name": "ThreatFox",
                "observation_count": 3,
            },
            {
                "source_id": 2,
                "source_name": "URLhaus",
                "observation_count": 1,
            },
        ],
        "global_indicators": [
            {
                "indicator_type": "domain",
                "indicator_count": 1,
            },
            {
                "indicator_type": "url",
                "indicator_count": 2,
            },
        ],
        "source_indicators": [
            {
                "source_name": "ThreatFox",
                "indicator_type": "domain",
                "observation_count": 1,
                "distinct_indicator_count": 1,
            },
            {
                "source_name": "ThreatFox",
                "indicator_type": "url",
                "observation_count": 2,
                "distinct_indicator_count": 2,
            },
            {
                "source_name": "URLhaus",
                "indicator_type": "url",
                "observation_count": 1,
                "distinct_indicator_count": 1,
            },
        ],
        "daily": [
            {
                "source_name": "ThreatFox",
                "first_seen_date": date(2026, 11, 8),
                "observation_count": 2,
                "distinct_indicator_count": 2,
            },
            {
                "source_name": "ThreatFox",
                "first_seen_date": date(2026, 11, 9),
                "observation_count": 1,
                "distinct_indicator_count": 1,
            },
            {
                "source_name": "URLhaus",
                "first_seen_date": date(2026, 11, 9),
                "observation_count": 1,
                "distinct_indicator_count": 1,
            },
        ],
        "intervals": [
            {
                "source_name": "ThreatFox",
                "total_observations": 3,
                "missing_last_seen": 1,
                "reversed_intervals": 0,
                "valid_intervals": 2,
                "avg_interval_hours": Decimal("12.50"),
            },
            {
                "source_name": "URLhaus",
                "total_observations": 1,
                "missing_last_seen": 1,
                "reversed_intervals": 0,
                "valid_intervals": 0,
                "avg_interval_hours": None,
            },
        ],
    }

    monkeypatch.setattr(
        service,
        "get_total_counts",
        lambda conn: {
            "canonical_indicators": 3,
            "source_observations": 4,
        },
    )

    monkeypatch.setattr(
        service,
        "get_source_totals",
        lambda conn: data["source_totals"],
    )

    monkeypatch.setattr(
        service,
        "get_global_indicator_distribution",
        lambda conn: data["global_indicators"],
    )

    monkeypatch.setattr(
        service,
        "get_source_indicator_distribution",
        lambda conn: data["source_indicators"],
    )

    monkeypatch.setattr(
        service,
        "get_threat_type_distribution",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "threat_type": "payload",
                "observation_count": 3,
            },
            {
                "source_name": "URLhaus",
                "threat_type": "malware_download",
                "observation_count": 1,
            },
        ],
    )

    monkeypatch.setattr(
        service,
        "get_top_malware_families",
        lambda conn, limit: [
            {
                "malware_family": "synthetic_test_family",
                "observation_count": 3,
                "distinct_indicators": 3,
            }
        ][:limit],
    )

    monkeypatch.setattr(
        service,
        "get_malware_coverage_by_source",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "total_observations": 3,
                "with_malware_family": 3,
                "without_malware_family": 0,
            },
            {
                "source_name": "URLhaus",
                "total_observations": 1,
                "with_malware_family": 0,
                "without_malware_family": 1,
            },
        ],
    )

    monkeypatch.setattr(
        service,
        "get_daily_first_seen",
        lambda conn: data["daily"],
    )

    monkeypatch.setattr(
        service,
        "get_timestamp_quality",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "timestamp_quality": "consistent",
                "observation_count": 2,
            },
            {
                "source_name": "ThreatFox",
                "timestamp_quality": "missing_last_seen",
                "observation_count": 1,
            },
            {
                "source_name": "URLhaus",
                "timestamp_quality": "missing_last_seen",
                "observation_count": 1,
            },
        ],
    )

    monkeypatch.setattr(
        service,
        "get_valid_interval_statistics",
        lambda conn: data["intervals"],
    )

    monkeypatch.setattr(
        service,
        "get_indicator_overlap",
        lambda conn: 1,
    )

    monkeypatch.setattr(
        service,
        "get_cross_source_overlaps",
        lambda conn: [
            {
                "first_source": "ThreatFox",
                "second_source": "URLhaus",
                "shared_indicators": 1,
            }
        ],
    )

    monkeypatch.setattr(
        service,
        "get_repeated_source_indicators",
        lambda conn: [],
    )

    monkeypatch.setattr(
        service,
        "get_data_quality",
        lambda conn: {
            "total": 4,
            "missing_last_seen": 2,
            "reversed_timestamps": 0,
            "zero_confidence_count": 1,
            "positive_confidence_count": 3,
        },
    )

    monkeypatch.setattr(
        service,
        "get_integrity_checks",
        lambda conn: {
            "missing_indicator_links": 0,
            "missing_source_links": 0,
        },
    )

    return data


def test_build_analytics_contract(mock_analytics):
    result = service.build_analytics(
        object(),
        top_families=15,
    )

    assert result["schema_version"] == "1.0"

    assert result["dataset"] == {
        "canonical_indicators": 3,
        "source_observations": 4,
        "source_count": 2,
    }

    assert result["correlation"][
        "shared_canonical_indicators"
    ] == 1

    assert len(
        result["threats"]["top_malware_families"]
    ) == 1

    assert result["temporal"]["timezone"] == "UTC"

    # The complete service output must serialize.
    json.dumps(result, allow_nan=False)


def test_source_total_mismatch_detected(
    mock_analytics,
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_total_counts",
        lambda conn: {
            "canonical_indicators": 3,
            "source_observations": 5,
        },
    )

    with pytest.raises(
        RuntimeError,
        match="source observation totals",
    ):
        service.build_analytics(object())


def test_daily_mismatch_detected(
    mock_analytics,
):
    mock_analytics["daily"][0][
        "observation_count"
    ] = 1

    with pytest.raises(
        RuntimeError,
        match="daily first-seen activity",
    ):
        service.build_analytics(object())


def test_interval_mismatch_detected(
    mock_analytics,
):
    mock_analytics["intervals"][0][
        "valid_intervals"
    ] = 1

    with pytest.raises(
        RuntimeError,
        match="interval completeness",
    ):
        service.build_analytics(object())


def test_fetch_analytics_uses_consistent_read_only_transaction(
    monkeypatch,
):
    executed = []

    class FakeConnection:
        def execute(self, statement):
            executed.append(str(statement))

    class FakeContext:
        def __enter__(self):
            return FakeConnection()

        def __exit__(self, *args):
            return False

    class FakeEngine:
        def connect(self):
            return FakeContext()

        def dispose(self):
            executed.append("DISPOSE")

    monkeypatch.setattr(
        service,
        "create_analytics_engine",
        lambda: FakeEngine(),
    )

    monkeypatch.setattr(
        service,
        "build_analytics",
        lambda conn, top_families: {
            "count": 4,
            "average": Decimal("12.50"),
        },
    )

    result = service.fetch_analytics()

    assert result == {
        "count": 4,
        "average": 12.5,
    }

    assert executed == [
        (
            "SET TRANSACTION ISOLATION LEVEL "
            "REPEATABLE READ READ ONLY"
        ),
        "DISPOSE",
    ]


def test_invalid_fetch_does_not_open_database(monkeypatch):
    def forbidden_connection():
        raise AssertionError(
            "Database connection should not open"
        )

    monkeypatch.setattr(
        service,
        "create_analytics_engine",
        forbidden_connection,
    )

    with pytest.raises(ValueError):
        service.fetch_analytics(top_families=0)
