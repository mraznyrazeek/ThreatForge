
"""
ThreatForge - Bulk Intelligence Ingestion Tests

Tests bulk collection, validation, and dry-run safety.

No real API calls or PostgreSQL writes.
"""

import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import ingest_bulk_intelligence as bulk  # noqa: E402


def test_default_arguments(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["bulk", "--source", "threatfox"],
    )

    args = bulk.parse_arguments()

    assert args.source == "threatfox"
    assert args.limit == 500
    assert args.days == 7
    assert args.execute is False


@pytest.mark.parametrize("limit", [0, -1, 1001])
def test_invalid_batch_limits(monkeypatch, limit):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bulk",
            "--source", "urlhaus",
            "--limit", str(limit),
        ],
    )

    with pytest.raises(SystemExit):
        bulk.parse_arguments()


@pytest.mark.parametrize("days", [0, 8])
def test_invalid_threatfox_lookback(monkeypatch, days):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bulk",
            "--source", "threatfox",
            "--days", str(days),
        ],
    )

    with pytest.raises(SystemExit):
        bulk.parse_arguments()


def test_threatfox_collection_limit(monkeypatch):
    records = [
        {"id": index}
        for index in range(1200)
    ]

    monkeypatch.setattr(
        bulk,
        "load_threatfox",
        lambda: ("test-key", "https://example.invalid"),
    )

    monkeypatch.setattr(
        bulk,
        "fetch_recent_iocs",
        lambda **kwargs: {
            "query_status": "ok",
            "data": records,
        },
    )

    selected, available = bulk.collect_records(
        source="threatfox",
        limit=500,
        days=7,
    )

    assert available == 1200
    assert len(selected) == 500


def test_urlhaus_collection_limit(monkeypatch):
    records = [
        {"id": index}
        for index in range(1000)
    ]

    monkeypatch.setattr(
        bulk,
        "load_urlhaus",
        lambda: ("test-key", "https://example.invalid"),
    )

    monkeypatch.setattr(
        bulk,
        "fetch_recent_urls",
        lambda **kwargs: {
            "query_status": "ok",
            "urls": records,
        },
    )

    selected, available = bulk.collect_records(
        source="urlhaus",
        limit=500,
        days=7,
    )

    assert available == 1000
    assert len(selected) == 500


def test_non_ok_response_rejected(monkeypatch):
    monkeypatch.setattr(
        bulk,
        "load_threatfox",
        lambda: ("test-key", "https://example.invalid"),
    )

    monkeypatch.setattr(
        bulk,
        "fetch_recent_iocs",
        lambda **kwargs: {
            "query_status": "error",
            "data": [],
        },
    )

    with pytest.raises(ValueError):
        bulk.collect_records(
            source="threatfox",
            limit=100,
            days=7,
        )


def test_dry_run_never_connects_to_database(monkeypatch):
    monkeypatch.setattr(
        bulk,
        "parse_arguments",
        lambda: SimpleNamespace(
            source="urlhaus",
            limit=100,
            days=7,
            execute=False,
        ),
    )

    monkeypatch.setattr(
        bulk,
        "collect_records",
        lambda *args: ([{"id": "1"}], 1000),
    )

    monkeypatch.setattr(
        bulk,
        "normalize_selected_records",
        lambda **kwargs: (
            [object()],
            Counter({
                "normalized": 1,
                "rejected": 0,
                "rejections_recorded": 0,
            }),
        ),
    )

    def unexpected_connection():
        raise AssertionError(
            "Dry run must not connect to PostgreSQL"
        )

    monkeypatch.setattr(
        bulk,
        "create_verified_engine",
        unexpected_connection,
    )

    assert bulk.main() == 0
