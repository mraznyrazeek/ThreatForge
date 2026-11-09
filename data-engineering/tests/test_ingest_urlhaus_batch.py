
"""
Tests for controlled URLhaus batch ingestion.

All provider responses and database operations are mocked.
No network requests or PostgreSQL writes occur.
"""

import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest


SRC_DIR = Path(__file__).resolve().parents[1] / "src"

sys.path.insert(0, str(SRC_DIR / "processing"))

import ingest_urlhaus_batch as pipeline  # noqa: E402


def test_collect_batch_selects_requested_limit(monkeypatch):
    records = [{"id": index} for index in range(20)]

    monkeypatch.setattr(
        pipeline,
        "load_configuration",
        lambda: ("test-key", "https://example.invalid"),
    )

    monkeypatch.setattr(
        pipeline,
        "fetch_recent_urls",
        lambda **kwargs: {
            "query_status": "ok",
            "urls": records,
        },
    )

    selected, available = pipeline.collect_batch(limit=5)

    assert available == 20
    assert len(selected) == 5
    assert selected == records[:5]


def test_collect_batch_rejects_bad_api_status(monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "load_configuration",
        lambda: ("test-key", "https://example.invalid"),
    )

    monkeypatch.setattr(
        pipeline,
        "fetch_recent_urls",
        lambda **kwargs: {
            "query_status": "error",
            "urls": [],
        },
    )

    with pytest.raises(ValueError):
        pipeline.collect_batch(limit=5)


def test_collect_batch_rejects_invalid_record_type(monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "load_configuration",
        lambda: ("test-key", "https://example.invalid"),
    )

    monkeypatch.setattr(
        pipeline,
        "fetch_recent_urls",
        lambda **kwargs: {
            "query_status": "ok",
            "urls": ["not-a-record"],
        },
    )

    with pytest.raises(ValueError):
        pipeline.collect_batch(limit=5)


def test_normalization_tracks_rejections_without_database():
    invalid_record = {
        "id": "test-record",
        "url": None,
        "date_added": None,
    }

    observations, counts = pipeline.normalize_batch(
        [invalid_record]
    )

    assert observations == []
    assert counts["normalized"] == 0
    assert counts["rejected"] == 1
    assert counts["rejections_recorded"] == 0


def test_normalization_requires_complete_tracking_arguments():
    with pytest.raises(ValueError):
        pipeline.normalize_batch(
            [],
            engine=object(),
            source_id=1,
        )


def test_rejected_record_uses_sanitized_reason(monkeypatch):
    recorded = []

    monkeypatch.setattr(
        pipeline,
        "normalize_records",
        lambda records: ([], {}),
    )

    monkeypatch.setattr(
        pipeline,
        "persist_rejected_record",
        lambda *args, **kwargs: recorded.append(kwargs),
    )

    observations, counts = pipeline.normalize_batch(
        [{"url": "invalid-test-data"}],
        engine=object(),
        source_id=1,
        ingestion_run_id=2,
    )

    assert observations == []
    assert counts["rejected"] == 1
    assert counts["rejections_recorded"] == 1

    assert len(recorded) == 1
    assert recorded[0]["rejection_category"] == (
        "normalization_failure"
    )
    assert recorded[0]["reason_code"] == "validation_failed"

    assert "raw_payload" not in recorded[0]
    assert "url" not in recorded[0]


def test_dry_run_does_not_create_database_engine(monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "parse_arguments",
        lambda: SimpleNamespace(
            limit=5,
            execute=False,
        ),
    )

    monkeypatch.setattr(
        pipeline,
        "collect_batch",
        lambda limit: ([{"id": "1"}], 1000),
    )

    monkeypatch.setattr(
        pipeline,
        "normalize_batch",
        lambda *args, **kwargs: (
            [object()],
            Counter({
                "normalized": 1,
                "rejected": 0,
                "rejections_recorded": 0,
            }),
        ),
    )

    def unexpected_database_connection():
        raise AssertionError(
            "Dry run must not connect to PostgreSQL"
        )

    monkeypatch.setattr(
        pipeline,
        "create_verified_engine",
        unexpected_database_connection,
    )

    assert pipeline.main() == 0
