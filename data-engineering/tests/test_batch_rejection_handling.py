
"""
ThreatForge - Batch Rejection Handling Tests

Tests:
1. Normalization rejects invalid records without database writes.
2. Execute-mode normalization stores sanitized rejection metadata.
3. Batch persistence records source-identity conflicts.

All external dependencies are mocked.
No API requests or real database writes are performed.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR / "processing"))

import ingest_threatfox_batch as batch  # noqa: E402


def test_dry_run_rejection_does_not_write(monkeypatch):
    """Rejected records in dry-run mode must not be persisted."""

    record = {"invalid": True}

    monkeypatch.setattr(
        batch,
        "normalize_records",
        lambda records: ([], {"failure_types": {}}),
    )

    save_rejection = Mock()

    monkeypatch.setattr(
        batch,
        "persist_rejected_record",
        save_rejection,
    )

    observations, counts = batch.normalize_batch([record])

    assert observations == []
    assert counts["normalized"] == 0
    assert counts["rejected"] == 1
    assert counts["rejections_recorded"] == 0

    save_rejection.assert_not_called()


def test_normalization_rejection_is_recorded(monkeypatch):
    """An active run must receive a sanitized rejection record."""

    fake_engine = object()

    monkeypatch.setattr(
        batch,
        "normalize_records",
        lambda records: ([], {"failure_types": {}}),
    )

    save_rejection = Mock()

    monkeypatch.setattr(
        batch,
        "persist_rejected_record",
        save_rejection,
    )

    observations, counts = batch.normalize_batch(
        [{"secret": "never-store-this"}],
        engine=fake_engine,
        source_id=12,
        ingestion_run_id=34,
    )

    assert observations == []
    assert counts["rejected"] == 1
    assert counts["rejections_recorded"] == 1

    save_rejection.assert_called_once_with(
        fake_engine,
        source_id=12,
        ingestion_run_id=34,
        rejection_category="normalization_failure",
        reason_code="validation_failed",
    )


def test_identity_conflict_is_recorded(monkeypatch):
    """Persistence identity conflicts must create safe rejection metadata."""

    fake_engine = object()
    observation = SimpleNamespace(source_record_id="synthetic")

    monkeypatch.setattr(
        batch,
        "persist_observation",
        Mock(side_effect=ValueError("identity conflict")),
    )

    monkeypatch.setattr(
        batch,
        "get_run_source_id",
        Mock(return_value=12),
    )

    save_rejection = Mock()

    monkeypatch.setattr(
        batch,
        "persist_rejected_record",
        save_rejection,
    )

    counts = batch.persist_batch(
        engine=fake_engine,
        observations=[observation],
        ingestion_run_id=34,
    )

    assert counts["inserted"] == 0
    assert counts["identity_conflicts"] == 1
    assert counts["database_failures"] == 0
    assert counts["rejections_recorded"] == 1

    save_rejection.assert_called_once_with(
        fake_engine,
        source_id=12,
        ingestion_run_id=34,
        rejection_category="identity_conflict",
        reason_code="source_identity_conflict",
    )


def test_partial_tracking_arguments_rejected():
    """Tracking arguments must be supplied together."""

    with pytest.raises(
        ValueError,
        match="requires engine",
    ):
        batch.normalize_batch(
            [],
            source_id=12,
        )
