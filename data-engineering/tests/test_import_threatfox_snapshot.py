
"""
ThreatForge - ThreatFox Snapshot Import Tests

Tests:
- Snapshot integrity
- Checkpoint creation and recovery
- Checkpoint incompatibility
- Concurrent-import locking
- Lock release
- Failed batch recovery
- Dry-run database safety

All tests use temporary files and mocked database
operations. No live API requests or PostgreSQL writes.
"""

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import import_threatfox_snapshot as importer  # noqa: E402


SNAPSHOT_NAME = "threatfox_20261109T190721711257Z.json"


@pytest.fixture
def isolated_runtime(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    checkpoints = tmp_path / "checkpoints"

    snapshots.mkdir()

    monkeypatch.setattr(importer, "SNAPSHOT_DIR", snapshots)
    monkeypatch.setattr(importer, "CHECKPOINT_DIR", checkpoints)

    return snapshots, checkpoints


def create_snapshot(directory, count=5):
    payload = {
        "source": "ThreatFox",
        "record_count": count,
        "records": [
            {"id": index + 1}
            for index in range(count)
        ],
    }

    path = directory / SNAPSHOT_NAME
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_snapshot_and_fingerprint(isolated_runtime):
    snapshots, _ = isolated_runtime
    path = create_snapshot(snapshots)

    records, digest = importer.load_snapshot(SNAPSHOT_NAME)

    assert len(records) == 5
    assert len({str(r["id"]) for r in records}) == 5
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()


def test_duplicate_source_ids_rejected(isolated_runtime):
    snapshots, _ = isolated_runtime
    path = create_snapshot(snapshots)

    payload = json.loads(path.read_text())
    payload["records"][1]["id"] = payload["records"][0]["id"]

    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate"):
        importer.load_snapshot(SNAPSHOT_NAME)


def test_checkpoint_round_trip(isolated_runtime):
    _, _ = isolated_runtime
    path = importer.checkpoint_path(SNAPSHOT_NAME)

    importer.save_checkpoint(
        path, "test-digest", 500, 10380, 1500
    )

    offset = importer.load_checkpoint(
        path, "test-digest", 500, 10380
    )

    assert offset == 1500


def test_missing_checkpoint_starts_at_zero(isolated_runtime):
    path = importer.checkpoint_path(SNAPSHOT_NAME)

    assert importer.load_checkpoint(
        path, "test-digest", 500, 10380
    ) == 0


@pytest.mark.parametrize(
    "digest,batch_size,total",
    [
        ("different-digest", 500, 10380),
        ("test-digest", 1000, 10380),
        ("test-digest", 500, 9999),
    ],
)
def test_checkpoint_incompatibility(
    isolated_runtime, digest, batch_size, total
):
    path = importer.checkpoint_path(SNAPSHOT_NAME)

    importer.save_checkpoint(
        path, "test-digest", 500, 10380, 1500
    )

    with pytest.raises(ValueError):
        importer.load_checkpoint(
            path, digest, batch_size, total
        )


def test_snapshot_lock_blocks_second_import(isolated_runtime):
    first = importer.acquire_snapshot_lock(SNAPSHOT_NAME)

    try:
        with pytest.raises(RuntimeError, match="already importing"):
            importer.acquire_snapshot_lock(SNAPSHOT_NAME)
    finally:
        importer.release_snapshot_lock(first)


def test_snapshot_lock_can_be_reacquired(isolated_runtime):
    first = importer.acquire_snapshot_lock(SNAPSHOT_NAME)
    importer.release_snapshot_lock(first)

    second = importer.acquire_snapshot_lock(SNAPSHOT_NAME)
    importer.release_snapshot_lock(second)


def test_failed_batch_does_not_advance_checkpoint(
    isolated_runtime, monkeypatch
):
    snapshots, _ = isolated_runtime
    create_snapshot(snapshots, count=5)

    monkeypatch.setattr(
        importer,
        "parse_arguments",
        lambda: SimpleNamespace(
            snapshot=SNAPSHOT_NAME,
            batch_size=2,
            max_batches=1,
            execute=True,
        ),
    )

    engine = SimpleNamespace(dispose=lambda: None)

    monkeypatch.setattr(
        importer, "create_verified_engine", lambda: engine
    )
    monkeypatch.setattr(
        importer, "process_batch", lambda *args: False
    )

    assert importer.main() == 2

    path = importer.checkpoint_path(SNAPSHOT_NAME)
    assert not path.exists()

    monkeypatch.setattr(
        importer, "process_batch", lambda *args: True
    )

    assert importer.main() == 0

    records, digest = importer.load_snapshot(SNAPSHOT_NAME)

    assert importer.load_checkpoint(
        path, digest, 2, len(records)
    ) == 2


def test_dry_run_never_connects_to_database(
    isolated_runtime, monkeypatch
):
    snapshots, _ = isolated_runtime
    create_snapshot(snapshots, count=5)

    monkeypatch.setattr(
        importer,
        "parse_arguments",
        lambda: SimpleNamespace(
            snapshot=SNAPSHOT_NAME,
            batch_size=2,
            max_batches=1,
            execute=False,
        ),
    )

    def forbidden_connection():
        raise AssertionError("Dry run opened PostgreSQL")

    monkeypatch.setattr(
        importer,
        "create_verified_engine",
        forbidden_connection,
    )
    monkeypatch.setattr(
        importer,
        "process_batch",
        lambda records, engine, execute: (
            engine is None and execute is False
        ),
    )

    assert importer.main() == 0

    checkpoint = importer.checkpoint_path(SNAPSHOT_NAME)
    assert not checkpoint.exists()
