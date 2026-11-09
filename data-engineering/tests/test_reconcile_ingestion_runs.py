
"""
ThreatForge - Ingestion Run Reconciliation Tests

Tests manual recovery safeguards using mocked database
connections and an isolated lock directory.

No live database writes or external API calls.
"""

import fcntl
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import reconcile_ingestion_runs as recovery  # noqa: E402


@pytest.fixture
def isolated_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(recovery, "RUNTIME_DIR", tmp_path)
    monkeypatch.setattr(
        recovery,
        "LOCK_FILE",
        tmp_path / "ingestion.lock",
    )


def mock_engine(update_result=None):
    connection = MagicMock()
    connection.execute.return_value.scalar_one_or_none.return_value = (
        update_result
    )

    engine = MagicMock()
    engine.begin.return_value.__enter__.return_value = connection

    return engine, connection


def test_default_mode_is_read_only(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconcile"],
    )

    args = recovery.parse_arguments()

    assert args.apply is False
    assert args.run_id is None


def test_apply_requires_explicit_run_id(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconcile", "--apply"],
    )

    with pytest.raises(SystemExit):
        recovery.parse_arguments()


def test_confirmation_must_match_run_id(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reconcile",
            "--run-id", "10",
            "--apply",
            "--confirm-run-id", "11",
        ],
    )

    with pytest.raises(SystemExit):
        recovery.parse_arguments()


def test_valid_explicit_confirmation(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reconcile",
            "--run-id", "10",
            "--apply",
            "--confirm-run-id", "10",
        ],
    )

    args = recovery.parse_arguments()

    assert args.apply is True
    assert args.run_id == 10


def test_recovery_rejects_locked_runner(
    isolated_runtime,
):
    engine, connection = mock_engine(update_result=10)

    recovery.LOCK_FILE.touch()

    with recovery.LOCK_FILE.open("a+") as lock:
        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )

        try:
            result = recovery.reconcile_run(
                engine,
                run_id=10,
            )

            assert result == 2
            connection.execute.assert_not_called()

        finally:
            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_UN,
            )


def test_ineligible_run_is_not_changed(
    isolated_runtime,
):
    engine, connection = mock_engine(
        update_result=None
    )

    result = recovery.reconcile_run(
        engine,
        run_id=10,
    )

    assert result == 2
    connection.execute.assert_called_once()


def test_recovery_targets_exact_running_stale_run(
    isolated_runtime,
):
    engine, connection = mock_engine(
        update_result=10
    )

    result = recovery.reconcile_run(
        engine,
        run_id=10,
    )

    assert result == 0

    query = connection.execute.call_args.args[0]
    parameters = connection.execute.call_args.args[1]

    assert "WHERE id = :run_id" in query.text
    assert "status = 'running'" in query.text
    assert "INTERVAL '15 minutes'" in query.text
    assert "status = 'failed'" in query.text

    assert parameters == {"run_id": 10}

    assert "DELETE" not in query.text.upper()


def test_lock_released_after_reconciliation(
    isolated_runtime,
):
    engine, _ = mock_engine(
        update_result=10
    )

    assert recovery.reconcile_run(engine, 10) == 0
    assert recovery.reconcile_run(engine, 10) == 0
