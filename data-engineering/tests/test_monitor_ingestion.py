
"""
ThreatForge - Ingestion Monitoring Tests

Tests operational monitoring with mocked database results.

No network calls, PostgreSQL writes, or live credentials.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import monitor_ingestion as monitor  # noqa: E402


def create_mock_engine(
    database="threatforge_db",
    sources=None,
    statuses=None,
    recent=None,
):
    """Build a mocked database engine for monitoring."""

    sources = sources if sources is not None else [
        {"name": "ThreatFox", "observation_count": 45},
        {"name": "URLhaus", "observation_count": 5},
    ]

    statuses = statuses if statuses is not None else [
        {
            "name": "ThreatFox",
            "status": "completed",
            "run_count": 2,
        },
        {
            "name": "URLhaus",
            "status": "completed",
            "run_count": 1,
        },
    ]

    recent = recent if recent is not None else [
        {
            "id": 3,
            "source_name": "URLhaus",
            "status": "completed",
            "records_received": 5,
            "records_normalized": 5,
            "records_rejected": 0,
            "potentially_stale": False,
        },
    ]

    connection = MagicMock()

    results = [
        MagicMock(),  # SET TRANSACTION READ ONLY
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    ]

    results[1].scalar_one.return_value = database
    results[2].mappings.return_value.all.return_value = sources
    results[3].mappings.return_value.all.return_value = statuses
    results[4].mappings.return_value.all.return_value = recent

    connection.execute.side_effect = results

    engine = MagicMock()
    engine.connect.return_value.__enter__.return_value = connection

    return engine, connection


def test_monitor_reports_sources(capsys):
    engine, _ = create_mock_engine()

    monitor.monitor(engine)

    output = capsys.readouterr().out

    assert "ThreatFox: 45" in output
    assert "URLhaus: 5" in output


def test_monitor_reports_ingestion_status(capsys):
    engine, _ = create_mock_engine()

    monitor.monitor(engine)

    output = capsys.readouterr().out

    assert "ThreatFox | completed: 2" in output
    assert "URLhaus | completed: 1" in output


def test_monitor_reports_recent_run(capsys):
    engine, _ = create_mock_engine()

    monitor.monitor(engine)

    output = capsys.readouterr().out

    assert "Run #3 | URLhaus | completed" in output
    assert "received=5" in output
    assert "rejected=0" in output


def test_monitor_uses_read_only_transaction():
    engine, connection = create_mock_engine()

    monitor.monitor(engine)

    first_query = connection.execute.call_args_list[0].args[0]

    assert "SET TRANSACTION READ ONLY" in first_query.text


def test_monitor_rejects_unexpected_database():
    engine, _ = create_mock_engine(
        database="unexpected_database"
    )

    with pytest.raises(ValueError):
        monitor.monitor(engine)


def test_monitor_flags_stale_runs(capsys):
    stale_run = {
        "id": 9,
        "source_name": "ThreatFox",
        "status": "running",
        "records_received": 0,
        "records_normalized": 0,
        "records_rejected": 0,
        "potentially_stale": True,
    }

    engine, _ = create_mock_engine(
        recent=[stale_run]
    )

    monitor.monitor(engine)

    output = capsys.readouterr().out

    assert "WARNING" in output
    assert "Run #9" in output


def test_monitor_handles_empty_results(capsys):
    engine, _ = create_mock_engine(
        sources=[],
        statuses=[],
        recent=[],
    )

    monitor.monitor(engine)

    output = capsys.readouterr().out

    assert "Monitoring completed (read-only)." in output


def test_main_disposes_engine(monkeypatch):
    engine, _ = create_mock_engine()

    monkeypatch.setattr(
        monitor,
        "create_monitoring_engine",
        lambda: engine,
    )

    assert monitor.main() == 0

    engine.dispose.assert_called_once()


def test_main_handles_database_failure(monkeypatch, capsys):
    def failing_engine():
        raise RuntimeError("Synthetic database failure")

    monkeypatch.setattr(
        monitor,
        "create_monitoring_engine",
        failing_engine,
    )

    assert monitor.main() == 1

    output = capsys.readouterr().out

    assert "Monitoring failed: RuntimeError" in output
    assert "Synthetic database failure" not in output
