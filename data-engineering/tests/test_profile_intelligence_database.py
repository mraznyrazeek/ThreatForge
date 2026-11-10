
"""
ThreatForge - M6.1 Database Profiling Tests

Tests:
- Approved table names
- Read-only database access requirement
- Expected database selection
- Cross-source overlap query
- Same-source repeated indicator query
- Safe timestamp formatting
- Report aggregation using mocked query results

No live PostgreSQL writes or external API requests.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy.sql import text

PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import profile_intelligence_database as profile  # noqa: E402


def test_expected_tables():
    assert set(profile.TABLE_NAMES) == {
        "intelligence_sources",
        "threat_indicators",
        "indicator_observations",
        "observation_history",
        "ingestion_runs",
        "rejected_records",
    }


def test_wrong_database_rejected(monkeypatch):
    monkeypatch.setenv(
        "DB_NAME",
        "threatforge_test_db",
    )

    with pytest.raises(RuntimeError):
        profile.create_read_only_engine()


def test_missing_database_rejected(monkeypatch):
    monkeypatch.delenv("DB_NAME", raising=False)

    with pytest.raises(RuntimeError):
        profile.create_read_only_engine()


def test_table_counts(monkeypatch):
    expected = {
        name: index + 1
        for index, name in enumerate(profile.TABLE_NAMES)
    }

    class FakeResult:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

    class FakeConnection:
        def execute(self, statement):
            sql = str(statement)

            for name, count in expected.items():
                if sql.strip() == (
                    f"SELECT COUNT(*) FROM public.{name}"
                ):
                    return FakeResult(count)

            raise AssertionError("Unexpected SQL query")

    assert profile.get_table_counts(
        FakeConnection()
    ) == expected


def test_cross_source_overlap_query():
    class FakeResult:
        def scalar_one(self):
            return 2

    class FakeConnection:
        def execute(self, statement):
            sql = str(statement)

            assert "COUNT(DISTINCT source_id) > 1" in sql
            assert "AS shared_indicators" in sql
            return FakeResult()

    assert profile.get_indicator_overlap(
        FakeConnection()
    ) == 2


def test_repeated_source_indicator_query():
    class FakeResult:
        def mappings(self):
            return self

        def one(self):
            return {
                "repeated_source_indicator_pairs": 4,
                "additional_observations": 4,
            }

    class FakeConnection:
        def execute(self, statement):
            sql = str(statement)

            assert "GROUP BY" in sql
            assert "source_id" in sql
            assert "indicator_id" in sql
            assert "HAVING COUNT(*) > 1" in sql

            return FakeResult()

    result = profile.get_repeated_source_indicators(
        FakeConnection()
    )

    assert result["repeated_source_indicator_pairs"] == 4
    assert result["additional_observations"] == 4


def test_missing_timestamp_format():
    assert profile.format_timestamp(None) == "N/A"


def test_timestamp_format():
    from datetime import datetime, timezone

    value = datetime(
        2026, 11, 9, 18, 0, tzinfo=timezone.utc
    )

    assert profile.format_timestamp(
        value
    ) == "2026-11-09T18:00:00+00:00"


def test_main_uses_read_only_transaction(monkeypatch):
    executed_sql = []

    class FakeConnection:
        def execute(self, statement):
            executed_sql.append(str(statement))

    class ConnectionContext:
        def __enter__(self):
            return FakeConnection()

        def __exit__(self, *args):
            return False

    class FakeEngine:
        def __init__(self):
            self.disposed = False

        def connect(self):
            return ConnectionContext()

        def dispose(self):
            self.disposed = True

    engine = FakeEngine()

    monkeypatch.setattr(
        profile,
        "create_read_only_engine",
        lambda: engine,
    )

    monkeypatch.setattr(
        profile,
        "print_report",
        lambda conn: executed_sql.append(
            "REPORT_EXECUTED"
        ),
    )

    assert profile.main() == 0

    assert executed_sql == [
        "SET TRANSACTION READ ONLY",
        "REPORT_EXECUTED",
    ]

    assert engine.disposed is True
