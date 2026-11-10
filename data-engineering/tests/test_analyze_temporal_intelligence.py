
"""
ThreatForge - M6.3 Temporal Intelligence Tests

Validates:
- Database selection safety
- UTC daily aggregation
- Timestamp quality aggregation
- Valid interval filtering
- Cross-source correlation
- Same-source repeated indicators
- Source totals
- Reconciliation checks
- Read-only transaction enforcement

Uses mocks only; no live database modifications.
"""

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

import analyze_temporal_intelligence as temporal  # noqa: E402


class FakeResult:
    """Minimal SQLAlchemy-style result object."""

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []

    def mappings(self):
        return self

    def all(self):
        return self.rows


class FakeConnection:
    """Capture SQL without opening PostgreSQL."""

    def __init__(self, rows=None):
        self.statements = []
        self.rows = rows

    def execute(self, statement):
        self.statements.append(str(statement))
        return FakeResult(self.rows)


@pytest.mark.parametrize(
    "database",
    [
        "threatforge_test_db",
        "postgres",
        "other_database",
    ],
)
def test_wrong_database_rejected(monkeypatch, database):
    monkeypatch.setenv("DB_NAME", database)

    with pytest.raises(RuntimeError):
        temporal.create_analytics_engine()


def test_missing_database_rejected(monkeypatch):
    monkeypatch.delenv("DB_NAME", raising=False)

    with pytest.raises(RuntimeError):
        temporal.create_analytics_engine()


def test_source_totals_query():
    conn = FakeConnection()

    temporal.get_source_totals(conn)

    sql = conn.statements[0]

    assert "LEFT JOIN public.indicator_observations" in sql
    assert "COUNT(o.id)" in sql
    assert "GROUP BY s.id, s.name" in sql


def test_daily_aggregation_uses_utc():
    conn = FakeConnection()

    temporal.get_daily_first_seen(conn)

    sql = conn.statements[0]

    assert "AT TIME ZONE 'UTC'" in sql
    assert "first_seen_date" in sql
    assert "COUNT(DISTINCT o.indicator_id)" in sql
    assert "GROUP BY" in sql


def test_timestamp_quality_query():
    conn = FakeConnection()

    temporal.get_timestamp_quality(conn)

    sql = conn.statements[0]

    assert "o.timestamp_quality" in sql
    assert "COUNT(*) AS observation_count" in sql
    assert "GROUP BY" in sql


def test_interval_statistics_exclude_invalid_intervals():
    conn = FakeConnection()

    temporal.get_valid_interval_statistics(conn)

    sql = conn.statements[0]

    assert "o.last_seen IS NULL" in sql
    assert "o.last_seen < o.first_seen" in sql
    assert "o.last_seen >= o.first_seen" in sql
    assert "EXTRACT(" in sql
    assert "EPOCH FROM" in sql


def test_cross_source_correlation_uses_canonical_ids():
    conn = FakeConnection()

    temporal.get_cross_source_overlaps(conn)

    sql = conn.statements[0]

    assert "x.indicator_id = y.indicator_id" in sql
    assert "x.source_id < y.source_id" in sql
    assert "COUNT(DISTINCT x.indicator_id)" in sql


def test_repeated_indicator_query():
    conn = FakeConnection()

    temporal.get_repeated_source_indicators(conn)

    sql = conn.statements[0]

    assert "o.indicator_id" in sql
    assert "HAVING COUNT(*) > 1" in sql
    assert "SUM(observation_count - 1)" in sql


def configure_report_mocks(monkeypatch, *, daily_count=3):
    """
    Supply a small, internally consistent dataset.

    Three observations:
    - Two with valid intervals
    - One with missing last_seen
    """

    monkeypatch.setattr(
        temporal,
        "get_source_totals",
        lambda conn: [
            {
                "source_id": 1,
                "source_name": "ThreatFox",
                "observation_count": 3,
            }
        ],
    )

    monkeypatch.setattr(
        temporal,
        "get_daily_first_seen",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "first_seen_date": "2026-11-09",
                "observation_count": daily_count,
                "distinct_indicator_count": 3,
            }
        ],
    )

    monkeypatch.setattr(
        temporal,
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
        ],
    )

    monkeypatch.setattr(
        temporal,
        "get_valid_interval_statistics",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "total_observations": 3,
                "missing_last_seen": 1,
                "reversed_intervals": 0,
                "valid_intervals": 2,
                "avg_interval_hours": 12.0,
            }
        ],
    )

    monkeypatch.setattr(
        temporal,
        "get_cross_source_overlaps",
        lambda conn: [],
    )

    monkeypatch.setattr(
        temporal,
        "get_repeated_source_indicators",
        lambda conn: [],
    )


def test_report_successful_reconciliation(
    monkeypatch,
    capsys,
):
    configure_report_mocks(monkeypatch)

    temporal.print_analysis(object())

    output = capsys.readouterr().out

    assert "Overall observations: 3" in output
    assert "Valid intervals: 2" in output
    assert "Mean valid interval (hours): 12.0" in output
    assert "ANALYSIS COMPLETE" in output


def test_daily_total_mismatch_detected(monkeypatch):
    configure_report_mocks(
        monkeypatch,
        daily_count=2,
    )

    with pytest.raises(
        RuntimeError,
        match="Daily observation totals",
    ):
        temporal.print_analysis(object())


def test_timestamp_quality_mismatch_detected(monkeypatch):
    configure_report_mocks(monkeypatch)

    monkeypatch.setattr(
        temporal,
        "get_timestamp_quality",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "timestamp_quality": "consistent",
                "observation_count": 2,
            }
        ],
    )

    with pytest.raises(
        RuntimeError,
        match="Timestamp-quality totals",
    ):
        temporal.print_analysis(object())


def test_interval_mismatch_detected(monkeypatch):
    configure_report_mocks(monkeypatch)

    monkeypatch.setattr(
        temporal,
        "get_valid_interval_statistics",
        lambda conn: [
            {
                "source_name": "ThreatFox",
                "total_observations": 3,
                "missing_last_seen": 1,
                "reversed_intervals": 1,
                "valid_intervals": 2,
                "avg_interval_hours": 12.0,
            }
        ],
    )

    with pytest.raises(
        RuntimeError,
        match="interval counts",
    ):
        temporal.print_analysis(object())


def test_main_enforces_read_only_transaction(monkeypatch):
    statements = []

    class FakeEngine:
        def connect(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, statement):
            statements.append(str(statement))

        def dispose(self):
            statements.append("DISPOSED")

    engine = FakeEngine()

    monkeypatch.setattr(
        temporal,
        "create_analytics_engine",
        lambda: engine,
    )

    monkeypatch.setattr(
        temporal,
        "print_analysis",
        lambda conn: statements.append("REPORT"),
    )

    assert temporal.main() == 0

    assert statements == [
        "SET TRANSACTION READ ONLY",
        "REPORT",
        "DISPOSED",
    ]
