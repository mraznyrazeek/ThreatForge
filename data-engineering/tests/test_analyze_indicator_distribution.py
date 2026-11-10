
"""
ThreatForge - M6.2 Indicator Distribution Tests

Tests:
- Percentage calculations and empty datasets
- Malware ranking limit validation
- Canonical indicator counting
- Source-level indicator aggregation
- Threat-type aggregation
- Malware-family filtering
- Malware metadata coverage
- Database selection safety
- Read-only execution

No live API calls or PostgreSQL writes.
"""

import sys
from pathlib import Path

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import analyze_indicator_distribution as analytics  # noqa: E402


class FakeResult:
    """Minimal SQLAlchemy result replacement."""

    def __init__(self, rows):
        self.rows = rows

    def mappings(self):
        return self

    def all(self):
        return self.rows


class FakeConnection:
    """Capture SQL without connecting to PostgreSQL."""

    def __init__(self, rows=None):
        self.statements = []
        self.parameters = []
        self.rows = rows if rows is not None else []

    def execute(self, statement, parameters=None):
        self.statements.append(str(statement))
        self.parameters.append(parameters)
        return FakeResult(self.rows)


@pytest.mark.parametrize(
    "part,whole,expected",
    [
        (50, 100, 50.0),
        (1, 3, 33.33),
        (0, 100, 0.0),
        (0, 0, 0.0),
    ],
)
def test_percentage(part, whole, expected):
    assert analytics.percentage(part, whole) == expected


@pytest.mark.parametrize(
    "limit",
    [0, -1, 101, True, 1.5, "15"],
)
def test_invalid_malware_limit(limit):
    connection = FakeConnection()

    with pytest.raises(ValueError):
        analytics.get_top_malware_families(
            connection,
            limit=limit,
        )

    assert connection.statements == []


def test_valid_malware_limit():
    connection = FakeConnection()

    analytics.get_top_malware_families(
        connection,
        limit=15,
    )

    assert len(connection.statements) == 1
    assert connection.parameters == [{"limit": 15}]
    assert "LIMIT :limit" in connection.statements[0]


def test_global_distribution_counts_canonical_indicators():
    connection = FakeConnection()

    analytics.get_global_indicator_distribution(connection)

    sql = connection.statements[0]

    assert "FROM public.threat_indicators" in sql
    assert "GROUP BY indicator_type" in sql
    assert "COUNT(*) AS indicator_count" in sql


def test_source_distribution_distinguishes_observations():
    connection = FakeConnection()

    analytics.get_source_indicator_distribution(connection)

    sql = connection.statements[0]

    assert "COUNT(o.id) AS observation_count" in sql
    assert "COUNT(DISTINCT o.indicator_id)" in sql
    assert "JOIN public.threat_indicators" in sql
    assert "JOIN public.intelligence_sources" in sql


def test_threat_type_distribution_grouping():
    connection = FakeConnection()

    analytics.get_threat_type_distribution(connection)

    sql = connection.statements[0]

    assert "o.threat_type" in sql
    assert "COUNT(*) AS observation_count" in sql
    assert "GROUP BY" in sql
    assert "s.name" in sql


def test_malware_ranking_excludes_missing_families():
    connection = FakeConnection()

    analytics.get_top_malware_families(
        connection,
        limit=10,
    )

    sql = connection.statements[0]

    assert "malware_family IS NOT NULL" in sql
    assert "BTRIM(malware_family) <> ''" in sql
    assert "COUNT(DISTINCT indicator_id)" in sql


def test_malware_coverage_uses_left_join():
    connection = FakeConnection()

    analytics.get_malware_coverage_by_source(connection)

    sql = connection.statements[0]

    assert "LEFT JOIN public.indicator_observations" in sql
    assert "with_malware_family" in sql
    assert "without_malware_family" in sql


def test_wrong_database_rejected(monkeypatch):
    monkeypatch.setenv(
        "DB_NAME",
        "threatforge_test_db",
    )

    with pytest.raises(RuntimeError):
        analytics.create_analytics_engine()


def test_missing_database_rejected(monkeypatch):
    monkeypatch.delenv(
        "DB_NAME",
        raising=False,
    )

    with pytest.raises(RuntimeError):
        analytics.create_analytics_engine()


def test_main_uses_read_only_transaction(monkeypatch):
    statements = []

    class ConnectionContext:
        def __enter__(self):
            return connection

        def __exit__(self, *args):
            return False

    class TestConnection:
        def execute(self, statement):
            statements.append(str(statement))

    class TestEngine:
        def __init__(self):
            self.disposed = False

        def connect(self):
            return ConnectionContext()

        def dispose(self):
            self.disposed = True

    connection = TestConnection()
    engine = TestEngine()

    monkeypatch.setattr(
        analytics,
        "create_analytics_engine",
        lambda: engine,
    )

    monkeypatch.setattr(
        analytics,
        "print_analysis",
        lambda conn: statements.append(
            "ANALYSIS_EXECUTED"
        ),
    )

    assert analytics.main() == 0

    assert statements == [
        "SET TRANSACTION READ ONLY",
        "ANALYSIS_EXECUTED",
    ]

    assert engine.disposed is True
