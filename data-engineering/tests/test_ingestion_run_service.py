
"""
ThreatForge - Ingestion Run Lifecycle Integration Tests

Tests the ingestion_run_service against PostgreSQL.

Coverage:
1. Starting an ingestion run
2. Completing a run with processing statistics
3. Recording a safe failure category
4. Rejecting invalid processing counts
5. Preventing invalid lifecycle transitions

Only the dedicated threatforge_test_db is permitted.

Each test creates a unique synthetic source.
All synthetic records are removed after each test.

Run:
    DB_NAME=threatforge_test_db \
    python -m pytest tests/test_ingestion_run_service.py -v
"""

import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = Path(__file__).resolve().parents[1] / "src"

load_dotenv(
    PROJECT_ROOT / ".env",
    override=False,
)

sys.path.insert(
    0,
    str(SRC_DIR / "processing"),
)

from ingestion_run_service import (  # noqa: E402
    IngestionFailureCategory,
    complete_ingestion_run,
    fail_ingestion_run,
    start_ingestion_run,
)


TEST_DATABASE = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Connect exclusively to the dedicated test database."""

    if os.environ.get("DB_NAME") != TEST_DATABASE:
        pytest.fail(
            "Integration tests require "
            "DB_NAME=threatforge_test_db"
        )

    url = URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=TEST_DATABASE,
    )

    db_engine = create_engine(
        url,
        pool_pre_ping=True,
    )

    try:
        with db_engine.connect() as connection:
            actual_database = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()

        assert actual_database == TEST_DATABASE

        yield db_engine

    finally:
        db_engine.dispose()


@pytest.fixture()
def source_name(engine):
    """
    Provide a unique synthetic intelligence source.

    Clean up its ingestion runs before deleting the
    source itself, respecting foreign-key dependencies.
    """

    name = f"ThreatForgeRunTest_{uuid4().hex}"

    try:
        yield name

    finally:
        with engine.begin() as connection:
            source_id = connection.execute(
                text(
                    """
                    SELECT id
                    FROM intelligence_sources
                    WHERE name = :name
                    """
                ),
                {"name": name},
            ).scalar_one_or_none()

            if source_id is not None:
                connection.execute(
                    text(
                        """
                        DELETE FROM ingestion_runs
                        WHERE source_id = :source_id
                        """
                    ),
                    {"source_id": source_id},
                )

                connection.execute(
                    text(
                        """
                        DELETE FROM intelligence_sources
                        WHERE id = :source_id
                        """
                    ),
                    {"source_id": source_id},
                )


def read_run(engine, run_id):
    """Retrieve persisted lifecycle information."""

    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                SELECT
                    id,
                    source_id,
                    status,
                    started_at,
                    completed_at,
                    records_received,
                    records_normalized,
                    records_rejected,
                    error_summary
                FROM ingestion_runs
                WHERE id = :run_id
                """
            ),
            {"run_id": run_id},
        ).mappings().one()


# ---------------------------------------------------------
# Test 1 - Start ingestion
# ---------------------------------------------------------

def test_start_ingestion_run(engine, source_name):
    """A new ingestion run starts in the running state."""

    result = start_ingestion_run(
        engine,
        source_name,
    )

    assert result.run_id > 0
    assert result.source_id > 0
    assert result.status == "running"
    assert result.records_received == 0
    assert result.records_normalized == 0
    assert result.records_rejected == 0

    row = read_run(engine, result.run_id)

    assert row["status"] == "running"
    assert row["started_at"] is not None
    assert row["completed_at"] is None
    assert row["error_summary"] is None


# ---------------------------------------------------------
# Test 2 - Complete ingestion
# ---------------------------------------------------------

def test_complete_ingestion_run(engine, source_name):
    """Successful completion persists final statistics."""

    started = start_ingestion_run(
        engine,
        source_name,
    )

    completed = complete_ingestion_run(
        engine=engine,
        run_id=started.run_id,
        records_received=10,
        records_normalized=9,
        records_rejected=1,
    )

    assert completed.run_id == started.run_id
    assert completed.status == "completed"
    assert completed.records_received == 10
    assert completed.records_normalized == 9
    assert completed.records_rejected == 1

    row = read_run(engine, started.run_id)

    assert row["status"] == "completed"
    assert row["completed_at"] is not None
    assert row["completed_at"] >= row["started_at"]
    assert row["records_received"] == 10
    assert row["records_normalized"] == 9
    assert row["records_rejected"] == 1
    assert row["error_summary"] is None


# ---------------------------------------------------------
# Test 3 - Failed ingestion
# ---------------------------------------------------------

def test_fail_ingestion_run(engine, source_name):
    """Failures persist an approved category, not raw errors."""

    started = start_ingestion_run(
        engine,
        source_name,
    )

    failed = fail_ingestion_run(
        engine=engine,
        run_id=started.run_id,
        failure_category=(
            IngestionFailureCategory.API_FAILURE
        ),
        records_received=5,
        records_normalized=3,
        records_rejected=2,
    )

    assert failed.status == "failed"
    assert failed.records_received == 5
    assert failed.records_normalized == 3
    assert failed.records_rejected == 2

    row = read_run(engine, started.run_id)

    assert row["status"] == "failed"
    assert row["completed_at"] is not None
    assert row["error_summary"] == "api_failure"


# ---------------------------------------------------------
# Test 4 - Invalid processing counts
# ---------------------------------------------------------

def test_invalid_counts_rejected(engine, source_name):
    """Invalid statistics must not change the run state."""

    started = start_ingestion_run(
        engine,
        source_name,
    )

    with pytest.raises(ValueError):
        complete_ingestion_run(
            engine=engine,
            run_id=started.run_id,
            records_received=5,
            records_normalized=6,
            records_rejected=0,
        )

    with pytest.raises(ValueError):
        fail_ingestion_run(
            engine=engine,
            run_id=started.run_id,
            failure_category=(
                IngestionFailureCategory.PERSISTENCE_FAILURE
            ),
            records_received=-1,
        )

    row = read_run(engine, started.run_id)

    assert row["status"] == "running"
    assert row["completed_at"] is None


# ---------------------------------------------------------
# Test 5 - Invalid lifecycle transition
# ---------------------------------------------------------

def test_terminal_run_cannot_transition_again(
    engine,
    source_name,
):
    """A completed run cannot be completed or failed again."""

    started = start_ingestion_run(
        engine,
        source_name,
    )

    complete_ingestion_run(
        engine=engine,
        run_id=started.run_id,
        records_received=10,
        records_normalized=10,
        records_rejected=0,
    )

    with pytest.raises(ValueError):
        complete_ingestion_run(
            engine=engine,
            run_id=started.run_id,
            records_received=10,
            records_normalized=10,
            records_rejected=0,
        )

    with pytest.raises(ValueError):
        fail_ingestion_run(
            engine=engine,
            run_id=started.run_id,
            failure_category=(
                IngestionFailureCategory.UNEXPECTED_FAILURE
            ),
        )

    row = read_run(engine, started.run_id)

    assert row["status"] == "completed"
    assert row["error_summary"] is None
