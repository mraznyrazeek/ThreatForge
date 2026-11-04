
"""
ThreatForge - Rejected Record Persistence Tests

Validates:
1. Sanitized normalization rejection persistence.
2. Persistence failure classification.
3. Rejection of completed ingestion runs.
4. Rejection of wrong-source ingestion runs.

Only the dedicated threatforge_test_db is permitted.
Synthetic test records are cleaned up after each test.
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

sys.path.insert(0, str(SRC_DIR / "processing"))

from ingestion_run_service import (  # noqa: E402
    start_ingestion_run,
    complete_ingestion_run,
)
from persist_rejected_record import (  # noqa: E402
    persist_rejected_record,
)


TEST_DATABASE = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Connect exclusively to the test database."""

    if os.environ.get("DB_NAME") != TEST_DATABASE:
        pytest.fail(
            "Requires DB_NAME=threatforge_test_db"
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
def rejection_context(engine):
    """Create isolated ingestion sources and clean up afterward."""

    token = uuid4().hex

    names = (
        f"ThreatForgeReject_{token}",
        f"ThreatForgeRejectOther_{token}",
    )

    try:
        yield {
            "engine": engine,
            "source_name": names[0],
            "other_source_name": names[1],
        }

    finally:
        with engine.begin() as connection:
            source_ids = list(
                connection.execute(
                    text(
                        """
                        SELECT id
                        FROM intelligence_sources
                        WHERE name IN (:first, :second)
                        """
                    ),
                    {
                        "first": names[0],
                        "second": names[1],
                    },
                ).scalars()
            )

            for source_id in source_ids:
                # Delete child rejection records first.
                connection.execute(
                    text(
                        """
                        DELETE FROM rejected_records
                        WHERE source_id = :source_id
                        """
                    ),
                    {"source_id": source_id},
                )

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


def read_rejection(engine, rejection_id):
    """Read the persisted rejection for verification."""

    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                SELECT
                    source_id,
                    ingestion_run_id,
                    source_record_id,
                    rejection_category,
                    rejection_details,
                    raw_payload
                FROM rejected_records
                WHERE id = :rejection_id
                """
            ),
            {"rejection_id": rejection_id},
        ).mappings().one()


def test_normalization_rejection_is_sanitized(
    rejection_context,
):
    engine = rejection_context["engine"]

    run = start_ingestion_run(
        engine,
        rejection_context["source_name"],
    )

    result = persist_rejected_record(
        engine,
        source_id=run.source_id,
        ingestion_run_id=run.run_id,
        rejection_category="normalization_failure",
        reason_code="validation_failed",
    )

    stored = read_rejection(
        engine,
        result.rejected_record_id,
    )

    assert stored["source_id"] == run.source_id
    assert stored["ingestion_run_id"] == run.run_id
    assert stored["source_record_id"] is None
    assert stored["rejection_category"] == (
        "normalization_failure"
    )
    assert stored["rejection_details"] == {
        "reason_code": "validation_failed"
    }
    assert stored["raw_payload"] == {}


def test_persistence_failure_is_classified(
    rejection_context,
):
    engine = rejection_context["engine"]

    run = start_ingestion_run(
        engine,
        rejection_context["source_name"],
    )

    result = persist_rejected_record(
        engine,
        source_id=run.source_id,
        ingestion_run_id=run.run_id,
        rejection_category="persistence_failure",
        reason_code="database_operation_failed",
    )

    stored = read_rejection(
        engine,
        result.rejected_record_id,
    )

    assert stored["rejection_category"] == (
        "persistence_failure"
    )
    assert stored["rejection_details"]["reason_code"] == (
        "database_operation_failed"
    )


def test_completed_run_is_rejected(
    rejection_context,
):
    engine = rejection_context["engine"]

    run = start_ingestion_run(
        engine,
        rejection_context["source_name"],
    )

    complete_ingestion_run(
        engine,
        run.run_id,
        records_received=0,
        records_normalized=0,
        records_rejected=0,
    )

    with pytest.raises(
        ValueError,
        match="not in running status",
    ):
        persist_rejected_record(
            engine,
            source_id=run.source_id,
            ingestion_run_id=run.run_id,
            rejection_category="normalization_failure",
            reason_code="validation_failed",
        )


def test_wrong_source_run_is_rejected(
    rejection_context,
):
    engine = rejection_context["engine"]

    run = start_ingestion_run(
        engine,
        rejection_context["other_source_name"],
    )

    with pytest.raises(
        ValueError,
        match="different source",
    ):
        persist_rejected_record(
            engine,
            source_id=run.source_id + 1000000,
            ingestion_run_id=run.run_id,
            rejection_category="normalization_failure",
            reason_code="validation_failed",
        )
