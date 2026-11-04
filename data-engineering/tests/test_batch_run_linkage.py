
"""
ThreatForge - Batch-to-Ingestion-Run Integration Tests

Coverage:
1. Batch persistence links inserted observations to the active run.
2. Reprocessing unchanged observations links them to a newer run
   without changing intelligence metadata timestamps.
3. A wrong-source ingestion run is rejected by batch persistence.

Safety:
- Uses only threatforge_test_db.
- Uses unique synthetic records.
- Does not call the ThreatFox API.
- Cleans up test data after every test.
"""

import os
import sys

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

load_dotenv(
    PROJECT_ROOT.parent / ".env",
    override=False,
)

sys.path.insert(0, str(SRC_DIR / "models"))
sys.path.insert(0, str(SRC_DIR / "processing"))

from threat_indicator import (  # noqa: E402
    SourceObservation,
    ThreatIndicator,
)
from ingestion_run_service import (  # noqa: E402
    start_ingestion_run,
    complete_ingestion_run,
)
from ingest_threatfox_batch import persist_batch  # noqa: E402


TEST_DATABASE = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Create an engine for the dedicated test database only."""

    if os.environ.get("DB_NAME") != TEST_DATABASE:
        pytest.fail(
            "Batch integration tests require "
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
def batch_context(engine):
    """
    Provide two synthetic observations sharing one source.

    Clean up in foreign-key dependency order.
    """

    token = uuid4().hex
    source_name = f"ThreatForgeBatchLink_{token}"
    other_source_name = f"ThreatForgeOtherBatch_{token}"

    observations = []

    for index in range(2):
        observations.append(
            SourceObservation(
                source_name=source_name,
                source_record_id=f"record_{index}_{token}",
                indicator=ThreatIndicator(
                    indicator_type="domain",
                    value=f"batch-{index}-{token}.example.com",
                ),
                threat_type="payload",
                malware_family="synthetic_family",
                confidence_level=60,
                first_seen=datetime(
                    2026, 1, 1, tzinfo=timezone.utc
                ),
                last_seen=None,
                reporter="ThreatForgeTest",
                reference=None,
                tags=["synthetic"],
            )
        )

    try:
        yield {
            "engine": engine,
            "observations": observations,
            "source_name": source_name,
            "other_source_name": other_source_name,
        }

    finally:
        with engine.begin() as connection:
            source_ids = list(
                connection.execute(
                    text(
                        """
                        SELECT id
                        FROM intelligence_sources
                        WHERE name IN (:source_a, :source_b)
                        """
                    ),
                    {
                        "source_a": source_name,
                        "source_b": other_source_name,
                    },
                ).scalars()
            )

            for source_id in source_ids:
                indicator_ids = list(
                    connection.execute(
                        text(
                            """
                            SELECT DISTINCT indicator_id
                            FROM indicator_observations
                            WHERE source_id = :source_id
                            """
                        ),
                        {"source_id": source_id},
                    ).scalars()
                )

                # History records reference observations, so delete
                # those child records before deleting their parents.
                connection.execute(
                    text(
                        """
                        DELETE FROM observation_history
                        WHERE observation_id IN (
                            SELECT id
                            FROM indicator_observations
                            WHERE source_id = :source_id
                        )
                        """
                    ),
                    {"source_id": source_id},
                )

                connection.execute(
                    text(
                        """
                        DELETE FROM indicator_observations
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

                for indicator_id in indicator_ids:
                    connection.execute(
                        text(
                            """
                            DELETE FROM threat_indicators
                            WHERE id = :indicator_id
                              AND NOT EXISTS (
                                  SELECT 1
                                  FROM indicator_observations
                                  WHERE indicator_id = :indicator_id
                              )
                            """
                        ),
                        {"indicator_id": indicator_id},
                    )


def read_batch_observations(engine, source_name):
    """Read persisted run linkage and timestamps."""

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT
                    o.source_record_id,
                    o.latest_ingestion_run_id,
                    o.updated_at
                FROM indicator_observations o
                JOIN intelligence_sources s
                  ON s.id = o.source_id
                WHERE s.name = :source_name
                ORDER BY o.source_record_id
                """
            ),
            {"source_name": source_name},
        ).mappings().all()

    return {
        row["source_record_id"]: dict(row)
        for row in rows
    }


def test_batch_inserts_observations_with_run_id(batch_context):
    """All inserted observations must reference their active run."""

    engine = batch_context["engine"]

    run = start_ingestion_run(
        engine,
        batch_context["source_name"],
    )

    counts = persist_batch(
        engine=engine,
        observations=batch_context["observations"],
        ingestion_run_id=run.run_id,
    )

    assert counts["inserted"] == 2
    assert counts["updated"] == 0
    assert counts["unchanged"] == 0
    assert counts["identity_conflicts"] == 0
    assert counts["database_failures"] == 0

    stored = read_batch_observations(
        engine,
        batch_context["source_name"],
    )

    assert len(stored) == 2

    assert all(
        record["latest_ingestion_run_id"] == run.run_id
        for record in stored.values()
    )


def test_repeated_batch_updates_only_run_linkage(batch_context):
    """
    Reprocessing identical observations must preserve
    updated_at while linking to the newer ingestion run.
    """

    engine = batch_context["engine"]
    source_name = batch_context["source_name"]
    observations = batch_context["observations"]

    first_run = start_ingestion_run(
        engine,
        source_name,
    )

    first_counts = persist_batch(
        engine=engine,
        observations=observations,
        ingestion_run_id=first_run.run_id,
    )

    assert first_counts["inserted"] == 2

    before = read_batch_observations(
        engine,
        source_name,
    )

    complete_ingestion_run(
        engine,
        first_run.run_id,
        records_received=2,
        records_normalized=2,
        records_rejected=0,
    )

    second_run = start_ingestion_run(
        engine,
        source_name,
    )

    second_counts = persist_batch(
        engine=engine,
        observations=observations,
        ingestion_run_id=second_run.run_id,
    )

    assert second_counts["inserted"] == 0
    assert second_counts["updated"] == 0
    assert second_counts["unchanged"] == 2
    assert second_counts["identity_conflicts"] == 0
    assert second_counts["database_failures"] == 0

    after = read_batch_observations(
        engine,
        source_name,
    )

    assert set(before) == set(after)

    for record_id in before:
        assert (
            after[record_id]["latest_ingestion_run_id"]
            == second_run.run_id
        )

        assert (
            after[record_id]["updated_at"]
            == before[record_id]["updated_at"]
        )


def test_batch_rejects_wrong_source_run(batch_context):
    """Batch persistence must not link to another source's run."""

    engine = batch_context["engine"]

    wrong_run = start_ingestion_run(
        engine,
        batch_context["other_source_name"],
    )

    counts = persist_batch(
        engine=engine,
        observations=batch_context["observations"],
        ingestion_run_id=wrong_run.run_id,
    )

    assert counts["inserted"] == 0
    assert counts["updated"] == 0
    assert counts["unchanged"] == 0
    assert counts["identity_conflicts"] == 2
    assert counts["database_failures"] == 0

    stored = read_batch_observations(
        engine,
        batch_context["source_name"],
    )

    assert stored == {}
