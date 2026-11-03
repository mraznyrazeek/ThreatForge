
"""
ThreatForge - Persistence Run Linkage Integration Tests

Tests that persisted observations correctly reference
their latest successful ingestion run.

Coverage:
1. New observations link to their ingestion run.
2. Unchanged observations link to later runs without
   changing intelligence metadata timestamps.
3. Changed observations update metadata and run linkage.
4. Wrong-source ingestion runs are rejected.
5. Completed ingestion runs are rejected.
6. Nonexistent ingestion runs are rejected.

Runs exclusively against threatforge_test_db.

All synthetic test records are cleaned up after each test.

No external API requests are performed.
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


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = Path(__file__).resolve().parents[1] / "src"

load_dotenv(
    PROJECT_ROOT / ".env",
    override=False,
)

sys.path.insert(0, str(SRC_DIR / "models"))
sys.path.insert(0, str(SRC_DIR / "processing"))

from threat_indicator import (  # noqa: E402
    SourceObservation,
    ThreatIndicator,
)
from persist_observation import persist_observation  # noqa: E402
from ingestion_run_service import (  # noqa: E402
    start_ingestion_run,
    complete_ingestion_run,
)


TEST_DATABASE = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Connect only to the dedicated test database."""

    if os.environ.get("DB_NAME") != TEST_DATABASE:
        pytest.fail(
            "Run with DB_NAME=threatforge_test_db"
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
def test_context(engine):
    """
    Create a unique synthetic observation.

    Cleanup removes observations, ingestion runs,
    intelligence sources, and orphaned indicators
    in foreign-key dependency order.
    """

    token = uuid4().hex

    source_name = f"ThreatForgeLinkTest_{token}"
    other_source_name = f"ThreatForgeOtherTest_{token}"

    observation = SourceObservation(
        source_name=source_name,
        source_record_id=f"record_{token}",
        indicator=ThreatIndicator(
            indicator_type="domain",
            value=f"link-{token}.example.com",
        ),
        threat_type="payload",
        malware_family="synthetic_family",
        confidence_level=50,
        first_seen=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        last_seen=None,
        reporter="ThreatForgeTest",
        reference=None,
        tags=["synthetic"],
    )

    try:
        yield {
            "engine": engine,
            "observation": observation,
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


def read_observation(engine, observation_id):
    """Read stored observation linkage and metadata."""

    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                SELECT
                    indicator_id,
                    latest_ingestion_run_id,
                    confidence_level,
                    threat_type,
                    updated_at
                FROM indicator_observations
                WHERE id = :observation_id
                """
            ),
            {
                "observation_id": observation_id,
            },
        ).mappings().one()


def test_inserted_observation_links_to_run(test_context):
    """A new observation must reference its running ingestion run."""

    engine = test_context["engine"]
    observation = test_context["observation"]

    run = start_ingestion_run(
        engine,
        observation.source_name,
    )

    result = persist_observation(
        engine,
        observation,
        ingestion_run_id=run.run_id,
    )

    stored = read_observation(
        engine,
        result.observation_id,
    )

    assert result.action == "inserted"
    assert stored["latest_ingestion_run_id"] == run.run_id
    assert stored["confidence_level"] == 50


def test_unchanged_observation_links_to_later_run(test_context):
    """
    Reprocessing unchanged intelligence must update
    run linkage without changing updated_at.
    """

    engine = test_context["engine"]
    observation = test_context["observation"]

    first_run = start_ingestion_run(
        engine,
        observation.source_name,
    )

    first = persist_observation(
        engine,
        observation,
        ingestion_run_id=first_run.run_id,
    )

    before = read_observation(
        engine,
        first.observation_id,
    )

    complete_ingestion_run(
        engine,
        first_run.run_id,
        records_received=1,
        records_normalized=1,
        records_rejected=0,
    )

    second_run = start_ingestion_run(
        engine,
        observation.source_name,
    )

    second = persist_observation(
        engine,
        observation,
        ingestion_run_id=second_run.run_id,
    )

    after = read_observation(
        engine,
        second.observation_id,
    )

    assert second.action == "unchanged"
    assert second.observation_id == first.observation_id

    assert (
        after["latest_ingestion_run_id"]
        == second_run.run_id
    )

    assert after["updated_at"] == before["updated_at"]
    assert after["indicator_id"] == before["indicator_id"]


def test_updated_observation_links_to_later_run(test_context):
    """Metadata changes must refresh updated_at and run linkage."""

    engine = test_context["engine"]
    observation = test_context["observation"]

    first_run = start_ingestion_run(
        engine,
        observation.source_name,
    )

    first = persist_observation(
        engine,
        observation,
        ingestion_run_id=first_run.run_id,
    )

    before = read_observation(
        engine,
        first.observation_id,
    )

    complete_ingestion_run(
        engine,
        first_run.run_id,
        records_received=1,
        records_normalized=1,
        records_rejected=0,
    )

    second_run = start_ingestion_run(
        engine,
        observation.source_name,
    )

    changed_observation = observation.model_copy(
        update={
            "confidence_level": 85,
            "threat_type": "malware_distribution",
        }
    )

    second = persist_observation(
        engine,
        changed_observation,
        ingestion_run_id=second_run.run_id,
    )

    after = read_observation(
        engine,
        second.observation_id,
    )

    assert second.action == "updated"
    assert second.observation_id == first.observation_id

    assert after["latest_ingestion_run_id"] == second_run.run_id
    assert after["confidence_level"] == 85
    assert after["threat_type"] == "malware_distribution"
    assert after["updated_at"] > before["updated_at"]


def test_wrong_source_run_rejected(test_context):
    """A run belonging to another source must be rejected."""

    engine = test_context["engine"]
    observation = test_context["observation"]

    wrong_run = start_ingestion_run(
        engine,
        test_context["other_source_name"],
    )

    with pytest.raises(
        ValueError,
        match="different source",
    ):
        persist_observation(
            engine,
            observation,
            ingestion_run_id=wrong_run.run_id,
        )


def test_completed_run_rejected(test_context):
    """An observation cannot be attached to a completed run."""

    engine = test_context["engine"]
    observation = test_context["observation"]

    run = start_ingestion_run(
        engine,
        observation.source_name,
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
        persist_observation(
            engine,
            observation,
            ingestion_run_id=run.run_id,
        )


def test_nonexistent_run_rejected(test_context):
    """A nonexistent ingestion run must be rejected."""

    engine = test_context["engine"]
    observation = test_context["observation"]

    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        persist_observation(
            engine,
            observation,
            ingestion_run_id=9223372036854775807,
        )
