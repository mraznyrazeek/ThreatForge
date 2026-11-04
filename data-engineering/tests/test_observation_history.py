
"""
ThreatForge - Observation History Integration Tests

Coverage:
1. Inserted and unchanged observations create no history.
2. Metadata changes preserve the previous state and
   attribute the change to the correct ingestion run.
3. Multiple updates create ordered previous-state snapshots.
4. Failed metadata updates roll back history and data changes.

Safety:
- Only threatforge_test_db is permitted.
- Uses unique synthetic observations.
- No external ThreatFox API calls.
- Removes synthetic data in foreign-key dependency order.

Run:
    DB_NAME=threatforge_test_db \
    python -m pytest tests/test_observation_history.py -v -W error
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
from sqlalchemy.exc import SQLAlchemyError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = Path(__file__).resolve().parents[1] / "src"

load_dotenv(PROJECT_ROOT / ".env", override=False)

sys.path.insert(0, str(SRC_DIR / "models"))
sys.path.insert(0, str(SRC_DIR / "processing"))

import persist_observation as persistence_module  # noqa: E402

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
    """Connect exclusively to the dedicated test database."""

    if os.environ.get("DB_NAME") != TEST_DATABASE:
        pytest.fail(
            "Observation history tests require "
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

    db_engine = create_engine(url, pool_pre_ping=True)

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
def history_context(engine):
    """Create and later remove a unique synthetic observation."""

    token = uuid4().hex
    source_name = f"ThreatForgeHistoryTest_{token}"

    observation = SourceObservation(
        source_name=source_name,
        source_record_id=f"history_{token}",
        indicator=ThreatIndicator(
            indicator_type="domain",
            value=f"history-{token}.example.com",
        ),
        threat_type="payload",
        malware_family="synthetic_family",
        confidence_level=40,
        first_seen=datetime(
            2026, 1, 1, tzinfo=timezone.utc
        ),
        last_seen=None,
        reporter="ThreatForgeTest",
        reference=None,
        tags=["synthetic", "history-test"],
    )

    try:
        yield {
            "engine": engine,
            "observation": observation,
            "source_name": source_name,
        }

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
                {"name": source_name},
            ).scalar_one_or_none()

            if source_id is not None:
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

                # Child history rows must be removed first.
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


def read_history(engine, observation_id):
    """Read history entries in insertion order."""

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT
                    id,
                    observation_id,
                    ingestion_run_id,
                    recorded_at,
                    snapshot
                FROM observation_history
                WHERE observation_id = :observation_id
                ORDER BY id
                """
            ),
            {"observation_id": observation_id},
        ).mappings().all()

    return [dict(row) for row in rows]


def read_current(engine, observation_id):
    """Read current persisted intelligence metadata."""

    with engine.connect() as connection:
        return dict(
            connection.execute(
                text(
                    """
                    SELECT
                        confidence_level,
                        threat_type,
                        latest_ingestion_run_id,
                        updated_at
                    FROM indicator_observations
                    WHERE id = :observation_id
                    """
                ),
                {"observation_id": observation_id},
            ).mappings().one()
        )


def test_inserted_and_unchanged_create_no_history(
    history_context,
):
    """Inserts and unchanged reprocessing must not create history."""

    engine = history_context["engine"]
    observation = history_context["observation"]

    first = persist_observation(engine, observation)

    assert first.action == "inserted"
    assert read_history(engine, first.observation_id) == []

    second = persist_observation(engine, observation)

    assert second.action == "unchanged"
    assert second.observation_id == first.observation_id
    assert read_history(engine, first.observation_id) == []


def test_metadata_change_preserves_previous_state_and_run(
    history_context,
):
    """A changed observation must preserve its previous state."""

    engine = history_context["engine"]
    observation = history_context["observation"]

    first_run = start_ingestion_run(
        engine,
        observation.source_name,
    )

    first = persist_observation(
        engine,
        observation,
        ingestion_run_id=first_run.run_id,
    )

    before = read_current(engine, first.observation_id)

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

    changed = observation.model_copy(
        update={
            "confidence_level": 85,
            "threat_type": "malware_distribution",
        }
    )

    second = persist_observation(
        engine,
        changed,
        ingestion_run_id=second_run.run_id,
    )

    assert second.action == "updated"

    history = read_history(engine, first.observation_id)

    assert len(history) == 1

    entry = history[0]
    snapshot = entry["snapshot"]

    assert entry["ingestion_run_id"] == second_run.run_id
    assert entry["recorded_at"] is not None

    assert snapshot["confidence_level"] == 40
    assert snapshot["threat_type"] == "payload"
    assert snapshot["malware_family"] == "synthetic_family"
    assert snapshot["tags"] == ["synthetic", "history-test"]

    assert (
        snapshot["latest_ingestion_run_id"]
        == first_run.run_id
    )

    assert snapshot["updated_at"] == (
        before["updated_at"].isoformat()
    ) or datetime.fromisoformat(
        snapshot["updated_at"]
    ) == before["updated_at"]

    current = read_current(engine, first.observation_id)

    assert current["confidence_level"] == 85
    assert current["threat_type"] == "malware_distribution"
    assert (
        current["latest_ingestion_run_id"]
        == second_run.run_id
    )

    assert current["updated_at"] > before["updated_at"]


def test_multiple_updates_preserve_successive_states(
    history_context,
):
    """Each metadata change must preserve the immediately prior state."""

    engine = history_context["engine"]
    observation = history_context["observation"]

    first = persist_observation(engine, observation)

    second = persist_observation(
        engine,
        observation.model_copy(
            update={"confidence_level": 60}
        ),
    )

    third = persist_observation(
        engine,
        observation.model_copy(
            update={"confidence_level": 90}
        ),
    )

    assert first.action == "inserted"
    assert second.action == "updated"
    assert third.action == "updated"

    history = read_history(engine, first.observation_id)

    assert len(history) == 2
    assert history[0]["snapshot"]["confidence_level"] == 40
    assert history[1]["snapshot"]["confidence_level"] == 60
    assert history[0]["id"] < history[1]["id"]

    # Independent persistence is allowed without a run.
    assert all(
        entry["ingestion_run_id"] is None
        for entry in history
    )

    current = read_current(engine, first.observation_id)

    assert current["confidence_level"] == 90


def test_failed_update_rolls_back_history(
    history_context,
    monkeypatch,
):
    """If the metadata update fails, history must also roll back."""

    engine = history_context["engine"]
    observation = history_context["observation"]

    first = persist_observation(engine, observation)
    before = read_current(engine, first.observation_id)

    # Replace only the UPDATE SQL for this test.
    # The history INSERT runs first, but the invalid
    # UPDATE must make the entire transaction roll back.
    monkeypatch.setattr(
        persistence_module,
        "OBSERVATION_UPDATE",
        text(
            """
            UPDATE indicator_observations
            SET nonexistent_test_column = 85
            WHERE id = :observation_id
            """
        ),
    )

    changed = observation.model_copy(
        update={"confidence_level": 85}
    )

    with pytest.raises(SQLAlchemyError):
        persist_observation(engine, changed)

    after = read_current(engine, first.observation_id)

    assert after["confidence_level"] == before["confidence_level"]
    assert after["updated_at"] == before["updated_at"]
    assert read_history(engine, first.observation_id) == []
