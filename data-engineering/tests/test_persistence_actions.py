
"""
ThreatForge - Persistence Action Integration Tests

Verifies:
- New observations are classified as inserted.
- Identical observations are classified as unchanged.
- Unchanged observations preserve updated_at.
- Metadata changes are classified as updated.
- Updated observations receive newer timestamps.

Runs only against threatforge_test_db.

Synthetic records are removed after testing.

Cleanup order:
1. observation_history
2. indicator_observations
3. intelligence_sources
4. orphaned threat_indicators

Run:
    DB_NAME=threatforge_test_db \
    python -m pytest tests/test_persistence_actions.py -v
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


TEST_DATABASE = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Connect exclusively to the dedicated test database."""

    if os.environ.get("DB_NAME") != TEST_DATABASE:
        pytest.skip(
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
def test_observation(engine):
    """
    Create a unique synthetic observation.

    Clean up synthetic records in foreign-key order.
    Never suppress exceptions during fixture cleanup.
    """

    token = uuid4().hex
    source_name = f"ThreatForgeActionTest_{token}"

    observation = SourceObservation(
        source_name=source_name,
        source_record_id=f"action_{token}",
        indicator=ThreatIndicator(
            indicator_type="domain",
            value=f"action-{token}.example.com",
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
        yield observation

    finally:
        # All cleanup operations share a transaction.
        # Only records belonging to this test's unique
        # synthetic intelligence source are selected.

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

                # Capture associated indicator IDs before
                # deleting their parent observations.

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

                # STEP 1:
                # Delete history FIRST.
                #
                # observation_history.observation_id
                # references indicator_observations.id.
                #
                # PostgreSQL prevents parent observations
                # from being deleted while their history
                # records still exist.

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

                # STEP 2:
                # Delete observations after history
                # references have been removed.

                connection.execute(
                    text(
                        """
                        DELETE FROM indicator_observations
                        WHERE source_id = :source_id
                        """
                    ),
                    {"source_id": source_id},
                )

                # STEP 3:
                # Remove the synthetic intelligence source.

                connection.execute(
                    text(
                        """
                        DELETE FROM intelligence_sources
                        WHERE id = :source_id
                        """
                    ),
                    {"source_id": source_id},
                )

                # STEP 4:
                # Delete only orphaned indicators.
                #
                # An indicator might theoretically be
                # referenced by another observation.
                # Do not delete it in that situation.

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


def get_updated_at(engine, observation_id):
    """Read the database-maintained observation timestamp."""

    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                SELECT updated_at
                FROM indicator_observations
                WHERE id = :observation_id
                """
            ),
            {"observation_id": observation_id},
        ).scalar_one()


def test_inserted_unchanged_updated_actions(
    engine,
    test_observation,
):
    """
    Verify all three actions:

    Insert -> unchanged -> metadata update.
    """

    # 1. First ingestion must insert.

    first = persist_observation(
        engine,
        test_observation,
    )

    assert first.action == "inserted"

    first_timestamp = get_updated_at(
        engine,
        first.observation_id,
    )

    # 2. Identical ingestion must not update.

    second = persist_observation(
        engine,
        test_observation,
    )

    assert second.action == "unchanged"
    assert second.source_id == first.source_id
    assert second.indicator_id == first.indicator_id
    assert second.observation_id == first.observation_id

    second_timestamp = get_updated_at(
        engine,
        second.observation_id,
    )

    assert second_timestamp == first_timestamp

    # 3. Changed metadata must update.

    updated_observation = test_observation.model_copy(
        update={
            "confidence_level": 85,
            "threat_type": "malware_distribution",
        }
    )

    third = persist_observation(
        engine,
        updated_observation,
    )

    assert third.action == "updated"
    assert third.observation_id == first.observation_id
    assert third.indicator_id == first.indicator_id

    third_timestamp = get_updated_at(
        engine,
        third.observation_id,
    )

    assert third_timestamp > second_timestamp

    # Verify the actual persisted metadata.

    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT
                    confidence_level,
                    threat_type
                FROM indicator_observations
                WHERE id = :observation_id
                """
            ),
            {"observation_id": third.observation_id},
        ).one()

    assert row.confidence_level == 85
    assert row.threat_type == "malware_distribution"


def test_new_observation_has_valid_action(
    engine,
    test_observation,
):
    """A distinct observation must be inserted."""

    result = persist_observation(
        engine,
        test_observation,
    )

    assert result.action == "inserted"
    assert result.observation_id > 0
    assert len(result.indicator_sha256) == 64
