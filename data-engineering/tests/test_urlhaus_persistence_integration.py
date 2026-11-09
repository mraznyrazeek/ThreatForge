
"""
ThreatForge - URLhaus PostgreSQL Persistence Integration Tests

Uses synthetic URLhaus observations and the dedicated
threatforge_test_db database.

Tests:
- Canonical indicator deduplication.
- Source observation identity.
- Unchanged observations.
- Metadata updates and historical snapshots.
- Safe cleanup of synthetic records.

No external API requests or real malicious URLs.
"""

import os
import sys
import uuid
from pathlib import Path

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


SRC_DIR = Path(__file__).resolve().parents[1] / "src"

sys.path.insert(0, str(SRC_DIR / "models"))
sys.path.insert(0, str(SRC_DIR / "processing"))

from threat_indicator import (  # noqa: E402
    SourceObservation,
    ThreatIndicator,
)
from persist_observation import persist_observation  # noqa: E402


TEST_DATABASE = "threatforge_test_db"


@pytest.fixture
def integration_engine():
    project_root = Path(__file__).resolve().parents[2]

    load_dotenv(project_root / ".env", override=False)

    if os.getenv("DB_NAME") != TEST_DATABASE:
        pytest.skip(
            "Integration test requires threatforge_test_db"
        )

    url = URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=TEST_DATABASE,
    )

    engine = create_engine(url, pool_pre_ping=True)

    with engine.connect() as connection:
        actual = connection.execute(
            text("SELECT current_database()")
        ).scalar_one()

        if actual != TEST_DATABASE:
            engine.dispose()
            raise RuntimeError("Unexpected database")

    yield engine

    engine.dispose()


def test_urlhaus_deduplication_and_history(integration_engine):
    unique_id = uuid.uuid4().hex
    source_name = f"URLhaus-test-{unique_id}"

    source_record_id = f"synthetic-{unique_id}"
    indicator_value = (
        f"https://synthetic-{unique_id}.example/test"
    )

    def observation(threat_type):
        return SourceObservation(
            source_name=source_name,
            source_record_id=source_record_id,
            indicator=ThreatIndicator(
                indicator_type="url",
                value=indicator_value,
            ),
            threat_type=threat_type,
            confidence_level=0,
            first_seen="2026-11-09 10:00:00 UTC",
            last_seen=None,
            tags=["synthetic-test"],
        )

    try:
        first = persist_observation(
            integration_engine,
            observation("malware_download"),
        )

        second = persist_observation(
            integration_engine,
            observation("malware_download"),
        )

        assert first.action == "inserted"
        assert second.action == "unchanged"
        assert first.indicator_id == second.indicator_id
        assert first.observation_id == second.observation_id

        with integration_engine.connect() as connection:
            history_before = connection.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM observation_history
                    WHERE observation_id = :id
                    """
                ),
                {"id": first.observation_id},
            ).scalar_one()

        assert history_before == 0

        third = persist_observation(
            integration_engine,
            observation("phishing"),
        )

        assert third.action == "updated"
        assert third.observation_id == first.observation_id

        with integration_engine.connect() as connection:
            history = connection.execute(
                text(
                    """
                    SELECT snapshot
                    FROM observation_history
                    WHERE observation_id = :id
                    """
                ),
                {"id": first.observation_id},
            ).scalar_one()

            current = connection.execute(
                text(
                    """
                    SELECT threat_type
                    FROM indicator_observations
                    WHERE id = :id
                    """
                ),
                {"id": first.observation_id},
            ).scalar_one()

            indicator_count = connection.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM threat_indicators
                    WHERE id = :id
                    """
                ),
                {"id": first.indicator_id},
            ).scalar_one()

        assert history["threat_type"] == "malware_download"
        assert current == "phishing"
        assert indicator_count == 1

    finally:
        with integration_engine.begin() as connection:
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
                        DELETE FROM intelligence_sources
                        WHERE id = :source_id
                        """
                    ),
                    {"source_id": source_id},
                )

            connection.execute(
                text(
                    """
                    DELETE FROM threat_indicators
                    WHERE normalized_value = :value
                      AND NOT EXISTS (
                          SELECT 1
                          FROM indicator_observations
                          WHERE indicator_id = threat_indicators.id
                      )
                    """
                ),
                {"value": indicator_value},
            )
