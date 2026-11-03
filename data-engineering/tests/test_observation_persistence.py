
"""
ThreatForge - Observation Persistence Integration Tests

Verifies the persistence service against the dedicated
PostgreSQL test database using synthetic indicators.

Tests:
1. First-time indicator and observation insertion
2. Repeated ingestion without duplicate records
3. Updating existing source observation metadata
4. Rejecting source-record identity conflicts atomically

Requires:
    DB_NAME=threatforge_test_db

No ThreatFox API calls are performed.

Test data is cleaned up after each test.
"""

import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = Path(__file__).resolve().parents[1] / "src"

load_dotenv(ROOT / ".env", override=False)

sys.path.insert(0, str(SRC_DIR / "models"))
sys.path.insert(0, str(SRC_DIR / "processing"))

from threat_indicator import (  # noqa: E402
    SourceObservation,
    ThreatIndicator,
)
from persist_observation import (  # noqa: E402
    calculate_indicator_digest,
    persist_observation,
)


TEST_DATABASE_NAME = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Connect only to the dedicated test database."""

    database_name = os.environ.get("DB_NAME")

    if database_name != TEST_DATABASE_NAME:
        pytest.skip(
            "Persistence integration tests require "
            "DB_NAME=threatforge_test_db"
        )

    url = URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=database_name,
    )

    assert url.database == TEST_DATABASE_NAME

    db_engine = create_engine(
        url,
        pool_pre_ping=True,
    )

    try:
        with db_engine.connect() as connection:
            connected_database = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()

        assert connected_database == TEST_DATABASE_NAME

        yield db_engine

    finally:
        db_engine.dispose()


@pytest.fixture()
def test_context(engine):
    """
    Give each test its own unique source and IOC values.

    Remove synthetic rows after the test, including
    when the test raises an assertion error.
    """

    token = uuid4().hex

    source_name = f"ThreatForgeTest_{token}"
    source_record_id = f"record_{token}"

    created_values = set()

    def make_observation(
        *,
        value=None,
        confidence_level=50,
        threat_type="payload",
    ):
        if value is None:
            value = f"test-{token}.example.com"

        created_values.add(value)

        return SourceObservation(
            source_name=source_name,
            source_record_id=source_record_id,
            indicator=ThreatIndicator(
                indicator_type="domain",
                value=value,
            ),
            threat_type=threat_type,
            malware_family="test_family",
            confidence_level=confidence_level,
            first_seen=datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
            last_seen=None,
            reporter="ThreatForgeTest",
            reference=None,
            tags=["synthetic", "integration-test"],
        )

    try:
        yield engine, make_observation

    finally:
        # All records created by these tests are synthetic.
        # Remove them in foreign-key dependency order.
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

            for value in created_values:
                digest = calculate_indicator_digest(
                    value.lower().rstrip(".")
                )

                connection.execute(
                    text(
                        """
                        DELETE FROM threat_indicators
                        WHERE indicator_type = 'domain'
                          AND value_sha256 = :digest
                        """
                    ),
                    {"digest": digest},
                )


def count_records(engine, table_name, column, value):
    """Count records using a fixed, trusted table/column."""

    allowed = {
        ("intelligence_sources", "name"),
        ("threat_indicators", "value_sha256"),
        ("indicator_observations", "source_id"),
    }

    if (table_name, column) not in allowed:
        raise ValueError("Unsupported test query")

    with engine.connect() as connection:
        return connection.execute(
            text(
                f"SELECT count(*) FROM {table_name} "
                f"WHERE {column} = :value"
            ),
            {"value": value},
        ).scalar_one()


def test_first_observation_insert(test_context):
    """A new observation creates its source and IOC."""

    engine, make_observation = test_context
    observation = make_observation()

    result = persist_observation(engine, observation)

    assert result.source_id > 0
    assert result.indicator_id > 0
    assert result.observation_id > 0

    expected_digest = hashlib.sha256(
        observation.indicator.value.encode("utf-8")
    ).hexdigest()

    assert result.indicator_sha256 == expected_digest

    assert count_records(
        engine,
        "intelligence_sources",
        "name",
        observation.source_name,
    ) == 1

    assert count_records(
        engine,
        "threat_indicators",
        "value_sha256",
        expected_digest,
    ) == 1

    assert count_records(
        engine,
        "indicator_observations",
        "source_id",
        result.source_id,
    ) == 1


def test_duplicate_ingestion_is_idempotent(test_context):
    """Repeated ingestion must not create duplicate rows."""

    engine, make_observation = test_context
    observation = make_observation()

    first = persist_observation(engine, observation)
    second = persist_observation(engine, observation)

    assert first.source_id == second.source_id
    assert first.indicator_id == second.indicator_id
    assert first.observation_id == second.observation_id

    assert count_records(
        engine,
        "indicator_observations",
        "source_id",
        first.source_id,
    ) == 1


def test_existing_observation_updates(test_context):
    """Metadata changes update the existing source record."""

    engine, make_observation = test_context

    original = make_observation(
        confidence_level=40,
    )

    updated = make_observation(
        confidence_level=85,
        threat_type="malware_distribution",
    )

    first_result = persist_observation(engine, original)
    second_result = persist_observation(engine, updated)

    assert first_result.observation_id == second_result.observation_id
    assert first_result.indicator_id == second_result.indicator_id

    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT confidence_level, threat_type
                FROM indicator_observations
                WHERE id = :id
                """
            ),
            {"id": second_result.observation_id},
        ).one()

    assert row.confidence_level == 85
    assert row.threat_type == "malware_distribution"


def test_identity_conflict_rolls_back(test_context):
    """
    An existing source record cannot silently change IOC.

    A rejected update must not leave an orphan indicator.
    """

    engine, make_observation = test_context

    original = make_observation()
    first_result = persist_observation(engine, original)

    conflicting = make_observation(
        value=f"changed-{uuid4().hex}.example.com",
    )

    conflicting_digest = calculate_indicator_digest(
        conflicting.indicator.value
    )

    with pytest.raises(
        ValueError,
        match="Source record identity conflict",
    ):
        persist_observation(engine, conflicting)

    # No canonical indicator should survive the failed
    # transaction for this conflicting identity.
    assert count_records(
        engine,
        "threat_indicators",
        "value_sha256",
        conflicting_digest,
    ) == 0

    # The original observation must still reference
    # its original canonical indicator.
    with engine.connect() as connection:
        indicator_id = connection.execute(
            text(
                """
                SELECT indicator_id
                FROM indicator_observations
                WHERE id = :id
                """
            ),
            {"id": first_result.observation_id},
        ).scalar_one()

    assert indicator_id == first_result.indicator_id
