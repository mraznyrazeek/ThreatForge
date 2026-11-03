
"""
ThreatForge - Observation Run Linkage Trigger Tests

Validates the PostgreSQL trigger introduced by migration
f2a0e94558b7.

Tests:
1. Linkage-only updates preserve updated_at.
2. Intelligence metadata updates refresh updated_at.
3. Identical updates preserve updated_at.

Only runs against threatforge_test_db.

All synthetic records are inserted into a transaction
that is rolled back after testing.

No API requests or production database writes.
"""

import hashlib
import os
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    PROJECT_ROOT / ".env",
    override=False,
)

TEST_DATABASE = "threatforge_test_db"


@pytest.fixture(scope="module")
def engine():
    """Connect exclusively to the test database."""

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
def connection(engine):
    """
    Run each test in a rollback-only transaction.

    No synthetic source, indicator, run, or observation
    will be permanently stored.
    """

    with engine.connect() as conn:
        transaction = conn.begin()

        try:
            yield conn
        finally:
            if transaction.is_active:
                transaction.rollback()


def create_test_records(connection):
    """
    Create synthetic source, indicator, ingestion runs,
    and observation within the current transaction.
    """

    token = uuid4().hex

    source_id = connection.execute(
        text(
            """
            INSERT INTO intelligence_sources (name)
            VALUES (:name)
            RETURNING id
            """
        ),
        {"name": f"ThreatForgeLinkageTest_{token}"},
    ).scalar_one()

    normalized_value = f"linkage-{token}.example.com"

    digest = hashlib.sha256(
        normalized_value.encode("utf-8")
    ).hexdigest()

    indicator_id = connection.execute(
        text(
            """
            INSERT INTO threat_indicators (
                indicator_type,
                normalized_value,
                value_sha256
            )
            VALUES (
                'domain',
                :value,
                :digest
            )
            RETURNING id
            """
        ),
        {
            "value": normalized_value,
            "digest": digest,
        },
    ).scalar_one()

    run_ids = []

    for _ in range(2):
        run_id = connection.execute(
            text(
                """
                INSERT INTO ingestion_runs (source_id)
                VALUES (:source_id)
                RETURNING id
                """
            ),
            {"source_id": source_id},
        ).scalar_one()

        run_ids.append(run_id)

    observation_id = connection.execute(
        text(
            """
            INSERT INTO indicator_observations (
                source_id,
                indicator_id,
                source_record_id,
                threat_type,
                confidence_level,
                first_seen,
                timestamp_quality,
                tags
            )
            VALUES (
                :source_id,
                :indicator_id,
                :source_record_id,
                'payload',
                50,
                now(),
                'missing_last_seen',
                '[]'::jsonb
            )
            RETURNING id
            """
        ),
        {
            "source_id": source_id,
            "indicator_id": indicator_id,
            "source_record_id": f"record_{token}",
        },
    ).scalar_one()

    return observation_id, run_ids


def read_updated_at(connection, observation_id):
    """Read the observation metadata-update timestamp."""

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


def test_linkage_only_preserves_updated_at(connection):
    """
    Changing latest_ingestion_run_id must not alter
    the intelligence metadata timestamp.
    """

    observation_id, run_ids = create_test_records(
        connection
    )

    before = read_updated_at(
        connection,
        observation_id,
    )

    for run_id in run_ids:
        connection.execute(
            text(
                """
                UPDATE indicator_observations
                SET latest_ingestion_run_id = :run_id
                WHERE id = :observation_id
                """
            ),
            {
                "run_id": run_id,
                "observation_id": observation_id,
            },
        )

        after = read_updated_at(
            connection,
            observation_id,
        )

        assert after == before

    linked_run_id = connection.execute(
        text(
            """
            SELECT latest_ingestion_run_id
            FROM indicator_observations
            WHERE id = :observation_id
            """
        ),
        {"observation_id": observation_id},
    ).scalar_one()

    assert linked_run_id == run_ids[-1]


def test_metadata_change_refreshes_updated_at(connection):
    """
    Changing confidence_level must refresh updated_at,
    even when run linkage is updated simultaneously.
    """

    observation_id, run_ids = create_test_records(
        connection
    )

    before = read_updated_at(
        connection,
        observation_id,
    )

    after = connection.execute(
        text(
            """
            UPDATE indicator_observations
            SET
                confidence_level = 85,
                latest_ingestion_run_id = :run_id
            WHERE id = :observation_id
            RETURNING updated_at
            """
        ),
        {
            "run_id": run_ids[0],
            "observation_id": observation_id,
        },
    ).scalar_one()

    assert after > before


def test_identical_update_preserves_updated_at(connection):
    """An identical metadata update must not refresh the timestamp."""

    observation_id, _ = create_test_records(
        connection
    )

    before = read_updated_at(
        connection,
        observation_id,
    )

    after = connection.execute(
        text(
            """
            UPDATE indicator_observations
            SET confidence_level = confidence_level
            WHERE id = :observation_id
            RETURNING updated_at
            """
        ),
        {"observation_id": observation_id},
    ).scalar_one()

    assert after == before
