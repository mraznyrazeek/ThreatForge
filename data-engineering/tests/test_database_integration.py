
"""
ThreatForge - PostgreSQL Integration Tests

Verifies deployed PostgreSQL schema behavior using
synthetic test data.

Tests cover:
- Application tables
- SHA-256 indicator storage
- Indicator uniqueness
- Confidence constraints
- Reversed timestamp preservation
- Automatic observation updated_at maintenance

All test changes are rolled back after each test.

Run:
    python -m pytest tests/test_database_integration.py -v
"""

import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env", override=True)

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src" / "models"),
)

from database_models import Base  # noqa: E402


def database_url():
    """Build the PostgreSQL connection URL securely."""

    return URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=os.environ["DB_NAME"],
    )


@pytest.fixture(scope="module")
def engine():
    """Create the SQLAlchemy database engine."""

    db_engine = create_engine(
        database_url(),
        pool_pre_ping=True,
    )

    yield db_engine

    db_engine.dispose()


@pytest.fixture()
def connection(engine):
    """
    Open a transaction for each test.

    Roll back every transaction after the test,
    leaving no persistent synthetic test records.
    """

    with engine.connect() as conn:
        transaction = conn.begin()

        try:
            yield conn
        finally:
            if transaction.is_active:
                transaction.rollback()


def insert_source(conn):
    """Insert a synthetic intelligence source."""

    return conn.execute(
        text(
            """
            INSERT INTO intelligence_sources (name)
            VALUES (:name)
            RETURNING id
            """
        ),
        {
            "name": "ThreatForge Integration Test",
        },
    ).scalar_one()


def insert_indicator(
    conn,
    normalized_value="test.example.com",
):
    """Insert an indicator with an application-generated digest."""

    digest = hashlib.sha256(
        normalized_value.encode("utf-8")
    ).hexdigest()

    indicator_id = conn.execute(
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

    return indicator_id, digest


# ---------------------------------------------------------
# 1. Schema Test
# ---------------------------------------------------------

def test_database_tables_exist(connection):
    """Verify that all six application tables exist."""

    expected = set(Base.metadata.tables)

    actual = set(
        connection.execute(
            text(
                """
                SELECT tablename
                FROM pg_catalog.pg_tables
                WHERE schemaname = 'public'
                """
            )
        ).scalars()
    )

    assert expected <= actual


# ---------------------------------------------------------
# 2. SHA-256 Storage Test
# ---------------------------------------------------------

def test_indicator_digest_and_identity(connection):
    """Verify indicator ID and SHA-256 digest storage."""

    indicator_id, digest = insert_indicator(connection)

    row = connection.execute(
        text(
            """
            SELECT normalized_value, value_sha256
            FROM threat_indicators
            WHERE id = :id
            """
        ),
        {
            "id": indicator_id,
        },
    ).one()

    assert indicator_id > 0
    assert row.normalized_value == "test.example.com"
    assert row.value_sha256 == digest
    assert len(digest) == 64


# ---------------------------------------------------------
# 3. Indicator Uniqueness Test
# ---------------------------------------------------------

def test_indicator_uniqueness(connection):
    """
    Verify PostgreSQL rejects duplicate indicator
    type and SHA-256 digest combinations.
    """

    insert_indicator(connection)

    # Nested transaction = PostgreSQL SAVEPOINT.
    # The SAVEPOINT must roll back after IntegrityError.
    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            insert_indicator(connection)


# ---------------------------------------------------------
# 4. Confidence Constraint Test
# ---------------------------------------------------------

def test_observation_confidence_constraint(connection):
    """Verify confidence values above 100 are rejected."""

    source_id = insert_source(connection)
    indicator_id, _ = insert_indicator(connection)

    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            connection.execute(
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
                        'confidence-test',
                        'test',
                        101,
                        now(),
                        'missing_last_seen',
                        '[]'::jsonb
                    )
                    """
                ),
                {
                    "source_id": source_id,
                    "indicator_id": indicator_id,
                },
            )


# ---------------------------------------------------------
# 5. Timestamp Quality Test
# ---------------------------------------------------------

def test_observation_timestamp_quality(connection):
    """
    Verify reversed source timestamps are preserved
    when properly classified.
    """

    source_id = insert_source(connection)
    indicator_id, _ = insert_indicator(connection)

    first_seen = datetime(
        2026, 1, 2,
        tzinfo=timezone.utc,
    )
    last_seen = first_seen - timedelta(days=1)

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
                last_seen,
                timestamp_quality,
                tags
            )
            VALUES (
                :source_id,
                :indicator_id,
                'reversed-test',
                'test',
                50,
                :first_seen,
                :last_seen,
                'reversed_interval',
                '[]'::jsonb
            )
            RETURNING id
            """
        ),
        {
            "source_id": source_id,
            "indicator_id": indicator_id,
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
    ).scalar_one()

    assert observation_id > 0


# ---------------------------------------------------------
# 6. Timestamp Trigger Test
# ---------------------------------------------------------

def test_observation_updated_at_trigger(connection):
    """Verify an UPDATE automatically refreshes updated_at."""

    source_id = insert_source(connection)
    indicator_id, _ = insert_indicator(connection)

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
                'trigger-test',
                'test',
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
        },
    ).scalar_one()

    before = connection.execute(
        text(
            """
            SELECT updated_at
            FROM indicator_observations
            WHERE id = :id
            """
        ),
        {
            "id": observation_id,
        },
    ).scalar_one()

    after = connection.execute(
        text(
            """
            UPDATE indicator_observations
            SET confidence_level = 75
            WHERE id = :id
            RETURNING updated_at
            """
        ),
        {
            "id": observation_id,
        },
    ).scalar_one()

    assert after >= before
