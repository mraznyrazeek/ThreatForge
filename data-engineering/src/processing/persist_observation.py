
"""
ThreatForge - Threat Intelligence Observation Persistence

Persists one validated SourceObservation to PostgreSQL.

Responsibilities:
- Register an intelligence source.
- Calculate SHA-256 of the normalized indicator.
- Deduplicate canonical indicators.
- Verify digest identity against stored values.
- Insert or update source observations.
- Preserve timestamp quality classifications.
- Execute all operations within one transaction.

Observation history, ingestion-run tracking, and
bulk ingestion will be added in later steps.

No external API requests are performed.
"""

import hashlib
import sys

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine


SRC_DIR = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(SRC_DIR / "models"),
)

from threat_indicator import SourceObservation  # noqa: E402


@dataclass(frozen=True)
class PersistenceResult:
    """Identifiers of the successfully persisted record."""

    source_id: int
    indicator_id: int
    observation_id: int
    indicator_sha256: str


def calculate_indicator_digest(normalized_value: str) -> str:
    """Calculate SHA-256 from a canonical UTF-8 value."""

    return hashlib.sha256(
        normalized_value.encode("utf-8")
    ).hexdigest()


def get_or_create_source(connection, source_name: str) -> int:
    """Register an intelligence provider if necessary."""

    connection.execute(
        text(
            """
            INSERT INTO intelligence_sources (name)
            VALUES (:name)
            ON CONFLICT (name) DO NOTHING
            """
        ),
        {"name": source_name},
    )

    return connection.execute(
        text(
            """
            SELECT id
            FROM intelligence_sources
            WHERE name = :name
            """
        ),
        {"name": source_name},
    ).scalar_one()


def get_or_create_indicator(
    connection,
    indicator_type: str,
    normalized_value: str,
) -> tuple[int, str]:
    """
    Deduplicate a canonical indicator by type and digest.

    Verify the stored normalized value when a matching
    digest exists to protect against unexpected collisions
    or incorrect application-supplied digest values.
    """

    digest = calculate_indicator_digest(normalized_value)

    connection.execute(
        text(
            """
            INSERT INTO threat_indicators (
                indicator_type,
                normalized_value,
                value_sha256
            )
            VALUES (
                :indicator_type,
                :normalized_value,
                :digest
            )
            ON CONFLICT (
                indicator_type,
                value_sha256
            ) DO NOTHING
            """
        ),
        {
            "indicator_type": indicator_type,
            "normalized_value": normalized_value,
            "digest": digest,
        },
    )

    row = connection.execute(
        text(
            """
            SELECT id, normalized_value
            FROM threat_indicators
            WHERE indicator_type = :indicator_type
              AND value_sha256 = :digest
            """
        ),
        {
            "indicator_type": indicator_type,
            "digest": digest,
        },
    ).one()

    if row.normalized_value != normalized_value:
        raise ValueError(
            "Indicator digest identity mismatch: "
            "stored normalized value differs"
        )

    return row.id, digest


OBSERVATION_UPSERT = text(
    """
    INSERT INTO indicator_observations (
        source_id,
        indicator_id,
        source_record_id,
        threat_type,
        malware_family,
        confidence_level,
        first_seen,
        last_seen,
        timestamp_quality,
        reporter,
        reference,
        tags
    )
    VALUES (
        :source_id,
        :indicator_id,
        :source_record_id,
        :threat_type,
        :malware_family,
        :confidence_level,
        :first_seen,
        :last_seen,
        :timestamp_quality,
        :reporter,
        :reference,
        :tags
    )
    ON CONFLICT (
        source_id,
        source_record_id
    )
    DO UPDATE SET
        threat_type = EXCLUDED.threat_type,
        malware_family = EXCLUDED.malware_family,
        confidence_level = EXCLUDED.confidence_level,
        first_seen = EXCLUDED.first_seen,
        last_seen = EXCLUDED.last_seen,
        timestamp_quality = EXCLUDED.timestamp_quality,
        reporter = EXCLUDED.reporter,
        reference = EXCLUDED.reference,
        tags = EXCLUDED.tags
    WHERE indicator_observations.indicator_id =
          EXCLUDED.indicator_id
    RETURNING id
    """
).bindparams(
    bindparam("tags", type_=JSONB()),
)


def persist_observation(
    engine: Engine,
    observation: SourceObservation,
) -> PersistenceResult:
    """
    Persist one validated source observation atomically.

    The engine manages the database connection.

    A successful transaction creates or updates:
    - Intelligence source
    - Canonical threat indicator
    - Source-specific observation

    If an existing source_record_id points to a
    different canonical indicator, the operation
    fails rather than silently changing identity.

    All database changes roll back on failure.
    """

    if not isinstance(observation, SourceObservation):
        raise TypeError(
            "observation must be a SourceObservation instance"
        )

    indicator_type, normalized_value = (
        observation.indicator.canonical_key
    )

    with engine.begin() as connection:

        # Step 1: Resolve source identity.

        source_id = get_or_create_source(
            connection,
            observation.source_name,
        )

        # Step 2: Resolve canonical indicator identity.

        indicator_id, digest = get_or_create_indicator(
            connection,
            indicator_type,
            normalized_value,
        )

        # Step 3: Insert or update the source observation.

        observation_id = connection.execute(
            OBSERVATION_UPSERT,
            {
                "source_id": source_id,
                "indicator_id": indicator_id,
                "source_record_id": (
                    observation.source_record_id
                ),
                "threat_type": observation.threat_type,
                "malware_family": observation.malware_family,
                "confidence_level": (
                    observation.confidence_level
                ),
                "first_seen": observation.first_seen,
                "last_seen": observation.last_seen,
                "timestamp_quality": (
                    observation.timestamp_quality.value
                ),
                "reporter": observation.reporter,
                "reference": observation.reference,
                "tags": observation.tags,
            },
        ).scalar_one_or_none()

        if observation_id is None:
            raise ValueError(
                "Source record identity conflict: "
                "an existing record references a "
                "different canonical indicator"
            )

    return PersistenceResult(
        source_id=source_id,
        indicator_id=indicator_id,
        observation_id=observation_id,
        indicator_sha256=digest,
    )
