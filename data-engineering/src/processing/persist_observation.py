
"""
ThreatForge - Threat Intelligence Observation Persistence

Persists one validated SourceObservation to PostgreSQL.

Responsibilities:
- Register intelligence sources.
- Calculate canonical indicator SHA-256 digests.
- Deduplicate canonical indicators.
- Verify digest identity.
- Insert new source observations.
- Update observations only when metadata changes.
- Leave identical observations unchanged.
- Reject source-record identity conflicts.
- Commit or roll back each operation atomically.

Observation history and ingestion-run tracking will
be implemented in subsequent milestones.

No external API requests are performed.
"""

import hashlib
import sys

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection, Engine

SRC_DIR = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(SRC_DIR / "models"))

from threat_indicator import SourceObservation  # noqa: E402


PersistenceAction = Literal["inserted", "updated", "unchanged"]


@dataclass(frozen=True)
class PersistenceResult:
    """Result of a successful persistence operation."""

    source_id: int
    indicator_id: int
    observation_id: int
    indicator_sha256: str
    action: PersistenceAction


def calculate_indicator_digest(normalized_value: str) -> str:
    """Calculate SHA-256 from normalized UTF-8 indicator text."""

    return hashlib.sha256(
        normalized_value.encode("utf-8")
    ).hexdigest()


def get_or_create_source(
    connection: Connection,
    source_name: str,
) -> int:
    """Return the existing or newly registered source ID."""

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
    connection: Connection,
    indicator_type: str,
    normalized_value: str,
) -> tuple[int, str]:
    """
    Resolve a canonical indicator by type and digest.

    A matching digest must also have an identical
    normalized value.
    """

    digest = calculate_indicator_digest(normalized_value)

    parameters = {
        "indicator_type": indicator_type,
        "normalized_value": normalized_value,
        "digest": digest,
    }

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
        parameters,
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
        parameters,
    ).one()

    if row.normalized_value != normalized_value:
        raise ValueError(
            "Indicator digest identity mismatch: "
            "stored normalized value differs"
        )

    return row.id, digest


# ---------------------------------------------------------
# Observation SQL
# ---------------------------------------------------------

OBSERVATION_INSERT = text(
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
    ) DO NOTHING
    RETURNING id
    """
).bindparams(
    bindparam("tags", type_=JSONB()),
)


OBSERVATION_SELECT = text(
    """
    SELECT
        id,
        indicator_id,
        threat_type,
        malware_family,
        confidence_level,
        first_seen,
        last_seen,
        timestamp_quality,
        reporter,
        reference,
        tags
    FROM indicator_observations
    WHERE source_id = :source_id
      AND source_record_id = :source_record_id
    FOR UPDATE
    """
)


OBSERVATION_UPDATE = text(
    """
    UPDATE indicator_observations
    SET
        threat_type = :threat_type,
        malware_family = :malware_family,
        confidence_level = :confidence_level,
        first_seen = :first_seen,
        last_seen = :last_seen,
        timestamp_quality = :timestamp_quality,
        reporter = :reporter,
        reference = :reference,
        tags = :tags
    WHERE id = :observation_id
    RETURNING id
    """
).bindparams(
    bindparam("tags", type_=JSONB()),
)


COMPARABLE_FIELDS = (
    "threat_type",
    "malware_family",
    "confidence_level",
    "first_seen",
    "last_seen",
    "timestamp_quality",
    "reporter",
    "reference",
    "tags",
)


def observation_has_changed(
    existing,
    parameters: dict,
) -> bool:
    """Check source observation metadata for real changes."""

    return any(
        existing[field] != parameters[field]
        for field in COMPARABLE_FIELDS
    )


def persist_observation(
    engine: Engine,
    observation: SourceObservation,
) -> PersistenceResult:
    """
    Persist one validated source observation atomically.

    Returns:
        inserted  - A new observation was stored.
        updated   - Existing metadata changed.
        unchanged - Existing metadata was identical.

    Existing source-record identities cannot silently
    switch to another canonical indicator.
    """

    if not isinstance(observation, SourceObservation):
        raise TypeError(
            "observation must be a SourceObservation instance"
        )

    indicator_type, normalized_value = (
        observation.indicator.canonical_key
    )

    with engine.begin() as connection:

        source_id = get_or_create_source(
            connection,
            observation.source_name,
        )

        indicator_id, digest = get_or_create_indicator(
            connection,
            indicator_type,
            normalized_value,
        )

        parameters = {
            "source_id": source_id,
            "indicator_id": indicator_id,
            "source_record_id": observation.source_record_id,
            "threat_type": observation.threat_type,
            "malware_family": observation.malware_family,
            "confidence_level": observation.confidence_level,
            "first_seen": observation.first_seen,
            "last_seen": observation.last_seen,
            "timestamp_quality": (
                observation.timestamp_quality.value
            ),
            "reporter": observation.reporter,
            "reference": observation.reference,
            "tags": observation.tags,
        }

        # Try creating a new source observation first.
        # A unique constraint prevents duplicate records.

        inserted_id = connection.execute(
            OBSERVATION_INSERT,
            parameters,
        ).scalar_one_or_none()

        if inserted_id is not None:
            observation_id = inserted_id
            action: PersistenceAction = "inserted"

        else:
            # Lock the existing row while comparing and
            # potentially updating its metadata.
            #
            # This prevents concurrent writers from
            # modifying this observation between the
            # comparison and the update.

            existing = connection.execute(
                OBSERVATION_SELECT,
                {
                    "source_id": source_id,
                    "source_record_id": (
                        observation.source_record_id
                    ),
                },
            ).mappings().one()

            if existing["indicator_id"] != indicator_id:
                raise ValueError(
                    "Source record identity conflict: "
                    "an existing record references a "
                    "different canonical indicator"
                )

            observation_id = existing["id"]

            if observation_has_changed(existing, parameters):
                connection.execute(
                    OBSERVATION_UPDATE,
                    {
                        **parameters,
                        "observation_id": observation_id,
                    },
                ).scalar_one()

                action = "updated"

            else:
                # No UPDATE statement is executed.
                # The database updated_at trigger does
                # not fire for unchanged observations.
                action = "unchanged"

    return PersistenceResult(
        source_id=source_id,
        indicator_id=indicator_id,
        observation_id=observation_id,
        indicator_sha256=digest,
        action=action,
    )
