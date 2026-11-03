
"""
ThreatForge - Threat Intelligence Observation Persistence

Persists one validated SourceObservation to PostgreSQL.

Responsibilities:
- Register intelligence sources.
- Calculate canonical indicator SHA-256 digests.
- Deduplicate canonical indicators.
- Verify stored digest identity.
- Insert new source observations.
- Update observations only when intelligence metadata changes.
- Leave identical intelligence metadata unchanged.
- Optionally link observations to a running ingestion run.
- Verify ingestion-run source identity and lifecycle status.
- Preserve updated_at for linkage-only updates.
- Reject source-record identity conflicts.
- Commit or roll back each operation atomically.

Observation history and rejected-record persistence will
be implemented in later steps.

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

sys.path.insert(
    0,
    str(SRC_DIR / "models"),
)

from threat_indicator import SourceObservation  # noqa: E402


PersistenceAction = Literal[
    "inserted",
    "updated",
    "unchanged",
]


@dataclass(frozen=True)
class PersistenceResult:
    """Result of a successful persistence operation."""

    source_id: int
    indicator_id: int
    observation_id: int
    indicator_sha256: str
    action: PersistenceAction


# ---------------------------------------------------------
# Indicator identity
# ---------------------------------------------------------

def calculate_indicator_digest(normalized_value: str) -> str:
    """Calculate SHA-256 from normalized UTF-8 indicator text."""

    return hashlib.sha256(
        normalized_value.encode("utf-8")
    ).hexdigest()


def get_or_create_source(
    connection: Connection,
    source_name: str,
) -> int:
    """Return an existing or newly registered source ID."""

    connection.execute(
        text(
            """
            INSERT INTO intelligence_sources (name)
            VALUES (:name)
            ON CONFLICT (name) DO NOTHING
            """
        ),
        {
            "name": source_name,
        },
    )

    return connection.execute(
        text(
            """
            SELECT id
            FROM intelligence_sources
            WHERE name = :name
            """
        ),
        {
            "name": source_name,
        },
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
# Ingestion-run validation
# ---------------------------------------------------------

def validate_ingestion_run(
    connection: Connection,
    ingestion_run_id: int,
    source_id: int,
) -> None:
    """
    Validate that an ingestion run:
    - Exists.
    - Belongs to the same intelligence source.
    - Is still running.

    FOR SHARE protects the selected run from concurrent
    status changes until the current transaction finishes.
    """

    row = connection.execute(
        text(
            """
            SELECT source_id, status
            FROM ingestion_runs
            WHERE id = :run_id
            FOR SHARE
            """
        ),
        {
            "run_id": ingestion_run_id,
        },
    ).mappings().one_or_none()

    if row is None:
        raise ValueError(
            "Ingestion run does not exist"
        )

    if row["source_id"] != source_id:
        raise ValueError(
            "Ingestion run belongs to a different source"
        )

    if row["status"] != "running":
        raise ValueError(
            "Ingestion run is not in running status"
        )


# ---------------------------------------------------------
# Observation SQL
# ---------------------------------------------------------

OBSERVATION_INSERT = text(
    """
    INSERT INTO indicator_observations (
        source_id,
        indicator_id,
        latest_ingestion_run_id,
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
        :ingestion_run_id,
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
        latest_ingestion_run_id,
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
        latest_ingestion_run_id = COALESCE(
            :ingestion_run_id,
            latest_ingestion_run_id
        ),
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


OBSERVATION_LINK_RUN = text(
    """
    UPDATE indicator_observations
    SET latest_ingestion_run_id = :ingestion_run_id
    WHERE id = :observation_id
    RETURNING id
    """
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
    """Check whether intelligence metadata has changed."""

    return any(
        existing[field] != parameters[field]
        for field in COMPARABLE_FIELDS
    )


# ---------------------------------------------------------
# Main persistence operation
# ---------------------------------------------------------

def persist_observation(
    engine: Engine,
    observation: SourceObservation,
    ingestion_run_id: int | None = None,
) -> PersistenceResult:
    """
    Persist one validated source observation atomically.

    Optional ingestion_run_id links the observation
    to an active run belonging to the same source.

    Actions:
        inserted:
            A new observation was created.

        updated:
            Existing intelligence metadata changed.

        unchanged:
            Intelligence metadata was identical.

    An unchanged observation may still have its latest
    ingestion run updated. The PostgreSQL trigger
    preserves updated_at for linkage-only updates.

    Calls without ingestion_run_id remain supported
    for existing tests and independent persistence.
    """

    if not isinstance(observation, SourceObservation):
        raise TypeError(
            "observation must be a SourceObservation instance"
        )

    if ingestion_run_id is not None:
        if (
            not isinstance(ingestion_run_id, int)
            or isinstance(ingestion_run_id, bool)
            or ingestion_run_id <= 0
        ):
            raise ValueError(
                "ingestion_run_id must be a positive integer"
            )

    indicator_type, normalized_value = (
        observation.indicator.canonical_key
    )

    with engine.begin() as connection:

        # 1. Resolve intelligence source.

        source_id = get_or_create_source(
            connection,
            observation.source_name,
        )

        # 2. Validate the optional ingestion-run link.

        if ingestion_run_id is not None:
            validate_ingestion_run(
                connection,
                ingestion_run_id,
                source_id,
            )

        # 3. Resolve canonical indicator identity.

        indicator_id, digest = get_or_create_indicator(
            connection,
            indicator_type,
            normalized_value,
        )

        # 4. Prepare validated observation values.

        parameters = {
            "source_id": source_id,
            "indicator_id": indicator_id,
            "ingestion_run_id": ingestion_run_id,
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

        # 5. Attempt first-time insertion.

        inserted_id = connection.execute(
            OBSERVATION_INSERT,
            parameters,
        ).scalar_one_or_none()

        if inserted_id is not None:
            observation_id = inserted_id
            action: PersistenceAction = "inserted"

        else:
            # 6. Lock and inspect the existing observation.

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

            metadata_changed = observation_has_changed(
                existing,
                parameters,
            )

            if metadata_changed:

                # 7A. Update intelligence metadata.
                # Include the new run ID when supplied.

                connection.execute(
                    OBSERVATION_UPDATE,
                    {
                        **parameters,
                        "observation_id": observation_id,
                    },
                ).scalar_one()

                action = "updated"

            else:
                # 7B. Intelligence metadata is unchanged.
                #
                # Update only the ingestion-run link
                # when a different run was supplied.

                if (
                    ingestion_run_id is not None
                    and existing["latest_ingestion_run_id"]
                    != ingestion_run_id
                ):
                    connection.execute(
                        OBSERVATION_LINK_RUN,
                        {
                            "observation_id": observation_id,
                            "ingestion_run_id": ingestion_run_id,
                        },
                    ).scalar_one()

                action = "unchanged"

    return PersistenceResult(
        source_id=source_id,
        indicator_id=indicator_id,
        observation_id=observation_id,
        indicator_sha256=digest,
        action=action,
    )
