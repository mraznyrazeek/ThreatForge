
"""
ThreatForge - Rejected Record Persistence

Stores sanitized processing rejection metadata.

Security:
- Never stores raw provider payloads.
- Never stores exception messages or API credentials.
- Uses approved rejection categories and reason codes.
- Requires an active ingestion run.
- Verifies the ingestion run belongs to the given source.
- Uses one atomic database transaction.

The raw_payload column is NOT NULL, so an empty JSON
object is intentionally stored.

No external API calls are performed.
"""

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine


RejectionCategory = Literal[
    "normalization_failure",
    "identity_conflict",
    "persistence_failure",
]

ALLOWED_REASON_CODES = {
    "validation_failed",
    "invalid_record_structure",
    "source_identity_conflict",
    "database_operation_failed",
}


@dataclass(frozen=True)
class RejectionResult:
    rejected_record_id: int
    source_id: int
    ingestion_run_id: int
    rejection_category: RejectionCategory


INSERT_REJECTION = text(
    """
    INSERT INTO rejected_records (
        source_id,
        ingestion_run_id,
        source_record_id,
        rejection_category,
        rejection_details,
        raw_payload
    )
    VALUES (
        :source_id,
        :ingestion_run_id,
        :source_record_id,
        :rejection_category,
        :rejection_details,
        :raw_payload
    )
    RETURNING id
    """
).bindparams(
    bindparam("rejection_details", type_=JSONB()),
    bindparam("raw_payload", type_=JSONB()),
)


def persist_rejected_record(
    engine: Engine,
    *,
    source_id: int,
    ingestion_run_id: int,
    rejection_category: RejectionCategory,
    reason_code: str,
    source_record_id: str | None = None,
) -> RejectionResult:
    """
    Persist one sanitized rejection atomically.

    The reason_code is an approved machine-readable value,
    not a raw validation or database exception message.

    source_record_id is optional. Callers should omit it
    unless the value is known to be safe to retain.
    """

    for field_name, value in (
        ("source_id", source_id),
        ("ingestion_run_id", ingestion_run_id),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        ):
            raise ValueError(
                f"{field_name} must be a positive integer"
            )

    allowed_categories = {
        "normalization_failure",
        "identity_conflict",
        "persistence_failure",
    }

    if rejection_category not in allowed_categories:
        raise ValueError(
            "Unsupported rejection category"
        )

    if reason_code not in ALLOWED_REASON_CODES:
        raise ValueError(
            "Unsupported rejection reason code"
        )

    if source_record_id is not None:
        if (
            not isinstance(source_record_id, str)
            or not source_record_id
            or len(source_record_id) > 255
        ):
            raise ValueError(
                "source_record_id must be a nonempty "
                "string of at most 255 characters"
            )

    with engine.begin() as connection:
        run = connection.execute(
            text(
                """
                SELECT source_id, status
                FROM ingestion_runs
                WHERE id = :run_id
                FOR SHARE
                """
            ),
            {"run_id": ingestion_run_id},
        ).mappings().one_or_none()

        if run is None:
            raise ValueError(
                "Ingestion run does not exist"
            )

        if run["source_id"] != source_id:
            raise ValueError(
                "Ingestion run belongs to a different source"
            )

        if run["status"] != "running":
            raise ValueError(
                "Ingestion run is not in running status"
            )

        rejected_id = connection.execute(
            INSERT_REJECTION,
            {
                "source_id": source_id,
                "ingestion_run_id": ingestion_run_id,
                "source_record_id": source_record_id,
                "rejection_category": rejection_category,
                "rejection_details": {
                    "reason_code": reason_code,
                },
                "raw_payload": {},
            },
        ).scalar_one()

    return RejectionResult(
        rejected_record_id=rejected_id,
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        rejection_category=rejection_category,
    )
