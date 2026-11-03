
"""
ThreatForge - Ingestion Run Lifecycle Service

Tracks the lifecycle of threat intelligence ingestion jobs.

Responsibilities:
- Start a new ingestion run.
- Mark a running job as completed.
- Mark a running job as failed.
- Store aggregate processing counts.
- Record timestamps automatically in PostgreSQL.
- Prevent invalid lifecycle transitions.
- Avoid storing raw exception messages or sensitive data.

Uses the existing ingestion_runs and intelligence_sources
tables. No schema changes are required.

This service does not fetch external intelligence,
normalize records, or modify indicator observations.
"""

from dataclasses import dataclass
from enum import Enum

from sqlalchemy import text
from sqlalchemy.engine import Engine

from persist_observation import get_or_create_source


class IngestionFailureCategory(str, Enum):
    """Approved categories for safe operational diagnostics."""

    API_FAILURE = "api_failure"
    NORMALIZATION_FAILURE = "normalization_failure"
    PERSISTENCE_FAILURE = "persistence_failure"
    CONFIGURATION_FAILURE = "configuration_failure"
    UNEXPECTED_FAILURE = "unexpected_failure"


@dataclass(frozen=True)
class IngestionRunResult:
    """Result of an ingestion run lifecycle transition."""

    run_id: int
    source_id: int
    status: str
    records_received: int
    records_normalized: int
    records_rejected: int


def validate_counts(
    records_received: int,
    records_normalized: int,
    records_rejected: int,
) -> None:
    """Validate aggregate ingestion counts."""

    values = (
        records_received,
        records_normalized,
        records_rejected,
    )

    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        for value in values
    ):
        raise ValueError(
            "Ingestion counts must be nonnegative integers"
        )

    if records_normalized + records_rejected > records_received:
        raise ValueError(
            "Normalized and rejected records cannot "
            "exceed received records"
        )


def start_ingestion_run(
    engine: Engine,
    source_name: str,
) -> IngestionRunResult:
    """
    Create a new ingestion run in the running state.

    The source is registered if it does not exist.

    Each call creates a new ingestion run, even when
    previous runs exist for the same source.
    """

    if not isinstance(source_name, str) or not source_name.strip():
        raise ValueError(
            "source_name must be a nonempty string"
        )

    with engine.begin() as connection:
        source_id = get_or_create_source(
            connection,
            source_name.strip(),
        )

        row = connection.execute(
            text(
                """
                INSERT INTO ingestion_runs (
                    source_id,
                    status
                )
                VALUES (
                    :source_id,
                    'running'
                )
                RETURNING
                    id,
                    source_id,
                    status,
                    records_received,
                    records_normalized,
                    records_rejected
                """
            ),
            {"source_id": source_id},
        ).mappings().one()

    return IngestionRunResult(
        run_id=row["id"],
        source_id=row["source_id"],
        status=row["status"],
        records_received=row["records_received"],
        records_normalized=row["records_normalized"],
        records_rejected=row["records_rejected"],
    )


def complete_ingestion_run(
    engine: Engine,
    run_id: int,
    records_received: int,
    records_normalized: int,
    records_rejected: int,
) -> IngestionRunResult:
    """
    Complete an existing running ingestion job.

    Counts describe records received, successfully
    normalized, and rejected during processing.

    A completed run may contain rejected records.
    The caller must decide whether any unresolved
    persistence failures make the run unsuccessful.

    Only running jobs can transition to completed.
    """

    validate_counts(
        records_received,
        records_normalized,
        records_rejected,
    )

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE ingestion_runs
                SET
                    status = 'completed',
                    completed_at = clock_timestamp(),
                    records_received = :received,
                    records_normalized = :normalized,
                    records_rejected = :rejected,
                    error_summary = NULL
                WHERE id = :run_id
                  AND status = 'running'
                RETURNING
                    id,
                    source_id,
                    status,
                    records_received,
                    records_normalized,
                    records_rejected
                """
            ),
            {
                "run_id": run_id,
                "received": records_received,
                "normalized": records_normalized,
                "rejected": records_rejected,
            },
        ).mappings().one_or_none()

        if row is None:
            raise ValueError(
                "Ingestion run does not exist "
                "or is no longer running"
            )

    return IngestionRunResult(
        run_id=row["id"],
        source_id=row["source_id"],
        status=row["status"],
        records_received=row["records_received"],
        records_normalized=row["records_normalized"],
        records_rejected=row["records_rejected"],
    )


def fail_ingestion_run(
    engine: Engine,
    run_id: int,
    failure_category: IngestionFailureCategory,
    records_received: int = 0,
    records_normalized: int = 0,
    records_rejected: int = 0,
) -> IngestionRunResult:
    """
    Mark an existing running ingestion job as failed.

    Stores only an approved failure category.

    Raw exception text, provider responses, credentials,
    and potentially sensitive IOC data are never stored
    in the error_summary column by this function.

    Only running jobs can transition to failed.
    """

    if not isinstance(
        failure_category,
        IngestionFailureCategory,
    ):
        raise TypeError(
            "failure_category must be an "
            "IngestionFailureCategory"
        )

    validate_counts(
        records_received,
        records_normalized,
        records_rejected,
    )

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE ingestion_runs
                SET
                    status = 'failed',
                    completed_at = clock_timestamp(),
                    records_received = :received,
                    records_normalized = :normalized,
                    records_rejected = :rejected,
                    error_summary = :error_summary
                WHERE id = :run_id
                  AND status = 'running'
                RETURNING
                    id,
                    source_id,
                    status,
                    records_received,
                    records_normalized,
                    records_rejected
                """
            ),
            {
                "run_id": run_id,
                "received": records_received,
                "normalized": records_normalized,
                "rejected": records_rejected,
                "error_summary": failure_category.value,
            },
        ).mappings().one_or_none()

        if row is None:
            raise ValueError(
                "Ingestion run does not exist "
                "or is no longer running"
            )

    return IngestionRunResult(
        run_id=row["id"],
        source_id=row["source_id"],
        status=row["status"],
        records_received=row["records_received"],
        records_normalized=row["records_normalized"],
        records_rejected=row["records_rejected"],
    )
