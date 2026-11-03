
"""
Preserve observation timestamps on ingestion-run linkage.

Revision ID: f2a0e94558b7
Revises: 48510eeeae7f

Purpose:
    Update the existing PostgreSQL trigger so that
    changing latest_ingestion_run_id alone does not
    modify the observation's updated_at timestamp.

    updated_at represents the last change to the
    observation's intelligence data, not the last
    ingestion run that processed the observation.

Behavior:
    - Intelligence data changes: refresh updated_at.
    - Ingestion-run linkage only: preserve updated_at.
    - Identical updates: preserve updated_at.

No table or column changes are made.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "f2a0e94558b7"

down_revision: Union[str, Sequence[str], None] = (
    "48510eeeae7f"
)

branch_labels: Union[str, Sequence[str], None] = None

depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Update timestamp trigger to distinguish intelligence
    metadata changes from ingestion-run linkage changes.
    """

    op.execute(
        """
        CREATE OR REPLACE FUNCTION
            threatforge_set_observation_updated_at()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF ROW(
                NEW.source_id,
                NEW.indicator_id,
                NEW.source_record_id,
                NEW.threat_type,
                NEW.malware_family,
                NEW.confidence_level,
                NEW.first_seen,
                NEW.last_seen,
                NEW.timestamp_quality,
                NEW.reporter,
                NEW.reference,
                NEW.tags
            ) IS DISTINCT FROM ROW(
                OLD.source_id,
                OLD.indicator_id,
                OLD.source_record_id,
                OLD.threat_type,
                OLD.malware_family,
                OLD.confidence_level,
                OLD.first_seen,
                OLD.last_seen,
                OLD.timestamp_quality,
                OLD.reporter,
                OLD.reference,
                OLD.tags
            ) THEN

                NEW.updated_at := clock_timestamp();

            ELSE

                NEW.updated_at := OLD.updated_at;

            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )


def downgrade() -> None:
    """
    Restore the original timestamp-trigger behavior.

    The previous implementation refreshed updated_at
    on every UPDATE, including ingestion-run linkage.
    """

    op.execute(
        """
        CREATE OR REPLACE FUNCTION
            threatforge_set_observation_updated_at()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            NEW.updated_at := clock_timestamp();

            RETURN NEW;
        END;
        $$;
        """
    )
