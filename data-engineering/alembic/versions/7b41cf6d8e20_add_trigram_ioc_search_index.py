
"""
Add a trigram index for ThreatForge IOC substring searches.

Revision ID: 7b41cf6d8e20
Revises: f2a0e94558b7

Purpose:
    Accelerate case-insensitive substring searches on
    threat_indicators.normalized_value.

    The API uses:
        lower(normalized_value) LIKE :pattern ESCAPE '\'

    The GIN index uses the matching lower() expression.

Downgrade:
    Remove the migration-managed index.
    Preserve pg_trgm because other database objects
    may depend on the extension.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "7b41cf6d8e20"

down_revision: Union[str, Sequence[str], None] = (
    "f2a0e94558b7"
)

branch_labels: Union[str, Sequence[str], None] = None

depends_on: Union[str, Sequence[str], None] = None


INDEX_NAME = "ix_threat_indicators_normalized_value_trgm"


def upgrade() -> None:
    """Enable trigram support and create the IOC search index."""

    op.execute(
        "CREATE EXTENSION IF NOT EXISTS pg_trgm"
    )

    op.execute(
        f"""
        CREATE INDEX {INDEX_NAME}
        ON public.threat_indicators
        USING GIN (
            lower(normalized_value) gin_trgm_ops
        )
        """
    )


def downgrade() -> None:
    """Remove the IOC search index, preserving pg_trgm."""

    op.execute(
        f"""
        DROP INDEX public.{INDEX_NAME}
        """
    )
