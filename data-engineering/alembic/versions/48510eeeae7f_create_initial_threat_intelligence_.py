
"""
Create initial ThreatForge threat intelligence schema.

Revision ID: 48510eeeae7f
Revises:
Create Date: 2026-11-02

Creates six application tables and an observation
timestamp maintenance trigger.

SHA-256 digests are calculated by the Python ingestion
layer and stored as ordinary database columns.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "48510eeeae7f"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the initial ThreatForge database schema."""

    # 1. Intelligence sources

    op.create_table(
        "intelligence_sources",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            "name",
            sa.String(100),
            nullable=False,
        ),
        sa.Column(
            "base_url",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "name",
            name="uq_intelligence_sources_name",
        ),
    )

    # 2. Canonical threat indicators

    op.create_table(
        "threat_indicators",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            "indicator_type",
            sa.String(30),
            nullable=False,
        ),
        sa.Column(
            "normalized_value",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "value_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "indicator_type IN "
            "('domain', 'url', 'ip:port', "
            "'md5_hash', 'sha1_hash', 'sha256_hash')",
            name="ck_threat_indicators_valid_indicator_type",
        ),
        sa.UniqueConstraint(
            "indicator_type",
            "value_sha256",
            name="uq_indicator_type_digest",
        ),
    )

    # 3. Ingestion runs

    op.create_table(
        "ingestion_runs",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            "source_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(20),
            server_default="running",
            nullable=False,
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "records_received",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "records_normalized",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "records_rejected",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "error_summary",
            sa.Text(),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed')",
            name="ck_ingestion_runs_valid_status",
        ),
        sa.CheckConstraint(
            "records_received >= 0 AND "
            "records_normalized >= 0 AND "
            "records_rejected >= 0",
            name="ck_ingestion_runs_nonnegative_counts",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_ingestion_runs_source_id_intelligence_sources",
        ),
    )

    op.create_index(
        "ix_ingestion_runs_source_id",
        "ingestion_runs",
        ["source_id"],
    )

    # 4. Indicator observations

    op.create_table(
        "indicator_observations",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            "source_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "indicator_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "latest_ingestion_run_id",
            sa.BigInteger(),
            nullable=True,
        ),
        sa.Column(
            "source_record_id",
            sa.String(255),
            nullable=False,
        ),
        sa.Column(
            "threat_type",
            sa.String(100),
            nullable=False,
        ),
        sa.Column(
            "malware_family",
            sa.String(255),
            nullable=True,
        ),
        sa.Column(
            "confidence_level",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "timestamp_quality",
            sa.String(30),
            nullable=False,
        ),
        sa.Column(
            "reporter",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "reference",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "tags",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "confidence_level BETWEEN 0 AND 100",
            name="ck_indicator_observations_valid_confidence",
        ),
        sa.CheckConstraint(
            "timestamp_quality IN "
            "('consistent', 'missing_last_seen', "
            "'reversed_interval')",
            name="ck_indicator_observations_valid_timestamp_quality",
        ),
        sa.CheckConstraint(
            "("
            "timestamp_quality = 'missing_last_seen' "
            "AND last_seen IS NULL"
            ") OR ("
            "timestamp_quality = 'consistent' "
            "AND last_seen >= first_seen"
            ") OR ("
            "timestamp_quality = 'reversed_interval' "
            "AND last_seen < first_seen"
            ")",
            name=(
                "ck_indicator_observations_"
                "timestamp_quality_matches_interval"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=(
                "fk_indicator_observations_"
                "source_id_intelligence_sources"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["threat_indicators.id"],
            name=(
                "fk_indicator_observations_"
                "indicator_id_threat_indicators"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["latest_ingestion_run_id"],
            ["ingestion_runs.id"],
            name="fk_observations_latest_ingestion_run",
        ),
        sa.UniqueConstraint(
            "source_id",
            "source_record_id",
            name="uq_source_record",
        ),
    )

    op.create_index(
        "ix_indicator_observations_source_id",
        "indicator_observations",
        ["source_id"],
    )

    op.create_index(
        "ix_indicator_observations_indicator_id",
        "indicator_observations",
        ["indicator_id"],
    )

    op.create_index(
        "ix_observations_first_seen",
        "indicator_observations",
        ["first_seen"],
    )

    # 5. Observation history

    op.create_table(
        "observation_history",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            "observation_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "ingestion_run_id",
            sa.BigInteger(),
            nullable=True,
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "snapshot",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            ["indicator_observations.id"],
            name=(
                "fk_observation_history_"
                "observation_id_indicator_observations"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_run_id"],
            ["ingestion_runs.id"],
            name=(
                "fk_observation_history_"
                "ingestion_run_id_ingestion_runs"
            ),
        ),
    )

    op.create_index(
        "ix_history_observation_recorded",
        "observation_history",
        ["observation_id", "recorded_at"],
    )

    # 6. Rejected records

    op.create_table(
        "rejected_records",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(),
            primary_key=True,
        ),
        sa.Column(
            "source_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "ingestion_run_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "source_record_id",
            sa.String(255),
            nullable=True,
        ),
        sa.Column(
            "rejection_category",
            sa.String(100),
            nullable=False,
        ),
        sa.Column(
            "rejection_details",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "raw_payload",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name=(
                "fk_rejected_records_"
                "source_id_intelligence_sources"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["ingestion_run_id"],
            ["ingestion_runs.id"],
            name=(
                "fk_rejected_records_"
                "ingestion_run_id_ingestion_runs"
            ),
        ),
    )

    op.create_index(
        "ix_rejected_records_source_received",
        "rejected_records",
        ["source_id", "received_at"],
    )

    # 7. Observation update timestamp trigger

    op.execute(
        """
        CREATE FUNCTION threatforge_set_observation_updated_at()
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

    op.execute(
        """
        CREATE TRIGGER trg_indicator_observations_updated_at
        BEFORE UPDATE ON indicator_observations
        FOR EACH ROW
        EXECUTE FUNCTION threatforge_set_observation_updated_at();
        """
    )


def downgrade() -> None:
    """
    Remove the initial schema.

    WARNING: Downgrading permanently deletes all
    stored records in the six application tables.
    """

    op.execute(
        """
        DROP TRIGGER IF EXISTS
        trg_indicator_observations_updated_at
        ON indicator_observations;
        """
    )

    op.execute(
        """
        DROP FUNCTION IF EXISTS
        threatforge_set_observation_updated_at();
        """
    )

    op.drop_index(
        "ix_rejected_records_source_received",
        table_name="rejected_records",
    )
    op.drop_table("rejected_records")

    op.drop_index(
        "ix_history_observation_recorded",
        table_name="observation_history",
    )
    op.drop_table("observation_history")

    op.drop_index(
        "ix_observations_first_seen",
        table_name="indicator_observations",
    )
    op.drop_index(
        "ix_indicator_observations_indicator_id",
        table_name="indicator_observations",
    )
    op.drop_index(
        "ix_indicator_observations_source_id",
        table_name="indicator_observations",
    )
    op.drop_table("indicator_observations")

    op.drop_index(
        "ix_ingestion_runs_source_id",
        table_name="ingestion_runs",
    )
    op.drop_table("ingestion_runs")

    op.drop_table("threat_indicators")
    op.drop_table("intelligence_sources")
