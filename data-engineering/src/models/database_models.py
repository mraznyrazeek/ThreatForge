
"""
ThreatForge - PostgreSQL Database Models

Defines the initial relational schema for threat
intelligence collection, normalization, storage,
data quality tracking, and observation history.

Tables:
1. intelligence_sources
2. ingestion_runs
3. threat_indicators
4. indicator_observations
5. observation_history
6. rejected_records

Uses SQLAlchemy 2.x declarative mapping.

Importing this module does not create database tables.
Schema changes are managed through Alembic migrations.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
)


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": (
        "fk_%(table_name)s_%(column_0_name)s_"
        "%(referred_table_name)s"
    ),
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all ThreatForge database models."""

    metadata = MetaData(
        naming_convention=NAMING_CONVENTION
    )


# ---------------------------------------------------------
# 1. Intelligence Sources
# ---------------------------------------------------------

class IntelligenceSource(Base):
    """Registered threat intelligence providers."""

    __tablename__ = "intelligence_sources"

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
    )

    base_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="true",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


# ---------------------------------------------------------
# 2. Ingestion Runs
# ---------------------------------------------------------

class IngestionRun(Base):
    """Tracks individual threat intelligence collection jobs."""

    __tablename__ = "ingestion_runs"

    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'failed')",
            name="valid_status",
        ),
        CheckConstraint(
            "records_received >= 0 AND "
            "records_normalized >= 0 AND "
            "records_rejected >= 0",
            name="nonnegative_counts",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default="running",
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    records_received: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )

    records_normalized: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )

    records_rejected: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )

    error_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


# ---------------------------------------------------------
# 3. Canonical Threat Indicators
# ---------------------------------------------------------

class ThreatIndicatorRecord(Base):
    """
    Stores unique canonical threat indicators.

    Identity:
        (indicator_type, value_sha256)

    The ingestion layer must calculate SHA-256 from the
    UTF-8 encoded normalized_value before insertion.

    When matching an existing digest, the ingestion
    layer must also compare normalized_value to detect
    the extremely unlikely possibility of a collision.

    The database enforces digest uniqueness but does
    not independently verify digest correctness.
    """

    __tablename__ = "threat_indicators"

    __table_args__ = (
        UniqueConstraint(
            "indicator_type",
            "value_sha256",
            name="uq_indicator_type_digest",
        ),
        CheckConstraint(
            "indicator_type IN "
            "('domain', 'url', 'ip:port', "
            "'md5_hash', 'sha1_hash', 'sha256_hash')",
            name="valid_indicator_type",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    normalized_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Application-managed digest.
    # Do not use a PostgreSQL generated column.
    value_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


# ---------------------------------------------------------
# 4. Indicator Observations
# ---------------------------------------------------------

class IndicatorObservation(Base):
    """
    Latest source-specific intelligence observation.

    Unique identity:
        (source_id, source_record_id)

    Timestamp anomalies are preserved and classified
    using the timestamp_quality field.

    The migration installs a PostgreSQL trigger to
    automatically maintain updated_at on SQL updates.
    """

    __tablename__ = "indicator_observations"

    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "source_record_id",
            name="uq_source_record",
        ),
        CheckConstraint(
            "confidence_level BETWEEN 0 AND 100",
            name="valid_confidence",
        ),
        CheckConstraint(
            "timestamp_quality IN "
            "('consistent', 'missing_last_seen', "
            "'reversed_interval')",
            name="valid_timestamp_quality",
        ),
        CheckConstraint(
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
            name="timestamp_quality_matches_interval",
        ),
        Index(
            "ix_observations_first_seen",
            "first_seen",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id"),
        nullable=False,
        index=True,
    )

    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("threat_indicators.id"),
        nullable=False,
        index=True,
    )

    latest_ingestion_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_runs.id"),
        nullable=True,
    )

    source_record_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    threat_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    malware_family: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    confidence_level: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    timestamp_quality: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    reporter: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    reference: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


# ---------------------------------------------------------
# 5. Observation History
# ---------------------------------------------------------

class ObservationHistory(Base):
    """
    Historical snapshots of source observations.

    The ingestion layer will create snapshots when
    relevant source intelligence changes.
    """

    __tablename__ = "observation_history"

    __table_args__ = (
        Index(
            "ix_history_observation_recorded",
            "observation_id",
            "recorded_at",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    observation_id: Mapped[int] = mapped_column(
        ForeignKey("indicator_observations.id"),
        nullable=False,
    )

    ingestion_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_runs.id"),
        nullable=True,
    )

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )


# ---------------------------------------------------------
# 6. Rejected Records
# ---------------------------------------------------------

class RejectedRecord(Base):
    """
    Records rejected during validation or normalization.

    Preserves source identity, structured diagnostic
    details, and original source payloads for controlled
    investigation and reprocessing.

    Payloads are untrusted data.

    Before live rejected-record persistence, implement
    access controls, safe diagnostic serialization,
    redaction, and data retention policies.
    """

    __tablename__ = "rejected_records"

    __table_args__ = (
        Index(
            "ix_rejected_records_source_received",
            "source_id",
            "received_at",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        Identity(),
        primary_key=True,
    )

    source_id: Mapped[int] = mapped_column(
        ForeignKey("intelligence_sources.id"),
        nullable=False,
    )

    ingestion_run_id: Mapped[int] = mapped_column(
        ForeignKey("ingestion_runs.id"),
        nullable=False,
    )

    source_record_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    rejection_category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    rejection_details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
