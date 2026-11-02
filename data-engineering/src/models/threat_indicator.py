
"""
ThreatForge - Normalized Threat Intelligence Models

Defines canonical indicators and source-specific observations.

Timestamp policy:
- Valid chronological intervals are accepted.
- Missing last_seen timestamps are accepted.
- Reversed intervals are rejected by default.
- Trusted source adapters may explicitly preserve
  reversed intervals with a quality warning.

No network requests or database writes are performed.
"""

import ipaddress
import re

from datetime import datetime, timezone
from enum import Enum
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class IndicatorType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP_PORT = "ip:port"
    SHA256 = "sha256_hash"
    SHA1 = "sha1_hash"
    MD5 = "md5_hash"


class TimestampQuality(str, Enum):
    CONSISTENT = "consistent"
    MISSING_LAST_SEEN = "missing_last_seen"
    REVERSED_INTERVAL = "reversed_interval"


HASH_LENGTHS = {
    IndicatorType.SHA256: 64,
    IndicatorType.SHA1: 40,
    IndicatorType.MD5: 32,
}


def validate_domain(value: str) -> None:
    """Validate the syntax of an ASCII domain name."""

    if len(value) > 253:
        raise ValueError("Domain exceeds 253 characters")

    labels = value.split(".")

    if len(labels) < 2:
        raise ValueError("Expected a fully qualified domain")

    for label in labels:
        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
            label,
        ):
            raise ValueError("Invalid domain label")


def validate_ip_port(value: str) -> None:
    """Validate IPv4:port or bracketed IPv6:port."""

    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", value)

        if not match:
            raise ValueError("Invalid bracketed IPv6:port")

        address, port_text = match.groups()

        if ipaddress.ip_address(address).version != 6:
            raise ValueError("Expected IPv6 address")

    else:
        if value.count(":") != 1:
            raise ValueError("Expected IPv4:port")

        address, port_text = value.rsplit(":", 1)

        if ipaddress.ip_address(address).version != 4:
            raise ValueError("Expected IPv4 address")

    if not port_text.isdigit():
        raise ValueError("Port must be numeric")

    port = int(port_text)

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")


class ThreatIndicator(BaseModel):
    """
    Canonical representation of a threat indicator.

    Source-specific intelligence is stored separately.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=8192)

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Indicator cannot be empty")

        return value

    @model_validator(mode="after")
    def validate_indicator(self):
        indicator_type = self.indicator_type
        value = self.value

        if indicator_type == IndicatorType.DOMAIN:
            normalized = value.lower().rstrip(".")
            validate_domain(normalized)
            object.__setattr__(self, "value", normalized)

        elif indicator_type in HASH_LENGTHS:
            expected_length = HASH_LENGTHS[indicator_type]

            if not re.fullmatch(
                rf"[0-9a-fA-F]{{{expected_length}}}",
                value,
            ):
                raise ValueError("Invalid file hash format")

            object.__setattr__(self, "value", value.lower())

        elif indicator_type == IndicatorType.IP_PORT:
            validate_ip_port(value)

        elif indicator_type == IndicatorType.URL:
            parsed = urlsplit(value)

            if (
                parsed.scheme.lower() not in ("http", "https")
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("Invalid HTTP/HTTPS URL")

            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("Invalid URL port") from exc

            if port is not None and not 1 <= port <= 65535:
                raise ValueError("Invalid URL port")

        return self

    @property
    def canonical_key(self) -> tuple[str, str]:
        return (self.indicator_type.value, self.value)


class SourceObservation(BaseModel):
    """
    Source-specific intelligence observation.

    Original timestamps are preserved even when a trusted
    adapter explicitly permits a reversed interval.

    Reversed intervals are rejected by default.
    """

    model_config = ConfigDict(extra="forbid")

    source_name: str = Field(min_length=1)
    source_record_id: str = Field(min_length=1)

    indicator: ThreatIndicator

    threat_type: str = Field(min_length=1)
    malware_family: str | None = None

    confidence_level: int = Field(
        strict=True,
        ge=0,
        le=100,
    )

    first_seen: datetime
    last_seen: datetime | None = None

    reporter: str | None = None
    reference: str | None = None
    tags: list[str] = Field(default_factory=list)

    allow_reversed_timestamps: bool = Field(
        default=False,
        strict=True,
        exclude=True,
        repr=False,
    )

    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def parse_provider_timestamp(cls, value):
        if value is None:
            return None

        if isinstance(value, str):
            value = datetime.strptime(
                value,
                "%Y-%m-%d %H:%M:%S UTC",
            ).replace(tzinfo=timezone.utc)

        return value

    @field_validator("first_seen", "last_seen")
    @classmethod
    def require_timezone(cls, value):
        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must be timezone-aware")

        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_observation(self):
        if (
            self.last_seen is not None
            and self.last_seen < self.first_seen
            and not self.allow_reversed_timestamps
        ):
            raise ValueError(
                "last_seen cannot precede first_seen"
            )

        return self

    @property
    def timestamp_quality(self) -> TimestampQuality:
        """Classify the source observation's timestamp interval."""

        if self.last_seen is None:
            return TimestampQuality.MISSING_LAST_SEEN

        if self.last_seen < self.first_seen:
            return TimestampQuality.REVERSED_INTERVAL

        return TimestampQuality.CONSISTENT

    @property
    def source_key(self) -> tuple[str, str]:
        return (
            self.source_name,
            self.source_record_id,
        )
