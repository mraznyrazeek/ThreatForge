
"""Tests for the ThreatForge URLhaus adapter."""

from datetime import timezone
from pathlib import Path
import sys

import pytest


SRC_DIR = Path(__file__).resolve().parents[1] / "src"

sys.path.insert(0, str(SRC_DIR / "processing"))

from normalize_urlhaus import (  # noqa: E402
    normalize_record,
    normalize_records,
    parse_urlhaus_timestamp,
)


@pytest.fixture
def valid_record():
    # Synthetic test data, not an actual malicious URL.
    return {
        "id": 12345,
        "url": "https://example.com/test-payload",
        "url_status": "online",
        "date_added": "2026-11-09 08:30:00 UTC",
        "threat": "malware_download",
        "tags": ["test", "synthetic"],
        "reporter": "test-reporter",
        "urlhaus_reference": (
            "https://urlhaus.abuse.ch/url/12345/"
        ),
    }


def test_normalize_valid_record(valid_record):
    observation = normalize_record(valid_record)

    assert observation.source_name == "URLhaus"
    assert observation.source_record_id == "12345"

    assert observation.indicator.indicator_type.value == "url"
    assert observation.indicator.value == valid_record["url"]

    assert observation.threat_type == "malware_download"
    assert observation.confidence_level == 0

    assert observation.last_seen is None
    assert observation.malware_family is None
    assert observation.tags == ["test", "synthetic"]

    assert observation.first_seen.tzinfo == timezone.utc


def test_source_identity(valid_record):
    observation = normalize_record(valid_record)

    assert observation.source_key == ("URLhaus", "12345")


def test_canonical_identity(valid_record):
    observation = normalize_record(valid_record)

    assert observation.indicator.canonical_key == (
        "url",
        "https://example.com/test-payload",
    )


def test_missing_url_rejected(valid_record):
    del valid_record["url"]

    with pytest.raises(KeyError):
        normalize_record(valid_record)


def test_invalid_url_rejected(valid_record):
    valid_record["url"] = "not-a-valid-url"

    with pytest.raises(ValueError):
        normalize_record(valid_record)


def test_missing_threat_rejected(valid_record):
    del valid_record["threat"]

    with pytest.raises(KeyError):
        normalize_record(valid_record)


def test_missing_timestamp_rejected(valid_record):
    valid_record["date_added"] = None

    with pytest.raises(ValueError):
        normalize_record(valid_record)


def test_utc_timestamp():
    parsed = parse_urlhaus_timestamp(
        "2026-11-09 08:30:00 UTC"
    )

    assert parsed.tzinfo == timezone.utc
    assert parsed.year == 2026


def test_iso_timestamp():
    parsed = parse_urlhaus_timestamp(
        "2026-11-09T08:30:00Z"
    )

    assert parsed.tzinfo == timezone.utc
    assert parsed.hour == 8


def test_missing_tags_allowed(valid_record):
    valid_record["tags"] = None

    observation = normalize_record(valid_record)

    assert observation.tags == []


def test_missing_optional_fields_allowed(valid_record):
    for key in ("tags", "reporter", "urlhaus_reference"):
        valid_record.pop(key)

    observation = normalize_record(valid_record)

    assert observation.tags == []
    assert observation.reporter is None
    assert observation.reference is None


def test_batch_with_invalid_record(valid_record):
    invalid_record = valid_record.copy()
    invalid_record["url"] = "invalid"

    observations, diagnostics = normalize_records(
        [valid_record, invalid_record]
    )

    assert len(observations) == 1
    assert diagnostics["total"] == 2
    assert diagnostics["successful"] == 1
    assert diagnostics["failed"] == 1
    assert diagnostics["failure_types"]["ValidationError"] == 1


def test_empty_batch():
    observations, diagnostics = normalize_records([])

    assert observations == []
    assert diagnostics["total"] == 0
    assert diagnostics["failed"] == 0
