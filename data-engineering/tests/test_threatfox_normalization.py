
"""
ThreatForge - ThreatFox Normalization Adapter Tests

Tests:
- Realistic ThreatFox record mapping
- Consistent, missing, and reversed timestamps
- Preservation of original timestamp values
- Canonical indicator normalization
- Invalid record handling
- Source-specific observation identity

All test records are synthetic.
No external API calls or database writes.
"""

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError


SRC_DIR = Path(__file__).resolve().parents[1] / "src"

sys.path.insert(0, str(SRC_DIR / "processing"))
sys.path.insert(0, str(SRC_DIR / "models"))

from normalize_threatfox import (  # noqa: E402
    normalize_record,
    normalize_records,
)
from threat_indicator import TimestampQuality  # noqa: E402


def make_threatfox_record(**overrides):
    """Create a valid synthetic ThreatFox API record."""

    record = {
        "id": "test-001",
        "ioc": "example.com",
        "ioc_type": "domain",
        "threat_type": "payload_delivery",
        "malware": "test_family",
        "confidence_level": 85,
        "first_seen": "2026-11-02 08:30:00 UTC",
        "last_seen": "2026-11-02 08:40:00 UTC",
        "reporter": "test-reporter",
        "reference": None,
        "tags": ["test"],
    }

    record.update(overrides)
    return record


class TestThreatFoxNormalization:

    def test_valid_record_normalization(self):
        observation = normalize_record(
            make_threatfox_record()
        )

        assert observation.source_name == "ThreatFox"
        assert observation.source_record_id == "test-001"
        assert observation.indicator.value == "example.com"
        assert observation.confidence_level == 85

    def test_domain_normalization(self):
        observation = normalize_record(
            make_threatfox_record(ioc="EXAMPLE.COM")
        )

        assert observation.indicator.value == "example.com"

    def test_consistent_timestamp_quality(self):
        observation = normalize_record(
            make_threatfox_record()
        )

        assert (
            observation.timestamp_quality
            == TimestampQuality.CONSISTENT
        )

    def test_missing_last_seen(self):
        observation = normalize_record(
            make_threatfox_record(last_seen=None)
        )

        assert observation.last_seen is None
        assert (
            observation.timestamp_quality
            == TimestampQuality.MISSING_LAST_SEEN
        )

    @pytest.mark.parametrize(
        "difference_seconds",
        [36, 120, 36578],
    )
    def test_reversed_timestamps_preserved(
        self,
        difference_seconds,
    ):
        from datetime import datetime, timedelta, timezone

        first = datetime(
            2026, 11, 2, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        last = first - timedelta(
            seconds=difference_seconds
        )

        observation = normalize_record(
            make_threatfox_record(
                first_seen=first.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ),
                last_seen=last.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ),
            )
        )

        assert (
            observation.timestamp_quality
            == TimestampQuality.REVERSED_INTERVAL
        )
        assert observation.first_seen == first
        assert observation.last_seen == last

    def test_invalid_domain_rejected(self):
        with pytest.raises(ValidationError):
            normalize_record(
                make_threatfox_record(
                    ioc="invalid_domain"
                )
            )

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValidationError):
            normalize_record(
                make_threatfox_record(
                    confidence_level=150
                )
            )

    def test_missing_required_field_rejected(self):
        record = make_threatfox_record()
        del record["ioc"]

        with pytest.raises(KeyError):
            normalize_record(record)

    def test_invalid_timestamp_rejected(self):
        with pytest.raises(ValidationError):
            normalize_record(
                make_threatfox_record(
                    first_seen="invalid-date"
                )
            )

    def test_source_record_identity(self):
        observation = normalize_record(
            make_threatfox_record()
        )

        assert observation.source_key == (
            "ThreatFox",
            "test-001",
        )

    def test_batch_normalization(self):
        records = [
            make_threatfox_record(id="1"),
            make_threatfox_record(
                id="2",
                last_seen=None,
            ),
            make_threatfox_record(
                id="3",
                last_seen="2026-11-02 08:29:24 UTC",
            ),
        ]

        observations, diagnostics = normalize_records(records)

        assert len(observations) == 3
        assert not diagnostics["failure_types"]

        qualities = {
            observation.timestamp_quality
            for observation in observations
        }

        assert qualities == {
            TimestampQuality.CONSISTENT,
            TimestampQuality.MISSING_LAST_SEEN,
            TimestampQuality.REVERSED_INTERVAL,
        }

    def test_invalid_record_counted(self):
        records = [
            make_threatfox_record(id="1"),
            make_threatfox_record(
                id="2",
                ioc="invalid_domain",
            ),
        ]

        observations, diagnostics = normalize_records(records)

        assert len(observations) == 1
        assert diagnostics["failure_types"]["ValidationError"] == 1
        assert diagnostics["failure_ioc_types"]["domain"] == 1

    def test_duplicate_indicator_distinct_sources(self):
        first = normalize_record(
            make_threatfox_record(
                id="100",
                ioc="EXAMPLE.COM",
            )
        )

        second = normalize_record(
            make_threatfox_record(
                id="101",
                ioc="example.com",
            )
        )

        assert (
            first.indicator.canonical_key
            == second.indicator.canonical_key
        )

        assert first.source_key != second.source_key

    def test_quality_flag_not_exported_implicitly(self):
        observation = normalize_record(
            make_threatfox_record(
                last_seen="2026-11-02 08:29:24 UTC"
            )
        )

        serialized = observation.model_dump(mode="json")

        assert "allow_reversed_timestamps" not in serialized
        assert "timestamp_quality" not in serialized

        # The persistence layer must explicitly include
        # timestamp_quality in its storage contract.
        assert (
            observation.timestamp_quality.value
            == "reversed_interval"
        )
