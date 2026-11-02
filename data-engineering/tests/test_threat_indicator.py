
"""
ThreatForge - Threat Indicator Model Tests

Tests normalized threat indicators and source observations
using synthetic, non-malicious test data.

No external APIs or databases are accessed.
"""

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError


# Import the model from the existing project structure.
MODELS_DIR = Path(__file__).resolve().parents[1] / "src" / "models"
sys.path.insert(0, str(MODELS_DIR))

from threat_indicator import (  # noqa: E402
    IndicatorType,
    SourceObservation,
    ThreatIndicator,
)


def make_observation(**overrides):
    """Construct a valid observation with optional overrides."""
    values = {
        "source_name": "ThreatFox",
        "source_record_id": "test-001",
        "indicator": ThreatIndicator(
            indicator_type="domain",
            value="example.com",
        ),
        "threat_type": "payload_delivery",
        "malware_family": "test_family",
        "confidence_level": 85,
        "first_seen": "2026-11-02 08:30:00 UTC",
        "last_seen": None,
        "tags": ["test"],
    }

    values.update(overrides)
    return SourceObservation(**values)


class TestThreatIndicator:

    def test_domain_normalization(self):
        indicator = ThreatIndicator(
            indicator_type="domain",
            value="EXAMPLE.COM",
        )
        assert indicator.value == "example.com"

    def test_domain_trailing_dot(self):
        indicator = ThreatIndicator(
            indicator_type="domain",
            value="example.com.",
        )
        assert indicator.value == "example.com"

    @pytest.mark.parametrize(
        "value",
        [
            "invalid_domain",
            "-example.com",
            "example..com",
            "example.com/path",
        ],
    )
    def test_invalid_domains(self, value):
        with pytest.raises(ValidationError):
            ThreatIndicator(
                indicator_type="domain",
                value=value,
            )

    @pytest.mark.parametrize(
        ("indicator_type", "length"),
        [
            (IndicatorType.MD5, 32),
            (IndicatorType.SHA1, 40),
            (IndicatorType.SHA256, 64),
        ],
    )
    def test_valid_hashes(self, indicator_type, length):
        indicator = ThreatIndicator(
            indicator_type=indicator_type,
            value="A" * length,
        )
        assert indicator.value == "a" * length

    @pytest.mark.parametrize(
        ("indicator_type", "value"),
        [
            (IndicatorType.MD5, "abcd"),
            (IndicatorType.SHA1, "z" * 40),
            (IndicatorType.SHA256, "1" * 63),
        ],
    )
    def test_invalid_hashes(self, indicator_type, value):
        with pytest.raises(ValidationError):
            ThreatIndicator(
                indicator_type=indicator_type,
                value=value,
            )

    def test_valid_ipv4_port(self):
        indicator = ThreatIndicator(
            indicator_type="ip:port",
            value="192.0.2.10:443",
        )
        assert indicator.value == "192.0.2.10:443"

    def test_valid_ipv6_port(self):
        indicator = ThreatIndicator(
            indicator_type="ip:port",
            value="[2001:db8::1]:443",
        )
        assert indicator.indicator_type == IndicatorType.IP_PORT

    @pytest.mark.parametrize(
        "value",
        [
            "999.999.999.999:80",
            "192.0.2.10:70000",
            "192.0.2.10:0",
            "192.0.2.10",
            "invalid:443",
        ],
    )
    def test_invalid_ip_ports(self, value):
        with pytest.raises(ValidationError):
            ThreatIndicator(
                indicator_type="ip:port",
                value=value,
            )

    def test_valid_url(self):
        indicator = ThreatIndicator(
            indicator_type="url",
            value="https://example.com/test",
        )
        assert indicator.value == "https://example.com/test"

    @pytest.mark.parametrize(
        "value",
        [
            "ftp://example.com/file",
            "not-a-url",
            "https://",
            "https://user:pass@example.com",
        ],
    )
    def test_invalid_urls(self, value):
        with pytest.raises(ValidationError):
            ThreatIndicator(
                indicator_type="url",
                value=value,
            )

    def test_canonical_identity(self):
        first = ThreatIndicator(
            indicator_type="domain",
            value="EXAMPLE.COM",
        )
        second = ThreatIndicator(
            indicator_type="domain",
            value="example.com",
        )

        assert first.canonical_key == second.canonical_key

    def test_different_indicator_types(self):
        domain = ThreatIndicator(
            indicator_type="domain",
            value="example.com",
        )
        url = ThreatIndicator(
            indicator_type="url",
            value="https://example.com",
        )

        assert domain.canonical_key != url.canonical_key


class TestSourceObservation:

    def test_valid_observation(self):
        observation = make_observation()

        assert observation.source_name == "ThreatFox"
        assert observation.confidence_level == 85

    def test_source_identity(self):
        observation = make_observation()

        assert observation.source_key == (
            "ThreatFox",
            "test-001",
        )

    @pytest.mark.parametrize(
        "confidence",
        [-1, 101, "85", None, True],
    )
    def test_invalid_confidence(self, confidence):
        with pytest.raises(ValidationError):
            make_observation(confidence_level=confidence)

    @pytest.mark.parametrize(
        "confidence",
        [0, 50, 100],
    )
    def test_valid_confidence_boundaries(self, confidence):
        observation = make_observation(
            confidence_level=confidence,
        )
        assert observation.confidence_level == confidence

    def test_timestamp_is_utc(self):
        observation = make_observation()

        assert observation.first_seen.utcoffset().total_seconds() == 0

    def test_invalid_timestamp(self):
        with pytest.raises(ValidationError):
            make_observation(
                first_seen="not-a-timestamp",
            )

    def test_last_seen_before_first_seen(self):
        with pytest.raises(ValidationError):
            make_observation(
                last_seen="2026-11-01 08:30:00 UTC",
            )

    def test_valid_last_seen(self):
        observation = make_observation(
            last_seen="2026-11-02 09:30:00 UTC",
        )

        assert observation.last_seen >= observation.first_seen

    def test_nullable_last_seen(self):
        observation = make_observation(last_seen=None)

        assert observation.last_seen is None

    def test_default_tags_are_independent(self):
        first = make_observation(tags=[])
        second = make_observation(tags=[])

        first.tags.append("test-tag")

        assert second.tags == []

    def test_unknown_fields_rejected_for_indicator(self):
        with pytest.raises(ValidationError):
            ThreatIndicator(
                indicator_type="domain",
                value="example.com",
                unexpected_field="value",
            )
