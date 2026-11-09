
"""
ThreatForge - URLhaus Normalization

Convert URLhaus records into the shared ThreatForge models.

- No network requests
- No database writes
- No execution or visits to reported malicious URLs
- No raw URL values in diagnostic output
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys

from pydantic import ValidationError


SRC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_DIR / "models"))

from threat_indicator import (  # noqa: E402
    IndicatorType,
    SourceObservation,
    ThreatIndicator,
)


SOURCE_NAME = "URLhaus"

# URLhaus does not supply a comparable confidence score
# in the fields currently mapped by this adapter.
# Zero is a temporary "unrated" convention, NOT a
# statement that the indicator is harmless.
UNRATED_CONFIDENCE = 0


def parse_urlhaus_timestamp(value: str) -> datetime:
    """Parse URLhaus timestamps into timezone-aware UTC."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing URLhaus timestamp")

    text = value.strip()

    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Invalid URLhaus timestamp") from exc

    # URLhaus provider timestamps without an explicit
    # offset are interpreted as UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def normalize_record(record: dict) -> SourceObservation:
    """Normalize one URLhaus record."""

    if not isinstance(record, dict):
        raise TypeError("Expected a URLhaus record object")

    record_id = record["id"]

    if isinstance(record_id, bool) or not isinstance(
        record_id, (str, int)
    ):
        raise ValueError("Invalid URLhaus record ID")

    source_record_id = str(record_id).strip()

    if not source_record_id:
        raise ValueError("Missing URLhaus record ID")

    indicator = ThreatIndicator(
        indicator_type=IndicatorType.URL,
        value=record["url"],
    )

    threat_type = record["threat"]

    if not isinstance(threat_type, str) or not threat_type.strip():
        raise ValueError("Missing URLhaus threat classification")

    raw_tags = record.get("tags")
    tags = [] if raw_tags is None else raw_tags

    first_seen = parse_urlhaus_timestamp(record["date_added"])

    return SourceObservation(
        source_name=SOURCE_NAME,
        source_record_id=source_record_id,
        indicator=indicator,
        threat_type=threat_type.strip(),
        malware_family=None,
        confidence_level=UNRATED_CONFIDENCE,
        first_seen=first_seen,
        last_seen=None,
        reporter=record.get("reporter"),
        reference=record.get("urlhaus_reference"),
        tags=tags,
    )


def normalize_records(records: list[dict]):
    """Normalize a batch with sanitized failure diagnostics."""

    if not isinstance(records, list):
        raise TypeError("Expected a list of URLhaus records")

    observations = []
    failure_types = Counter()

    for record in records:
        try:
            observation = normalize_record(record)
            observations.append(observation)

        except ValidationError:
            failure_types["ValidationError"] += 1

        except (TypeError, ValueError, KeyError) as exc:
            failure_types[type(exc).__name__] += 1

    diagnostics = {
        "total": len(records),
        "successful": len(observations),
        "failed": len(records) - len(observations),
        "failure_types": failure_types,
    }

    return observations, diagnostics


def analyze_normalization(
    observations: list[SourceObservation],
    diagnostics: dict,
) -> None:
    """Print aggregate results without revealing IOC values."""

    print("\n=== URLHAUS NORMALIZATION RESULTS ===")
    print(f"Records received: {diagnostics['total']}")
    print(f"Successfully normalized: {diagnostics['successful']}")
    print(f"Failed validation: {diagnostics['failed']}")

    total = diagnostics["total"]

    if total:
        rate = diagnostics["successful"] / total * 100
        print(f"Success rate: {rate:.2f}%")

    print("\n=== FAILURE CATEGORIES ===")

    if not diagnostics["failure_types"]:
        print("None")
    else:
        for category, count in sorted(
            diagnostics["failure_types"].items()
        ):
            print(f"{category}: {count}")

    indicator_keys = {
        observation.indicator.canonical_key
        for observation in observations
    }

    source_keys = {
        observation.source_key
        for observation in observations
    }

    print("\n=== UNIQUENESS ===")
    print(f"Unique canonical indicators: {len(indicator_keys)}")
    print(f"Unique source records: {len(source_keys)}")

    print("\n=== DATA QUALITY ===")
    print("Confidence: unrated placeholder (0)")
    print("Last seen: not inferred from URL status")
    print("Original URL values: not displayed")
    print("Database writes: disabled")
