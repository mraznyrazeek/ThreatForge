
"""
ThreatForge - ThreatFox Normalization & Quality Analysis

Normalize real ThreatFox records into internal Pydantic
models while preserving source timestamp anomalies.

Responsibilities:
- Retrieve recent ThreatFox records.
- Validate indicator and observation fields.
- Preserve original timestamps.
- Classify timestamp quality.
- Report validation failures safely.
- Measure indicator and source-record uniqueness.

No database writes or suspicious URL requests.
"""

import sys
from collections import Counter
from pathlib import Path

import requests
from pydantic import ValidationError


SRC_DIR = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(SRC_DIR / "collectors"))
sys.path.insert(0, str(SRC_DIR / "models"))

from threatfox_collector import (  # noqa: E402
    fetch_recent_iocs,
    load_configuration,
)
from threat_indicator import (  # noqa: E402
    SourceObservation,
    ThreatIndicator,
    TimestampQuality,
)


# Approved messages from our own validation models.
# Never print arbitrary source-supplied error content.
KNOWN_VALIDATION_MESSAGES = {
    "Domain exceeds 253 characters",
    "Expected a fully qualified domain",
    "Invalid domain label",
    "Invalid bracketed IPv6:port",
    "Expected IPv4:port",
    "Expected IPv6 address",
    "Port must be numeric",
    "Port must be between 1 and 65535",
    "Invalid file hash format",
    "Invalid HTTP/HTTPS URL",
    "Invalid URL port",
    "Indicator cannot be empty",
    "Timestamp must be timezone-aware",
    "last_seen cannot precede first_seen",
}


def normalize_record(record: dict) -> SourceObservation:
    """
    Convert a ThreatFox record into internal models.

    ThreatFox-specific timestamp policy:
    Preserve reversed intervals and classify them
    instead of silently changing source values.
    """

    indicator = ThreatIndicator(
        indicator_type=record["ioc_type"],
        value=record["ioc"],
    )

    return SourceObservation(
        source_name="ThreatFox",
        source_record_id=str(record["id"]),
        indicator=indicator,
        threat_type=record["threat_type"],
        malware_family=record.get("malware"),
        confidence_level=record["confidence_level"],
        first_seen=record["first_seen"],
        last_seen=record.get("last_seen"),
        reporter=record.get("reporter"),
        reference=record.get("reference"),
        tags=record.get("tags") or [],
        allow_reversed_timestamps=True,
    )


def safe_error_reason(error: dict) -> str:
    """Classify validation failures without revealing IOC data."""

    error_type = error.get("type", "unknown_error")

    if error_type != "value_error":
        return str(error_type)

    context = error.get("ctx") or {}
    original_error = context.get("error")

    if original_error is None:
        return "Unclassified value error"

    message = str(original_error)

    if message in KNOWN_VALIDATION_MESSAGES:
        return message

    return "Other validation error"


def normalize_records(records: list[dict]):
    """Normalize a batch and collect diagnostic counts."""

    observations = []

    failure_types = Counter()
    failure_ioc_types = Counter()
    failure_details = Counter()

    for record in records:
        try:
            observation = normalize_record(record)
            observations.append(observation)

        except ValidationError as exc:
            failure_types["ValidationError"] += 1

            ioc_type = str(record.get("ioc_type", "unknown"))
            failure_ioc_types[ioc_type] += 1

            for error in exc.errors(
                include_input=False,
                include_url=False,
            ):
                reason = safe_error_reason(error)
                failure_details[(ioc_type, reason)] += 1

        except (ValueError, TypeError, KeyError) as exc:
            failure_types[type(exc).__name__] += 1

            ioc_type = str(record.get("ioc_type", "unknown"))
            failure_ioc_types[ioc_type] += 1

            failure_details[
                (ioc_type, type(exc).__name__)
            ] += 1

    diagnostics = {
        "failure_types": failure_types,
        "failure_ioc_types": failure_ioc_types,
        "failure_details": failure_details,
    }

    return observations, diagnostics


def print_counter(title: str, counts: Counter) -> None:
    """Print aggregate results."""

    print(f"\n=== {title} ===")

    if not counts:
        print("None")
        return

    for key, count in counts.most_common():
        if isinstance(key, tuple):
            label = " | ".join(map(str, key))
        else:
            label = str(key)

        print(f"{label}: {count}")


def analyze_normalization(
    observations: list[SourceObservation],
    diagnostics: dict,
    total: int,
) -> int:
    """Print normalization and quality statistics."""

    successful = len(observations)
    failed = total - successful

    print("\n=== THREATFORGE NORMALIZATION RESULTS ===")
    print(f"Records received: {total}")
    print(f"Successfully normalized: {successful}")
    print(f"Failed validation: {failed}")

    if total:
        print(
            f"Normalization success rate: "
            f"{successful / total * 100:.2f}%"
        )

    print_counter(
        "FAILURE CATEGORIES",
        diagnostics["failure_types"],
    )

    print_counter(
        "FAILED IOC TYPES",
        diagnostics["failure_ioc_types"],
    )

    print_counter(
        "DETAILED VALIDATION REASONS",
        diagnostics["failure_details"],
    )

    timestamp_quality_counts = Counter(
        observation.timestamp_quality.value
        for observation in observations
    )

    print_counter(
        "TIMESTAMP QUALITY DISTRIBUTION",
        timestamp_quality_counts,
    )

    indicator_type_counts = Counter(
        observation.indicator.indicator_type.value
        for observation in observations
    )

    print_counter(
        "NORMALIZED INDICATOR TYPES",
        indicator_type_counts,
    )

    canonical_keys = {
        observation.indicator.canonical_key
        for observation in observations
    }

    source_keys = {
        observation.source_key
        for observation in observations
    }

    print("\n=== INDICATOR UNIQUENESS ===")
    print(f"Unique canonical indicators: {len(canonical_keys)}")
    print(f"Unique source records: {len(source_keys)}")

    print(
        "Repeated canonical indicator observations: "
        f"{successful - len(canonical_keys)}"
    )

    print(
        "Repeated source record occurrences: "
        f"{successful - len(source_keys)}"
    )

    print("\n=== DATA QUALITY SUMMARY ===")

    reversed_count = timestamp_quality_counts[
        TimestampQuality.REVERSED_INTERVAL.value
    ]

    missing_count = timestamp_quality_counts[
        TimestampQuality.MISSING_LAST_SEEN.value
    ]

    print(f"Reversed timestamp intervals: {reversed_count}")
    print(f"Missing last_seen timestamps: {missing_count}")
    print(f"Rejected records: {failed}")

    if reversed_count:
        print(
            "WARNING: Reversed intervals are preserved "
            "and must be flagged in downstream analytics."
        )

    print("\nNormalization analysis completed.")

    return failed


def main() -> None:
    try:
        api_key, api_url = load_configuration()

        response = fetch_recent_iocs(
            api_key=api_key,
            api_url=api_url,
            days=1,
        )

        if not isinstance(response, dict):
            raise ValueError("Expected JSON response object")

        if response.get("query_status") != "ok":
            raise ValueError("ThreatFox returned non-OK status")

        records = response.get("data")

        if not isinstance(records, list):
            raise ValueError("Expected a list of IOC records")

        if any(not isinstance(r, dict) for r in records):
            raise ValueError("IOC list contains non-object records")

        observations, diagnostics = normalize_records(records)

        failed = analyze_normalization(
            observations=observations,
            diagnostics=diagnostics,
            total=len(records),
        )

        if failed:
            raise SystemExit(2)

    except requests.RequestException as exc:
        print(f"API request failed: {type(exc).__name__}")
        raise SystemExit(1) from exc

    except (ValueError, TypeError, KeyError) as exc:
        print(f"Normalization run failed: {type(exc).__name__}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
