
"""
ThreatForge - ThreatFox Timestamp Anomaly Analysis

Investigate records where last_seen precedes first_seen.

This script:
- Fetches recent ThreatFox indicators.
- Measures timestamp inconsistencies.
- Reports aggregate statistics.
- Does not print IOC values or credentials.
- Does not modify source records.
"""

import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests


SRC_DIR = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(SRC_DIR / "collectors"))

from threatfox_collector import (  # noqa: E402
    fetch_recent_iocs,
    load_configuration,
)


def parse_timestamp(value):
    """Parse ThreatFox UTC timestamps without altering them."""

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("Timestamp is not a string")

    return datetime.strptime(
        value,
        "%Y-%m-%d %H:%M:%S UTC",
    ).replace(tzinfo=timezone.utc)


def classify_difference(seconds):
    """Categorize how far timestamps are out of order."""

    if seconds < 60:
        return "Less than 1 minute"

    if seconds < 3600:
        return "1 minute to 1 hour"

    if seconds < 86400:
        return "1 hour to 1 day"

    if seconds < 604800:
        return "1 day to 1 week"

    return "More than 1 week"


def analyze(records):
    total = len(records)

    anomalies = []
    invalid_timestamps = 0
    missing_first_seen = 0
    missing_last_seen = 0

    for record in records:
        try:
            first = parse_timestamp(record.get("first_seen"))
            last = parse_timestamp(record.get("last_seen"))

        except (ValueError, TypeError):
            invalid_timestamps += 1
            continue

        if first is None:
            missing_first_seen += 1
            continue

        if last is None:
            missing_last_seen += 1
            continue

        if last < first:
            difference = (first - last).total_seconds()

            anomalies.append({
                "ioc_type": str(record.get("ioc_type", "unknown")),
                "difference_seconds": difference,
            })

    print("\n=== THREATFORGE TIMESTAMP ANALYSIS ===")
    print(f"Total records: {total}")
    print(f"Missing first_seen: {missing_first_seen}")
    print(f"Missing last_seen: {missing_last_seen}")
    print(f"Invalid timestamps: {invalid_timestamps}")
    print(f"Reversed timestamps: {len(anomalies)}")

    if not anomalies:
        print("\nNo reversed timestamp intervals found.")
        return

    print("\n=== ANOMALIES BY IOC TYPE ===")

    type_counts = Counter(
        item["ioc_type"] for item in anomalies
    )

    for name, count in type_counts.most_common():
        print(f"{name}: {count}")

    differences = [
        item["difference_seconds"]
        for item in anomalies
    ]

    print("\n=== TIME DIFFERENCE STATISTICS ===")

    print(f"Minimum: {min(differences):.0f} seconds")
    print(f"Maximum: {max(differences):.0f} seconds")

    print(
        "Average: "
        f"{sum(differences) / len(differences):.2f} seconds"
    )

    print("\n=== DIFFERENCE CATEGORIES ===")

    categories = Counter(
        classify_difference(value)
        for value in differences
    )

    for name, count in categories.most_common():
        print(f"{name}: {count}")

    print("\nTimestamp anomaly analysis completed.")


def main():
    try:
        api_key, api_url = load_configuration()

        response = fetch_recent_iocs(
            api_key=api_key,
            api_url=api_url,
            days=1,
        )

        if not isinstance(response, dict):
            raise ValueError("Unexpected API response")

        if response.get("query_status") != "ok":
            raise ValueError("ThreatFox query was unsuccessful")

        records = response.get("data")

        if not isinstance(records, list):
            raise ValueError("Expected IOC record list")

        if any(not isinstance(r, dict) for r in records):
            raise ValueError("Invalid record structure")

        analyze(records)

    except (requests.RequestException, ValueError, TypeError) as exc:
        print(
            "Timestamp analysis failed: "
            f"{type(exc).__name__}"
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
