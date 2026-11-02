
from collections import Counter
from datetime import datetime
from pathlib import Path
import os

import requests
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

REQUIRED_FIELDS = (
    "id",
    "ioc",
    "ioc_type",
    "threat_type",
    "first_seen",
)


def fetch_data():
    api_key = os.getenv("THREATFOX_API_KEY")
    api_url = os.getenv("THREATFOX_API_URL")

    if not api_key or not api_url:
        raise ValueError("ThreatFox configuration is missing")

    response = requests.post(
        api_url,
        headers={"Auth-Key": api_key},
        json={"query": "get_iocs", "days": 1},
        timeout=30,
    )
    response.raise_for_status()

    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError("Unexpected API response format")

    if payload.get("query_status") != "ok":
        raise ValueError(
            f"ThreatFox query status: {payload.get('query_status')}"
        )

    records = payload.get("data")

    if not isinstance(records, list):
        raise ValueError("Expected a list of IOC records")

    if any(not isinstance(record, dict) for record in records):
        raise ValueError("IOC list contains invalid records")

    return records


def parse_timestamp(value):
    if not value:
        return None

    try:
        return datetime.strptime(
            value, "%Y-%m-%d %H:%M:%S UTC"
        )
    except (ValueError, TypeError):
        return None


def analyze(records):
    print("\n=== THREATFORGE DATA QUALITY ANALYSIS ===")

    total = len(records)
    print(f"Total records: {total}")

    if not records:
        print("No records available for analysis")
        return

    ids = [str(r["id"]) for r in records if r.get("id") is not None]
    counts = Counter(ids)

    print(f"Records with IDs: {len(ids)}")
    print(f"Unique IDs: {len(counts)}")
    print(
        f"Duplicate ID occurrences: "
        f"{sum(count - 1 for count in counts.values() if count > 1)}"
    )

    print("\n=== IOC TYPES ===")
    for name, count in Counter(
        str(r.get("ioc_type") or "unknown") for r in records
    ).most_common():
        print(f"{name}: {count}")

    print("\n=== TOP 10 MALWARE FAMILIES ===")
    for name, count in Counter(
        str(r.get("malware") or "unknown") for r in records
    ).most_common(10):
        print(f"{name}: {count}")

    print("\n=== THREAT TYPES ===")
    for name, count in Counter(
        str(r.get("threat_type") or "unknown") for r in records
    ).most_common():
        print(f"{name}: {count}")

    print("\n=== REQUIRED FIELD VALIDATION ===")
    for field in REQUIRED_FIELDS:
        missing = sum(
            1 for r in records
            if r.get(field) is None or r.get(field) == ""
        )
        print(f"{field}: {missing} missing")

    print("\n=== CONFIDENCE VALIDATION ===")
    scores = []
    invalid = 0

    for record in records:
        value = record.get("confidence_level")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= value <= 100
        ):
            invalid += 1
        else:
            scores.append(value)

    print(f"Valid confidence scores: {len(scores)}")
    print(f"Invalid/missing confidence: {invalid}")

    if scores:
        print(f"Average confidence: {sum(scores) / len(scores):.2f}")

    print("\n=== TIMESTAMP VALIDATION ===")
    timestamps = [
        parse_timestamp(r.get("first_seen"))
        for r in records
    ]
    valid_dates = [value for value in timestamps if value is not None]

    print(f"Valid first_seen dates: {len(valid_dates)}")
    print(f"Invalid/missing dates: {total - len(valid_dates)}")

    if valid_dates:
        print(f"Earliest: {min(valid_dates)} UTC")
        print(f"Latest: {max(valid_dates)} UTC")

    print("\nAnalysis completed.")


def main():
    try:
        records = fetch_data()
        analyze(records)
    except (requests.RequestException, ValueError) as exc:
        print(f"Analysis failed: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
