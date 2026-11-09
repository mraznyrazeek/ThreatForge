
"""
ThreatForge - ThreatFox Intelligence Collector

Responsibilities:
- Load ThreatFox API configuration.
- Retrieve recent threat intelligence indicators.
- Validate the basic API response structure.
- Print safe collection statistics.

Security:
- Never print API keys.
- Never print raw IOC values or response payloads.
- Never expose API response bodies in error messages.
- No PostgreSQL writes.
"""

import os
from collections import Counter
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def load_configuration() -> tuple[str, str]:
    """Load ThreatFox configuration from the project root."""

    env_path = PROJECT_ROOT / ".env"

    # Use the current local .env credentials instead of
    # potentially outdated inherited terminal variables.
    load_dotenv(env_path, override=True)

    api_key = os.getenv("THREATFOX_API_KEY", "").strip()
    api_url = os.getenv("THREATFOX_API_URL", "").strip()

    if not api_key:
        raise ValueError("THREATFOX_API_KEY is missing")

    if not api_url:
        raise ValueError("THREATFOX_API_URL is missing")

    expected_url = "https://threatfox-api.abuse.ch/api/v1/"

    if api_url != expected_url:
        raise ValueError("Unexpected ThreatFox API URL")

    return api_key, api_url


def fetch_recent_iocs(
    api_key: str,
    api_url: str,
    days: int = 1,
) -> dict[str, Any]:
    """Retrieve recent IOC records from ThreatFox."""

    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise ValueError("days must be a positive integer")

    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "query": "get_iocs",
        "days": days,
    }

    response = requests.post(
        api_url,
        headers=headers,
        json=payload,
        timeout=30,
        allow_redirects=False,
    )

    response.raise_for_status()

    data = response.json()

    if not isinstance(data, dict):
        raise ValueError("Unexpected ThreatFox response structure")

    return data


def print_response_summary(data: dict[str, Any]) -> None:
    """Print aggregate collection statistics without IOC values."""

    print("\n=== THREATFOX COLLECTION RESULTS ===")

    status = data.get("query_status")
    print(f"Query status: {status}")

    records = data.get("data", [])

    if not isinstance(records, list):
        raise ValueError("ThreatFox data must be a list")

    print(f"Total IOC records returned: {len(records)}")

    if status != "ok":
        raise ValueError("ThreatFox returned non-OK status")

    if not records:
        print("No IOC records returned.")
        return

    indicator_types = Counter(
        str(record.get("ioc_type", "unknown"))
        for record in records
        if isinstance(record, dict)
    )

    print("\n=== INDICATOR TYPE DISTRIBUTION ===")

    for indicator_type, count in indicator_types.most_common():
        print(f"{indicator_type}: {count}")

    print("\n=== RESPONSE STRUCTURE VALIDATION ===")

    required_fields = (
        "id",
        "ioc",
        "ioc_type",
        "threat_type",
        "confidence_level",
        "first_seen",
    )

    sample = records[:5]

    print(f"Records inspected: {len(sample)}")

    for field in required_fields:
        present = sum(
            isinstance(record, dict)
            and record.get(field) is not None
            for record in sample
        )

        print(f"  {field}: {present}/{len(sample)} present")

    print("\nNo raw IOC values or API keys were printed.")


def main() -> None:
    print("=== THREATFORGE THREATFOX COLLECTOR ===")

    try:
        api_key, api_url = load_configuration()

        print("API configuration: loaded")
        print("Authentication key: present")
        print("Database writes: disabled")

        data = fetch_recent_iocs(
            api_key=api_key,
            api_url=api_url,
            days=1,
        )

        print_response_summary(data)

        print("\nThreatFox collection completed successfully.")

    except requests.RequestException as exc:
        print(
            "ThreatFox network/API request failed: "
            f"{type(exc).__name__}"
        )
        raise SystemExit(1) from None

    except (ValueError, TypeError, KeyError) as exc:
        print(
            "ThreatFox collection failed: "
            f"{type(exc).__name__}"
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
