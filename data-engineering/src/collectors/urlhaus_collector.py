
"""
ThreatForge - URLhaus Intelligence Collector

Collects recent malicious URL intelligence from URLhaus.

Responsibilities:
- Load API configuration securely from .env.
- Authenticate using the Auth-Key header.
- Make a read-only HTTPS request.
- Validate the API response structure.
- Return records for later normalization.
- Print only safe summary statistics.

This collector does not:
- Download malicious payloads.
- Visit malicious URLs.
- Write to PostgreSQL.
- Print API credentials or raw IOC values.
"""

import os
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_TIMEOUT = 30
MAX_PREVIEW_RECORDS = 5


def load_configuration() -> tuple[str, str]:
    """Load and validate URLhaus API configuration."""

    load_dotenv(
        PROJECT_ROOT / ".env",
        override=True,
    )

    api_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    api_url = os.getenv("URLHAUS_API_URL", "").strip()

    if not api_key:
        raise ValueError(
            "URLHAUS_AUTH_KEY is not configured"
        )

    if not api_url:
        raise ValueError(
            "URLHAUS_API_URL is not configured"
        )

    parsed = urlparse(api_url)

    if (
        parsed.scheme != "https"
        or parsed.hostname != "urlhaus-api.abuse.ch"
        or parsed.path != "/v1/urls/recent/"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Unexpected URLhaus API endpoint configuration"
        )

    return api_key, api_url


def fetch_recent_urls(
    api_key: str,
    api_url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Fetch recent URLhaus intelligence using HTTPS GET.

    The API key is sent in the Auth-Key header.
    The response must contain query_status and urls.
    """

    if not api_key:
        raise ValueError("URLhaus authentication key is missing")

    if timeout <= 0:
        raise ValueError("Timeout must be positive")

    response = requests.get(
        api_url,
        headers={
            "Auth-Key": api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatForge-Research-Collector/1.0",
        },
        timeout=timeout,
        allow_redirects=False,
    )

    response.raise_for_status()

    if response.is_redirect:
        raise ValueError("Unexpected URLhaus API redirect")

    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError(
            "URLhaus response must be a JSON object"
        )

    if payload.get("query_status") != "ok":
        raise ValueError(
            "URLhaus returned a non-OK query status"
        )

    records = payload.get("urls")

    if not isinstance(records, list):
        raise ValueError(
            "URLhaus response does not contain a URL list"
        )

    if any(not isinstance(record, dict) for record in records):
        raise ValueError(
            "URLhaus returned an invalid record structure"
        )

    return payload


def summarize_records(records: list[dict]) -> None:
    """Display safe aggregate statistics only."""

    print("\n=== URLHAUS COLLECTION RESULTS ===")
    print(f"Total URL records returned: {len(records)}")

    status_counts = Counter(
        str(record.get("url_status", "unknown"))
        for record in records
    )

    print("\nURL status distribution:")

    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")

    print("\n=== RESPONSE STRUCTURE VALIDATION ===")

    sample = records[:MAX_PREVIEW_RECORDS]

    required_fields = (
        "id",
        "url",
        "url_status",
        "date_added",
    )

    print(f"Records inspected: {len(sample)}")

    for field in required_fields:
        present = sum(
            record.get(field) is not None
            for record in sample
        )

        print(
            f"  {field}: {present}/{len(sample)} present"
        )

    print("\nNo malicious URLs or API keys were printed.")


def main() -> int:
    """Run a controlled read-only URLhaus API test."""

    print("=== THREATFORGE URLHAUS COLLECTOR ===")

    try:
        api_key, api_url = load_configuration()

        print("API configuration: loaded")
        print("Authentication key: present")
        print("Request method: GET")
        print("Database writes: disabled")

        response = fetch_recent_urls(
            api_key=api_key,
            api_url=api_url,
        )

        records = response["urls"]

        summarize_records(records)

        print("\nURLhaus collection completed successfully.")

        return 0

    except requests.RequestException as exc:
        print(
            "URLhaus network/API request failed: "
            f"{type(exc).__name__}"
        )
        return 1

    except (ValueError, KeyError, TypeError) as exc:
        print(
            "URLhaus configuration/response error: "
            f"{type(exc).__name__}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
