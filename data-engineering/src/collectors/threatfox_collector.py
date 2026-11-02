import json
import os
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv


def load_configuration() -> tuple[str, str]:
    """
    Load API configuration from the project root .env file.
    """
    env_path = Path(__file__).resolve().parents[3] / ".env"
    load_dotenv(env_path)

    api_key = os.getenv("THREATFOX_API_KEY")
    api_url = os.getenv("THREATFOX_API_URL")

    if not api_key:
        raise ValueError("THREATFOX_API_KEY is missing from .env")

    if not api_url:
        raise ValueError("THREATFOX_API_URL is missing from .env")

    return api_key, api_url


def fetch_recent_iocs(api_key: str, api_url: str, days: int = 1) -> dict[str, Any]:
    """
    Fetch recent IOCs from ThreatFox.
    """
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json",
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
    )

    response.raise_for_status()
    return response.json()


def print_response_summary(data: dict[str, Any]) -> None:
    """
    Print a high-level summary of the ThreatFox response.
    """
    print("\n=== ThreatFox Response Summary ===")

    query_status = data.get("query_status")
    print(f"Query status: {query_status}")

    records = data.get("data", [])

    if not isinstance(records, list):
        print("Unexpected response format: 'data' is not a list.")
        return

    print(f"IOC records returned: {len(records)}")

    if not records:
        print("No IOC records were returned.")
        return

    print("\n=== Sample IOC Records (first 3) ===")

    for index, record in enumerate(records[:3], start=1):
        print(f"\nRecord {index}")
        print("-" * 40)
        print(f"IOC ID: {record.get('id')}")
        print(f"IOC: {record.get('ioc')}")
        print(f"IOC Type: {record.get('ioc_type')}")
        print(f"Threat Type: {record.get('threat_type')}")
        print(f"Malware: {record.get('malware')}")
        print(f"Confidence Level: {record.get('confidence_level')}")
        print(f"First Seen: {record.get('first_seen')}")
        print(f"Last Seen: {record.get('last_seen')}")
        print(f"Reporter: {record.get('reporter')}")


def print_raw_keys(data: dict[str, Any]) -> None:
    """
    Print top-level keys and sample record keys for schema inspection.
    """
    print("\n=== Response Structure Inspection ===")
    print("Top-level keys:", list(data.keys()))

    records = data.get("data", [])
    if isinstance(records, list) and records:
        print("\nKeys in the first IOC record:")
        print(list(records[0].keys()))


def main() -> None:
    try:
        api_key, api_url = load_configuration()
        data = fetch_recent_iocs(api_key, api_url, days=1)

        print_response_summary(data)
        print_raw_keys(data)

        print("\n=== Full Raw Response Preview ===")
        print(json.dumps(data, indent=2)[:3000])

    except requests.exceptions.Timeout:
        print("Request timed out while contacting ThreatFox.")
    except requests.exceptions.HTTPError as exc:
        print(f"HTTP error occurred: {exc}")
    except requests.exceptions.RequestException as exc:
        print(f"Request error occurred: {exc}")
    except ValueError as exc:
        print(f"Configuration error: {exc}")
    except Exception as exc:
        print(f"Unexpected error: {exc}")


if __name__ == "__main__":
    main()