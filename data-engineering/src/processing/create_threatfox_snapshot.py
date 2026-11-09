
"""
ThreatForge - ThreatFox Feed Snapshot

Fetch one complete recent ThreatFox API response and
save it locally for consistent, restartable bulk ingestion.

- No PostgreSQL writes
- No IOC values or API credentials printed
- Snapshot restricted to local .runtime directory
- Unique snapshot file per collection
- No partial final files
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

SRC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_DIR / "collectors"))

from threatfox_collector import (  # noqa: E402
    load_configuration,
    fetch_recent_iocs,
)

DATA_ENGINEERING_DIR = SRC_DIR.parent
SNAPSHOT_DIR = DATA_ENGINEERING_DIR / ".runtime" / "snapshots"


def main() -> int:
    print("=== THREATFORGE THREATFOX SNAPSHOT ===")

    temporary_path = None

    try:
        api_key, api_url = load_configuration()

        response = fetch_recent_iocs(
            api_key=api_key,
            api_url=api_url,
            days=7,
        )

        if not isinstance(response, dict):
            raise ValueError("Invalid response structure")

        if response.get("query_status") != "ok":
            raise ValueError("ThreatFox returned non-OK status")

        records = response.get("data")

        if not isinstance(records, list):
            raise ValueError("Records must be a list")

        if any(not isinstance(item, dict) for item in records):
            raise ValueError("Records contain invalid objects")

        identifiers = [str(record["id"]) for record in records]

        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Duplicate source record IDs")

        collected_at = datetime.now(timezone.utc)

        snapshot = {
            "source": "ThreatFox",
            "collected_at_utc": collected_at.isoformat(),
            "lookback_days": 7,
            "record_count": len(records),
            "records": records,
        }

        SNAPSHOT_DIR.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        os.chmod(SNAPSHOT_DIR, 0o700)

        timestamp = collected_at.strftime("%Y%m%dT%H%M%S%fZ")
        destination = SNAPSHOT_DIR / f"threatfox_{timestamp}.json"
        temporary_path = SNAPSHOT_DIR / f".threatfox_{timestamp}.tmp"

        descriptor = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(snapshot, file, separators=(",", ":"))
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, destination)

        print("Source: ThreatFox")
        print("Lookback: 7 days")
        print(f"Records captured: {len(records)}")
        print(f"Unique source IDs: {len(set(identifiers))}")
        print(f"Snapshot: {destination.name}")
        print("Storage: local .runtime/snapshots/")
        print("Database writes: none")
        print("Snapshot creation successful.")

        return 0

    except (requests.RequestException, ValueError, KeyError, OSError) as exc:
        print(f"Snapshot failed: {type(exc).__name__}")
        return 1

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
