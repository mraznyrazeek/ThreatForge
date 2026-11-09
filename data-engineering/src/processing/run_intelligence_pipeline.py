
"""
ThreatForge - Unified Threat Intelligence Pipeline

Runs existing source-specific ingestion pipelines through
one controlled entry point.

- Dry-run by default.
- Explicit --execute required for database writes.
- Source isolation: one failure does not skip other sources.
- Summary of each source's execution result.
- No raw IOC values or credentials printed.
"""

import argparse
import subprocess
import sys
from pathlib import Path


PROCESSING_DIR = Path(__file__).resolve().parent

SOURCE_SCRIPTS = {
    "threatfox": "ingest_threatfox_batch.py",
    "urlhaus": "ingest_urlhaus_batch.py",
}

MAX_BATCH_SIZE = 10


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run ThreatForge intelligence pipelines"
    )

    parser.add_argument(
        "--sources",
        nargs="+",
        choices=tuple(SOURCE_SCRIPTS),
        default=list(SOURCE_SCRIPTS),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="ThreatFox lookback period",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Enable database writes",
    )

    args = parser.parse_args()

    if not 1 <= args.limit <= MAX_BATCH_SIZE:
        parser.error("--limit must be between 1 and 10")

    if args.days < 1:
        parser.error("--days must be at least 1")

    return args


def build_command(source, limit, days, execute):
    """Build a controlled command for an existing pipeline."""

    script_name = SOURCE_SCRIPTS[source]
    script_path = PROCESSING_DIR / script_name

    command = [
        sys.executable,
        str(script_path),
        "--limit",
        str(limit),
    ]

    if source == "threatfox":
        command.extend(["--days", str(days)])

    if execute:
        command.append("--execute")

    return command


def run_source(source, limit, days, execute):
    """Run one source without interrupting the other sources."""

    command = build_command(
        source=source,
        limit=limit,
        days=days,
        execute=execute,
    )

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {
            "source": source,
            "status": "timeout",
            "return_code": 1,
        }
    except OSError:
        return {
            "source": source,
            "status": "execution_error",
            "return_code": 1,
        }

    return {
        "source": source,
        "status": (
            "success"
            if result.returncode == 0
            else "failed"
        ),
        "return_code": result.returncode,
    }


def main():
    args = parse_arguments()

    print("\n=== THREATFORGE UNIFIED INGESTION ===")

    print(
        "Mode: "
        + (
            "EXECUTE - PostgreSQL writes enabled"
            if args.execute
            else "DRY RUN - No database writes"
        )
    )

    sources = list(dict.fromkeys(args.sources))

    print(f"Sources: {', '.join(sources)}")
    print(f"Maximum records per source: {args.limit}")

    results = []

    for source in sources:
        print(f"\nRunning source: {source}")

        result = run_source(
            source=source,
            limit=args.limit,
            days=args.days,
            execute=args.execute,
        )

        results.append(result)

        print(f"Status: {result['status']}")
        print(f"Exit code: {result['return_code']}")

    print("\n=== PIPELINE SUMMARY ===")

    for result in results:
        print(
            f"{result['source']}: {result['status']}"
        )

    failures = sum(
        result["return_code"] != 0
        for result in results
    )

    print(f"Sources attempted: {len(results)}")
    print(f"Sources failed: {failures}")

    if failures:
        print("Pipeline completed with source failures.")
        return 2

    print("All selected pipelines completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
