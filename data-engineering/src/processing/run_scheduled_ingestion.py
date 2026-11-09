
"""
ThreatForge - Controlled Scheduled Ingestion Runner

One-shot job runner for macOS launchd or another scheduler.

Features:
- Calls the existing unified ingestion orchestrator.
- Dry-run by default.
- Requires --execute for PostgreSQL writes.
- Prevents overlapping invocations using a file lock.
- Enforces execution timeout.
- Reports safe operational outcomes without raw IOC data.

Scheduling is configured separately after validation.
"""

import argparse
import fcntl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROCESSING_DIR = Path(__file__).resolve().parent
DATA_ENGINEERING_DIR = PROCESSING_DIR.parents[1]

ORCHESTRATOR = (
    PROCESSING_DIR / "run_intelligence_pipeline.py"
)

RUNTIME_DIR = DATA_ENGINEERING_DIR / ".runtime"
LOCK_FILE = RUNTIME_DIR / "ingestion.lock"

MAX_BATCH_SIZE = 10
JOB_TIMEOUT_SECONDS = 300


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run a controlled ThreatForge ingestion job"
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


def build_command(args):
    command = [
        sys.executable,
        str(ORCHESTRATOR),
        "--limit",
        str(args.limit),
        "--days",
        str(args.days),
    ]

    if args.execute:
        command.append("--execute")

    return command


def run_job(args) -> int:
    RUNTIME_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    with LOCK_FILE.open("a+") as lock:
        try:
            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            print("Status: skipped")
            print("Reason: another ingestion job is running")
            return 2

        print("=== THREATFORGE SCHEDULED INGESTION ===")
        print(f"Started UTC: {utc_now()}")

        print(
            "Mode: "
            + (
                "EXECUTE"
                if args.execute
                else "DRY RUN"
            )
        )

        command = build_command(args)

        try:
            result = subprocess.run(
                command,
                cwd=DATA_ENGINEERING_DIR,
                capture_output=True,
                text=True,
                timeout=JOB_TIMEOUT_SECONDS,
                check=False,
            )

            if result.returncode == 0:
                print("Status: success")
                return 0

            print("Status: failed")
            print(f"Pipeline exit code: {result.returncode}")
            return 1

        except subprocess.TimeoutExpired:
            print("Status: timeout")
            return 1

        except OSError:
            print("Status: execution_error")
            return 1

        finally:
            print(f"Finished UTC: {utc_now()}")
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def main() -> int:
    args = parse_arguments()
    return run_job(args)


if __name__ == "__main__":
    raise SystemExit(main())
