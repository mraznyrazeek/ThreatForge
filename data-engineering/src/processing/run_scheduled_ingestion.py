
"""
ThreatForge - Safe Scheduled Ingestion Runner

Runs the unified ingestion pipeline as one scheduled job.

Safety:
- Dry-run by default.
- Explicit --execute required for database writes.
- Prevents overlapping scheduled jobs.
- Runs child processes in an isolated process group.
- Terminates the process group on timeout/interruption.
- Never logs raw API responses, IOCs, or credentials.
- Does not automatically modify stale ingestion runs.

Designed for macOS launchd.
"""

import argparse
import fcntl
import os
import signal
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
TERMINATION_GRACE_SECONDS = 10


class JobInterrupted(Exception):
    """Raised when the scheduler receives a stop signal."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run scheduled ThreatForge ingestion"
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
        help="Enable PostgreSQL writes",
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


def terminate_process_group(process):
    """
    Stop the orchestrator and its descendant processes.

    Because the orchestrator starts in a new process
    session, its child ingestion scripts inherit that
    session unless they deliberately detach.
    """

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(
            timeout=TERMINATION_GRACE_SECONDS
        )
    except subprocess.TimeoutExpired:
        pass

    # Terminate any remaining members of the same group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    process.wait()


def interruption_handler(signum, frame):
    raise JobInterrupted()


def execute_pipeline(command):
    """
    Execute the pipeline with a process-group boundary.

    Return a safe status and exit code.
    """

    previous_sigterm = signal.getsignal(signal.SIGTERM)
    previous_sigint = signal.getsignal(signal.SIGINT)

    process = None

    try:
        signal.signal(
            signal.SIGTERM,
            interruption_handler,
        )

        signal.signal(
            signal.SIGINT,
            interruption_handler,
        )

        process = subprocess.Popen(
            command,
            cwd=DATA_ENGINEERING_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        try:
            return_code = process.wait(
                timeout=JOB_TIMEOUT_SECONDS
            )

        except subprocess.TimeoutExpired:
            terminate_process_group(process)
            return "timeout", 1

        if return_code == 0:
            return "success", 0

        return "failed", return_code

    except JobInterrupted:
        if process is not None:
            terminate_process_group(process)

        return "interrupted", 1

    except OSError:
        if process is not None:
            terminate_process_group(process)

        return "execution_error", 1

    finally:
        signal.signal(
            signal.SIGTERM,
            previous_sigterm,
        )

        signal.signal(
            signal.SIGINT,
            previous_sigint,
        )


def run_job(args) -> int:
    """Run one controlled and non-overlapping job."""

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
            print(
                "Reason: another ingestion job is running"
            )
            return 2

        try:
            print(
                "=== THREATFORGE SCHEDULED INGESTION ===",
                flush=True,
            )

            print(
                f"Started UTC: {utc_now()}",
                flush=True,
            )

            print(
                "Mode: "
                + (
                    "EXECUTE"
                    if args.execute
                    else "DRY RUN"
                ),
                flush=True,
            )

            command = build_command(args)

            status, return_code = execute_pipeline(
                command
            )

            print(
                f"Status: {status}",
                flush=True,
            )

            print(
                f"Pipeline exit code: {return_code}",
                flush=True,
            )

            return 0 if status == "success" else 1

        finally:
            print(
                f"Finished UTC: {utc_now()}",
                flush=True,
            )

            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_UN,
            )


def main() -> int:
    args = parse_arguments()
    return run_job(args)


if __name__ == "__main__":
    raise SystemExit(main())
