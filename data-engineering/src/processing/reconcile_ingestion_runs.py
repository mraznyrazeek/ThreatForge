
"""
ThreatForge - Manual Ingestion Run Reconciliation

Lists potentially stale ingestion runs and supports
explicit operator-approved reconciliation.

Safety:
- Read-only by default.
- Never automatically changes a run because of its age.
- Requires an exact run ID and explicit confirmation.
- Requires the scheduler/ingestion processes to be stopped
  and checked by the operator before an update.
- Uses the scheduled runner's lock.
- Rechecks status and age in PostgreSQL.
- Never deletes observations, indicators, or history.
- Does not expose raw IOC values or credentials.
"""

import argparse
import fcntl
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


PROCESSING_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = PROCESSING_DIR.parents[1] / ".runtime"
LOCK_FILE = RUNTIME_DIR / "ingestion.lock"

from monitor_ingestion import create_monitoring_engine  # noqa: E402


MINIMUM_STALE_MINUTES = 15


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Inspect or reconcile stale ingestion runs"
    )

    parser.add_argument(
        "--run-id",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Enable a specifically confirmed database update",
    )

    parser.add_argument(
        "--confirm-run-id",
        type=int,
        default=None,
        help="Repeat the exact run ID to authorize reconciliation",
    )

    args = parser.parse_args()

    if args.apply:
        if args.run_id is None or args.run_id <= 0:
            parser.error("--apply requires a positive --run-id")

        if args.confirm_run_id != args.run_id:
            parser.error(
                "--confirm-run-id must match --run-id"
            )
    elif args.confirm_run_id is not None:
        parser.error(
            "--confirm-run-id requires --apply"
        )

    return args


def list_stale_runs(engine):
    """Display potentially stale runs without modifying data."""

    with engine.connect() as connection:
        connection.execute(
            text("SET TRANSACTION READ ONLY")
        )

        rows = connection.execute(
            text(
                """
                SELECT
                    r.id,
                    s.name AS source_name,
                    r.status,
                    r.started_at,
                    r.records_received,
                    r.records_normalized,
                    r.records_rejected
                FROM ingestion_runs r
                JOIN intelligence_sources s
                    ON s.id = r.source_id
                WHERE r.status = 'running'
                  AND r.started_at <=
                      clock_timestamp()
                      - INTERVAL '15 minutes'
                ORDER BY r.started_at
                """
            )
        ).mappings().all()

    print("=== POTENTIALLY STALE INGESTION RUNS ===")

    if not rows:
        print("No potentially stale runs detected.")
        return

    for row in rows:
        print(
            f"Run #{row['id']} | "
            f"{row['source_name']} | "
            f"{row['status']} | "
            f"started={row['started_at']}"
        )

    print(
        "\nThese runs require manual investigation. "
        "Age alone does not establish that they are abandoned."
    )


def reconcile_run(engine, run_id):
    """
    Reconcile exactly one confirmed, abandoned run.

    The caller must have stopped the scheduler and checked
    for active ingestion processes before invoking this.

    The update occurs only if the run is still running
    and exceeds the minimum stale threshold.
    """

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
            print(
                "Recovery refused: scheduled ingestion "
                "lock is currently held."
            )
            return 2

        try:
            with engine.begin() as connection:
                row = connection.execute(
                    text(
                        """
                        UPDATE ingestion_runs
                        SET
                            status = 'failed',
                            completed_at = clock_timestamp(),
                            error_summary = 'unexpected_failure'
                        WHERE id = :run_id
                          AND status = 'running'
                          AND started_at <=
                              clock_timestamp()
                              - INTERVAL '15 minutes'
                        RETURNING id
                        """
                    ),
                    {"run_id": run_id},
                ).scalar_one_or_none()

            if row is None:
                print(
                    "No eligible running record found. "
                    "No changes made."
                )
                return 2

            print(
                f"Run #{row} reconciled with "
                "status=failed."
            )
            print(
                "Existing observations and history "
                "were preserved."
            )

            return 0

        finally:
            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_UN,
            )


def main():
    args = parse_arguments()
    engine = None

    try:
        engine = create_monitoring_engine()

        if not args.apply:
            list_stale_runs(engine)
            return 0

        print(
            "Operator confirmation received for "
            f"run #{args.run_id}."
        )

        return reconcile_run(
            engine,
            args.run_id,
        )

    except (SQLAlchemyError, OSError, ValueError) as exc:
        print(
            "Reconciliation failed: "
            f"{type(exc).__name__}"
        )
        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
