
"""
ThreatForge - Resumable ThreatFox Snapshot Import

Imports a fixed ThreatFox snapshot into PostgreSQL using
the existing tested ingestion and persistence functions.

Features:
- Dry-run by default.
- Explicit --execute required for database writes.
- Maximum 1,000 records per batch.
- Checkpoint after each successfully finalized batch.
- Snapshot SHA-256 verification on resume.
- Snapshot-specific lock prevents concurrent imports.
- Safe batch retries using existing deduplication.
- Sanitized error reporting.
- No raw IOC values, credentials, or payloads logged.
- Does not modify the scheduled ingestion pipeline.

Run from data-engineering.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys

from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError


# ---------------------------------------------------------
# Project paths and imports
# ---------------------------------------------------------

SRC_DIR = Path(__file__).resolve().parents[1]
DATA_ENGINEERING_DIR = SRC_DIR.parent

sys.path.insert(
    0,
    str(SRC_DIR / "processing"),
)

from ingest_threatfox_batch import (  # noqa: E402
    create_verified_engine,
    normalize_batch,
    persist_batch,
    print_persistence_results,
    record_failed_run,
    classify_failure,
)

from ingestion_run_service import (  # noqa: E402
    IngestionFailureCategory,
    start_ingestion_run,
    complete_ingestion_run,
    fail_ingestion_run,
)


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

SNAPSHOT_DIR = (
    DATA_ENGINEERING_DIR
    / ".runtime"
    / "snapshots"
)

CHECKPOINT_DIR = (
    DATA_ENGINEERING_DIR
    / ".runtime"
    / "checkpoints"
)

SOURCE_NAME = "ThreatFox"

MAX_BATCH_SIZE = 1000

SNAPSHOT_PATTERN = re.compile(
    r"threatfox_\d{8}T\d{12}Z\.json"
)


# ---------------------------------------------------------
# Command-line arguments
# ---------------------------------------------------------

def parse_arguments():
    """
    Parse and validate snapshot import arguments.
    """

    parser = argparse.ArgumentParser(
        description="Resumable ThreatFox snapshot ingestion"
    )

    parser.add_argument(
        "--snapshot",
        required=True,
        help=(
            "Snapshot filename inside "
            ".runtime/snapshots"
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Records per batch (1-1000)",
    )

    parser.add_argument(
        "--max-batches",
        type=int,
        default=1,
        help=(
            "Maximum batches processed "
            "per invocation (1-100)"
        ),
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Enable PostgreSQL writes "
            "and checkpoint updates"
        ),
    )

    args = parser.parse_args()

    if not SNAPSHOT_PATTERN.fullmatch(
        args.snapshot
    ):
        parser.error(
            "Invalid ThreatFox snapshot filename"
        )

    if not 1 <= args.batch_size <= MAX_BATCH_SIZE:
        parser.error(
            "--batch-size must be between 1 and 1000"
        )

    if not 1 <= args.max_batches <= 100:
        parser.error(
            "--max-batches must be between 1 and 100"
        )

    return args


# ---------------------------------------------------------
# Snapshot loading and validation
# ---------------------------------------------------------

def load_snapshot(filename):
    """
    Load and validate a fixed ThreatFox snapshot.

    Calculate a SHA-256 fingerprint of the snapshot
    to verify checkpoint compatibility.
    """

    path = SNAPSHOT_DIR / filename

    if (
        not path.is_file()
        or path.is_symlink()
    ):
        raise ValueError(
            "Snapshot file not found or invalid"
        )

    raw = path.read_bytes()

    digest = hashlib.sha256(
        raw
    ).hexdigest()

    snapshot = json.loads(raw)

    if not isinstance(snapshot, dict):
        raise ValueError(
            "Invalid snapshot structure"
        )

    if snapshot.get("source") != SOURCE_NAME:
        raise ValueError(
            "Unexpected snapshot source"
        )

    records = snapshot.get("records")

    if not isinstance(records, list):
        raise ValueError(
            "Snapshot records must be a list"
        )

    if snapshot.get("record_count") != len(records):
        raise ValueError(
            "Snapshot record count mismatch"
        )

    if any(
        not isinstance(record, dict)
        for record in records
    ):
        raise ValueError(
            "Snapshot contains invalid records"
        )

    if any(
        record.get("id") is None
        for record in records
    ):
        raise ValueError(
            "Snapshot contains missing record IDs"
        )

    identifiers = [
        str(record["id"])
        for record in records
    ]

    if len(identifiers) != len(set(identifiers)):
        raise ValueError(
            "Snapshot contains duplicate source IDs"
        )

    return records, digest


# ---------------------------------------------------------
# Checkpoint paths and validation
# ---------------------------------------------------------

def checkpoint_path(snapshot_filename):
    """
    Return the checkpoint path for a snapshot.
    """

    return CHECKPOINT_DIR / (
        snapshot_filename.removesuffix(".json")
        + ".checkpoint.json"
    )


def load_checkpoint(
    path,
    digest,
    batch_size,
    total,
):
    """
    Load and validate the existing checkpoint.

    Return zero when no checkpoint exists.

    Reject incompatible snapshot fingerprints,
    batch sizes, record counts, or offsets.
    """

    if not path.exists():
        if path.is_symlink():
            raise ValueError(
                "Invalid checkpoint file"
            )

        return 0

    if (
        path.is_symlink()
        or not path.is_file()
    ):
        raise ValueError(
            "Invalid checkpoint file"
        )

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError(
            "Invalid checkpoint structure"
        )

    if data.get("source") != SOURCE_NAME:
        raise ValueError(
            "Checkpoint source mismatch"
        )

    if data.get("snapshot_sha256") != digest:
        raise ValueError(
            "Snapshot fingerprint changed"
        )

    if data.get("batch_size") != batch_size:
        raise ValueError(
            "Checkpoint batch size mismatch"
        )

    if data.get("total_records") != total:
        raise ValueError(
            "Checkpoint record count mismatch"
        )

    offset = data.get("next_offset")

    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or not 0 <= offset <= total
    ):
        raise ValueError(
            "Invalid checkpoint offset"
        )

    if (
        offset != total
        and offset % batch_size != 0
    ):
        raise ValueError(
            "Checkpoint is not batch-aligned"
        )

    return offset


# ---------------------------------------------------------
# Atomic checkpoint persistence
# ---------------------------------------------------------

def save_checkpoint(
    path,
    digest,
    batch_size,
    total,
    offset,
):
    """
    Atomically save progress after a successful batch.

    The checkpoint is written to a temporary file
    and then moved into place using os.replace().
    """

    CHECKPOINT_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    os.chmod(
        CHECKPOINT_DIR,
        0o700,
    )

    if path.is_symlink():
        raise ValueError(
            "Invalid checkpoint destination"
        )

    data = {
        "source": SOURCE_NAME,
        "snapshot_sha256": digest,
        "batch_size": batch_size,
        "total_records": total,
        "next_offset": offset,
    }

    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.tmp"
    )

    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                data,
                file,
                indent=2,
            )

            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temporary,
            path,
        )

    finally:
        temporary.unlink(
            missing_ok=True
        )


# ---------------------------------------------------------
# Snapshot-specific locking
# ---------------------------------------------------------

def acquire_snapshot_lock(snapshot_filename):
    """
    Acquire a non-blocking lock for this snapshot.

    Prevent multiple instances of this importer
    from importing the same snapshot concurrently.

    The returned file must remain open throughout
    the import.

    The lock is released by the caller in finally.
    """

    CHECKPOINT_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    os.chmod(
        CHECKPOINT_DIR,
        0o700,
    )

    lock_path = CHECKPOINT_DIR / (
        snapshot_filename.removesuffix(".json")
        + ".lock"
    )

    if lock_path.is_symlink():
        raise ValueError(
            "Invalid snapshot lock path"
        )

    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT,
        0o600,
    )

    lock = os.fdopen(
        descriptor,
        "a+",
    )

    try:
        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )

    except BlockingIOError:
        lock.close()

        raise RuntimeError(
            "Another process is already "
            "importing this snapshot"
        )

    except Exception:
        lock.close()
        raise

    return lock


def release_snapshot_lock(lock):
    """
    Release and close a previously acquired lock.

    The lock file stays on disk.
    Only the operating-system lock is released.
    """

    if lock is None:
        return

    try:
        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_UN,
        )

    finally:
        lock.close()


# ---------------------------------------------------------
# Batch normalization and persistence
# ---------------------------------------------------------

def process_batch(
    records,
    engine,
    execute,
):
    """
    Normalize and optionally persist one fixed batch.

    Return True only when the batch has been
    processed and finalized successfully.
    """

    run_id = None
    source_id = None

    received = len(records)

    normalized = 0
    rejected = 0

    phase = "normalization"

    try:
        if execute:
            started = start_ingestion_run(
                engine=engine,
                source_name=SOURCE_NAME,
            )

            run_id = started.run_id
            source_id = started.source_id

            print(
                f"Ingestion run ID: {run_id}"
            )

        observations, counts = normalize_batch(
            records,
            engine=engine if execute else None,
            source_id=source_id if execute else None,
            ingestion_run_id=run_id if execute else None,
        )

        normalized = counts["normalized"]
        rejected = counts["rejected"]

        if normalized + rejected != received:
            raise ValueError(
                "Normalization count mismatch"
            )

        print(
            f"Normalized: {normalized}"
        )

        print(
            f"Rejected: {rejected}"
        )

        if not execute:
            return rejected == 0

        phase = "persistence"

        persistence_counts = persist_batch(
            engine=engine,
            observations=observations,
            ingestion_run_id=run_id,
        )

        successful, failures = (
            print_persistence_results(
                persistence_counts
            )
        )

        if successful + failures != normalized:
            raise RuntimeError(
                "Persistence count mismatch"
            )

        phase = "finalization"

        if failures:
            fail_ingestion_run(
                engine=engine,
                run_id=run_id,
                failure_category=(
                    IngestionFailureCategory
                    .PERSISTENCE_FAILURE
                ),
                records_received=received,
                records_normalized=normalized,
                records_rejected=rejected,
            )

            run_id = None

            print(
                "Batch failed: persistence failures"
            )

            return False

        completed = complete_ingestion_run(
            engine=engine,
            run_id=run_id,
            records_received=received,
            records_normalized=normalized,
            records_rejected=rejected,
        )

        run_id = None

        print(
            f"Run status: {completed.status}"
        )

        return True

    except (
        ValueError,
        RuntimeError,
        SQLAlchemyError,
    ) as exc:

        print(
            "Batch processing failed: "
            f"{type(exc).__name__}"
        )

        record_failed_run(
            engine,
            run_id,
            classify_failure(phase),
            received,
            normalized,
            rejected,
        )

        return False


# ---------------------------------------------------------
# Main snapshot import workflow
# ---------------------------------------------------------

def main():
    args = parse_arguments()

    print(
        "=== THREATFORGE SNAPSHOT IMPORT ==="
    )

    print(
        f"Mode: {'EXECUTE' if args.execute else 'DRY RUN'}"
    )

    print(
        f"Batch size: {args.batch_size}"
    )

    print(
        f"Maximum batches: {args.max_batches}"
    )

    engine = None
    snapshot_lock = None

    try:
        # Acquire the snapshot lock before loading
        # or processing snapshot/checkpoint data.

        snapshot_lock = acquire_snapshot_lock(
            args.snapshot
        )

        records, digest = load_snapshot(
            args.snapshot
        )

        total = len(records)

        path = checkpoint_path(
            args.snapshot
        )

        offset = load_checkpoint(
            path,
            digest,
            args.batch_size,
            total,
        )

        print(
            f"Snapshot records: {total}"
        )

        print(
            f"Starting offset: {offset}"
        )

        print(
            f"Remaining records: {total - offset}"
        )

        if offset == total:
            print(
                "Snapshot already fully imported."
            )
            return 0

        if args.execute:
            engine = create_verified_engine()

            print(
                "Verified database: threatforge_db"
            )

        processed_batches = 0

        while offset < total:

            if processed_batches >= args.max_batches:
                break

            end = min(
                offset + args.batch_size,
                total,
            )

            batch = records[
                offset:end
            ]

            print(
                f"\n=== BATCH {processed_batches + 1}: "
                f"RECORDS {offset + 1}-{end} ==="
            )

            success = process_batch(
                batch,
                engine,
                args.execute,
            )

            if not success:
                print(
                    "Import stopped at current batch."
                )

                print(
                    "Checkpoint not advanced."
                )

                return 2

            # Only advance progress after successful
            # processing and finalization.

            next_offset = end

            if args.execute:
                save_checkpoint(
                    path,
                    digest,
                    args.batch_size,
                    total,
                    next_offset,
                )

            offset = next_offset
            processed_batches += 1

            print(
                f"Progress: {offset}/{total}"
            )

        print(
            "\n=== SNAPSHOT IMPORT SUMMARY ==="
        )

        print(
            f"Batches processed: {processed_batches}"
        )

        if args.execute:
            print(
                f"Persisted checkpoint offset: {offset}"
            )

        else:
            print(
                "No PostgreSQL or checkpoint writes."
            )

        if offset == total:
            print(
                "Snapshot processing complete."
            )

        else:
            print(
                f"Remaining records: {total - offset}"
            )

        return 0

    except (
        ValueError,
        KeyError,
        OSError,
        RuntimeError,
        SQLAlchemyError,
    ) as exc:

        print(
            "Snapshot import failed: "
            f"{type(exc).__name__}"
        )

        return 1

    finally:
        # Close the database connection first.

        if engine is not None:
            engine.dispose()

        # Keep the lock until processing and
        # database cleanup have completed.

        if snapshot_lock is not None:
            release_snapshot_lock(
                snapshot_lock
            )


if __name__ == "__main__":
    raise SystemExit(main())
