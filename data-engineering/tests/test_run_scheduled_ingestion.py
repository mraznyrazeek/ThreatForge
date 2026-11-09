
"""
ThreatForge - Scheduled Ingestion Runner Tests

Verify one-shot job execution, dry-run safety, failure
handling, and non-overlapping execution.

No real child processes, API calls, or database writes.
"""

import fcntl
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import run_scheduled_ingestion as runner  # noqa: E402


@pytest.fixture
def isolated_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "RUNTIME_DIR", tmp_path)
    monkeypatch.setattr(
        runner,
        "LOCK_FILE",
        tmp_path / "ingestion.lock",
    )


def make_args(execute=False, limit=5, days=1):
    return SimpleNamespace(
        execute=execute,
        limit=limit,
        days=days,
    )


def test_default_arguments(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["scheduled-ingestion"],
    )

    args = runner.parse_arguments()

    assert args.limit == 5
    assert args.days == 1
    assert args.execute is False


@pytest.mark.parametrize("limit", [0, -1, 11])
def test_invalid_limit_rejected(monkeypatch, limit):
    monkeypatch.setattr(
        sys,
        "argv",
        ["scheduled-ingestion", "--limit", str(limit)],
    )

    with pytest.raises(SystemExit):
        runner.parse_arguments()


def test_dry_run_command():
    command = runner.build_command(make_args())

    assert command[0] == sys.executable
    assert command[1] == str(runner.ORCHESTRATOR)
    assert "--limit" in command
    assert "--days" in command
    assert "--execute" not in command


def test_execute_requires_explicit_flag():
    command = runner.build_command(
        make_args(execute=True)
    )

    assert command[-1] == "--execute"


def test_successful_job(monkeypatch, isolated_runtime):
    def fake_run(command, **kwargs):
        assert "--execute" not in command
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == runner.JOB_TIMEOUT_SECONDS

        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert runner.run_job(make_args()) == 0
    assert runner.LOCK_FILE.exists()


def test_failed_child_process(monkeypatch, isolated_runtime):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=2
        ),
    )

    assert runner.run_job(make_args()) == 1


def test_child_timeout(monkeypatch, isolated_runtime):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=command,
            timeout=runner.JOB_TIMEOUT_SECONDS,
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert runner.run_job(make_args()) == 1


def test_execution_error(monkeypatch, isolated_runtime):
    def fake_run(command, **kwargs):
        raise OSError("Synthetic execution failure")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert runner.run_job(make_args()) == 1


def test_overlapping_job_is_skipped(
    monkeypatch,
    isolated_runtime,
):
    runner.LOCK_FILE.touch()

    with runner.LOCK_FILE.open("a+") as lock:
        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )

        def should_not_run(*args, **kwargs):
            raise AssertionError(
                "Overlapping job must not execute"
            )

        monkeypatch.setattr(
            subprocess,
            "run",
            should_not_run,
        )

        assert runner.run_job(make_args()) == 2

        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_UN,
        )


def test_lock_released_after_failure(
    monkeypatch,
    isolated_runtime,
):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1
        ),
    )

    assert runner.run_job(make_args()) == 1

    # A second invocation must be able to acquire the lock.
    assert runner.run_job(make_args()) == 1
