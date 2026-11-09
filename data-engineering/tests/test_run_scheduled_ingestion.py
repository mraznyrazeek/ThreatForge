
"""
ThreatForge - Scheduled Runner Safety Tests

All child processes are mocked.
No network calls or database writes.
"""

import fcntl
import signal
import subprocess
import sys

from pathlib import Path
from types import SimpleNamespace

import pytest


PROCESSING_DIR = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "processing"
)

sys.path.insert(0, str(PROCESSING_DIR))

import run_scheduled_ingestion as runner  # noqa: E402


@pytest.fixture
def isolated_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(
        runner,
        "RUNTIME_DIR",
        tmp_path,
    )

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


class FakeProcess:
    def __init__(self, returncode=0, timeout=False):
        self.pid = 123456
        self.returncode = returncode
        self.timeout = timeout
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1

        if self.timeout and self.wait_calls == 1:
            raise subprocess.TimeoutExpired(
                cmd="synthetic-command",
                timeout=timeout,
            )

        return self.returncode


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
    assert "--execute" not in command


def test_execute_requires_explicit_flag():
    command = runner.build_command(
        make_args(execute=True)
    )

    assert command[-1] == "--execute"


def test_successful_job(monkeypatch, isolated_runtime):
    def fake_popen(command, **kwargs):
        assert "--execute" not in command
        assert kwargs["start_new_session"] is True
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL

        return FakeProcess(returncode=0)

    monkeypatch.setattr(
        subprocess,
        "Popen",
        fake_popen,
    )

    assert runner.run_job(make_args()) == 0
    assert runner.LOCK_FILE.exists()


def test_failed_child_process(monkeypatch, isolated_runtime):
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(
            returncode=2
        ),
    )

    assert runner.run_job(make_args()) == 1


def test_timeout_terminates_process_group(
    monkeypatch,
    isolated_runtime,
):
    signals_sent = []

    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(
            timeout=True
        ),
    )

    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: signals_sent.append(
            (pid, sig)
        ),
    )

    assert runner.run_job(make_args()) == 1

    assert (
        123456,
        signal.SIGTERM,
    ) in signals_sent


def test_execution_error(monkeypatch, isolated_runtime):
    def fake_popen(*args, **kwargs):
        raise OSError("Synthetic execution failure")

    monkeypatch.setattr(
        subprocess,
        "Popen",
        fake_popen,
    )

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

        def unexpected_process(*args, **kwargs):
            raise AssertionError(
                "Overlapping job must not execute"
            )

        monkeypatch.setattr(
            subprocess,
            "Popen",
            unexpected_process,
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
        "Popen",
        lambda *args, **kwargs: FakeProcess(
            returncode=1
        ),
    )

    assert runner.run_job(make_args()) == 1

    # A subsequent invocation can acquire the lock.
    assert runner.run_job(make_args()) == 1


def test_termination_handler_raises():
    with pytest.raises(runner.JobInterrupted):
        runner.interruption_handler(
            signal.SIGTERM,
            None,
        )


def test_unexpected_signal_handlers_restored(monkeypatch):
    original_sigterm = signal.getsignal(signal.SIGTERM)
    original_sigint = signal.getsignal(signal.SIGINT)

    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(
            returncode=0
        ),
    )

    runner.execute_pipeline(
        runner.build_command(make_args())
    )

    assert (
        signal.getsignal(signal.SIGTERM)
        == original_sigterm
    )

    assert (
        signal.getsignal(signal.SIGINT)
        == original_sigint
    )
