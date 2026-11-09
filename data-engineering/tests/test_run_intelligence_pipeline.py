
"""
ThreatForge - Unified Ingestion Orchestrator Tests

All child processes are mocked.
No API calls or database writes are performed.
"""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PROCESSING_DIR = Path(__file__).resolve().parents[1] / "src" / "processing"
sys.path.insert(0, str(PROCESSING_DIR))

import run_intelligence_pipeline as pipeline  # noqa: E402


def test_default_sources(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["pipeline"])

    args = pipeline.parse_arguments()

    assert args.sources == ["threatfox", "urlhaus"]
    assert args.limit == 5
    assert args.days == 1
    assert args.execute is False


def test_source_selection(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["pipeline", "--sources", "urlhaus", "--limit", "3"],
    )

    args = pipeline.parse_arguments()

    assert args.sources == ["urlhaus"]
    assert args.limit == 3


@pytest.mark.parametrize("limit", [0, -1, 11])
def test_invalid_batch_limit_rejected(monkeypatch, limit):
    monkeypatch.setattr(
        sys,
        "argv",
        ["pipeline", "--limit", str(limit)],
    )

    with pytest.raises(SystemExit):
        pipeline.parse_arguments()


def test_threatfox_command_is_dry_run():
    command = pipeline.build_command(
        source="threatfox",
        limit=5,
        days=1,
        execute=False,
    )

    assert command[0] == sys.executable
    assert command[1].endswith("ingest_threatfox_batch.py")
    assert command[-4:] == ["--limit", "5", "--days", "1"]
    assert "--execute" not in command


def test_urlhaus_command_excludes_days():
    command = pipeline.build_command(
        source="urlhaus",
        limit=5,
        days=1,
        execute=False,
    )

    assert command[1].endswith("ingest_urlhaus_batch.py")
    assert "--days" not in command
    assert "--execute" not in command


def test_execute_flag_is_explicit():
    command = pipeline.build_command(
        source="urlhaus",
        limit=5,
        days=1,
        execute=True,
    )

    assert command[-1] == "--execute"


def test_successful_child_process(monkeypatch):
    def fake_run(command, **kwargs):
        assert "--execute" not in command
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == 120

        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = pipeline.run_source(
        "threatfox", 5, 1, False
    )

    assert result["status"] == "success"
    assert result["return_code"] == 0


def test_failed_child_process(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1),
    )

    result = pipeline.run_source(
        "urlhaus", 5, 1, False
    )

    assert result["status"] == "failed"
    assert result["return_code"] == 1


def test_source_timeout(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=command,
            timeout=120,
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = pipeline.run_source(
        "threatfox", 5, 1, False
    )

    assert result["status"] == "timeout"
    assert result["return_code"] != 0


def test_source_execution_error(monkeypatch):
    def fake_run(command, **kwargs):
        raise OSError("synthetic execution failure")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = pipeline.run_source(
        "urlhaus", 5, 1, False
    )

    assert result["status"] == "execution_error"
    assert result["return_code"] != 0


def test_failure_does_not_skip_next_source(monkeypatch):
    attempted = []

    monkeypatch.setattr(
        pipeline,
        "parse_arguments",
        lambda: SimpleNamespace(
            sources=["threatfox", "urlhaus"],
            limit=5,
            days=1,
            execute=False,
        ),
    )

    def fake_run_source(source, limit, days, execute):
        attempted.append(source)

        return {
            "source": source,
            "status": "failed" if source == "threatfox" else "success",
            "return_code": 1 if source == "threatfox" else 0,
        }

    monkeypatch.setattr(
        pipeline, "run_source", fake_run_source
    )

    assert pipeline.main() == 2
    assert attempted == ["threatfox", "urlhaus"]


def test_duplicate_sources_run_once(monkeypatch):
    attempted = []

    monkeypatch.setattr(
        pipeline,
        "parse_arguments",
        lambda: SimpleNamespace(
            sources=["urlhaus", "urlhaus"],
            limit=5,
            days=1,
            execute=False,
        ),
    )

    def fake_run_source(source, limit, days, execute):
        attempted.append(source)

        return {
            "source": source,
            "status": "success",
            "return_code": 0,
        }

    monkeypatch.setattr(
        pipeline, "run_source", fake_run_source
    )

    assert pipeline.main() == 0
    assert attempted == ["urlhaus"]
