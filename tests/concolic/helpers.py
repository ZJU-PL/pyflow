"""Shared fixtures for concolic executor tests."""

from pathlib import Path

from pyflow.concolic import ExplorationResult, ReplayStatus, replay_runs


def target_file(tmp_path: Path, source: str) -> Path:
    target = tmp_path / "target.py"
    target.write_text(source, encoding="utf-8")
    return target


def assert_matches_cpython(path: Path, result: ExplorationResult) -> None:
    """Assert that every comparable run matches a fresh CPython execution."""

    replays = replay_runs(path, result.entry, result.runs)
    mismatches = [replay for replay in replays if replay.status is not ReplayStatus.MATCHED]
    assert not mismatches, [replay.differences for replay in mismatches]
