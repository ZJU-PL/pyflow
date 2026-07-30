"""Process execution primitives with explicit timeouts and durable logs."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ProcessOutcome:
    argv: tuple[str, ...]
    cwd: str
    returncode: int | None
    duration_seconds: float
    timed_out: bool
    stdout_path: str
    stderr_path: str
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 6),
            "timed_out": self.timed_out,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "error": self.error,
        }


def run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    env: Mapping[str, str] | None = None,
) -> ProcessOutcome:
    """Run an argv vector without a shell and terminate its process group on timeout."""

    command = tuple(str(part) for part in argv)
    started = time.monotonic()
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=timeout_seconds)
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process_group(process)
                returncode = process.returncode
        error = None
    except FileNotFoundError as exc:
        returncode = None
        timed_out = False
        error = str(exc)
        stderr_path.write_text(str(exc) + "\n", encoding="utf-8")
        stdout_path.touch()
    except OSError as exc:
        returncode = None
        timed_out = False
        error = str(exc)
        stderr_path.write_text(str(exc) + "\n", encoding="utf-8")
        stdout_path.touch()
    return ProcessOutcome(
        argv=command,
        cwd=str(cwd),
        returncode=returncode,
        duration_seconds=time.monotonic() - started,
        timed_out=timed_out,
        stdout_path=stdout_path.name,
        stderr_path=stderr_path.name,
        error=error,
    )


def probe_version(
    command: Sequence[str], *, cwd: Path, env: Mapping[str, str] | None = None
) -> str | None:
    """Return a stable one-line tool version without failing a benchmark run."""

    try:
        child_env = os.environ.copy()
        if env:
            child_env.update(env)
        completed = subprocess.run(
            tuple(command),
            cwd=str(cwd),
            env=child_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr).strip()
    return text.splitlines()[0] if text else None


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
