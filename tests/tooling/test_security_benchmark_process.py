from __future__ import annotations

import sys

from tools.security_benchmark_runner.process import run_process


def test_run_process_records_timeout_and_logs(tmp_path):
    outcome = run_process(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        cwd=tmp_path,
        timeout_seconds=0.05,
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
    )

    assert outcome.timed_out is True
    assert (tmp_path / "stdout.log").exists()
    assert (tmp_path / "stderr.log").exists()
