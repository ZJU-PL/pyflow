"""Hard deadlines cover blocked preparation and isolate optional import hooks."""

import json
import os
import subprocess
import sys
import time

import pytest

from pyflow.cli import callgraph
from pyflow.cli.callgraph_worker import CallgraphWorkerError, run_isolated_callgraph
from pyflow.ir.mir import lower_file
from tests.cli.test_callgraph import parse_callgraph_args


@pytest.mark.parametrize("algorithm", ["pycg", "pycg-mir"])
def test_hard_deadline_terminates_blocked_backend_and_preserves_output(
    tmp_path, monkeypatch, capsys, algorithm
):
    from pyflow.cli import callgraph_worker

    real_popen = subprocess.Popen
    processes = []

    def blocked_worker(*args, **kwargs):
        process = real_popen([sys.executable, "-c", "import time; time.sleep(20)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(callgraph_worker.subprocess, "Popen", blocked_worker)
    source = tmp_path / "main.py"
    source.write_text("pass\n")
    output = tmp_path / "graph.json"
    output.write_text('{"previous": []}')
    args = parse_callgraph_args(
        source, "--algorithm", algorithm, "--max-seconds", "0.2", "-o", output
    )
    started = time.monotonic()
    assert callgraph.run_callgraph(source, args) == 1
    assert time.monotonic() - started < 3
    assert processes[0].poll() is not None
    assert output.read_text() == '{"previous": []}'
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "worker was terminated" in captured.err


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")
def test_timeout_kills_descendants_holding_worker_pipes(monkeypatch):
    from pyflow.cli import callgraph_worker

    real_popen = subprocess.Popen

    def worker_with_child(*args, **kwargs):
        script = "import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); print('child started', flush=True); time.sleep(20)"
        return real_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(callgraph_worker.subprocess, "Popen", worker_with_child)
    started = time.monotonic()
    with pytest.raises(CallgraphWorkerError, match="exceeded"):
        run_isolated_callgraph({}, timeout=0.5)
    # communicate() cannot finish while a surviving child holds its pipes open.
    assert time.monotonic() - started < 3


def test_parent_does_not_eagerly_import_optional_pycg():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import pyflow.cli.callgraph; assert 'pycg' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_mir_import_depth_is_bounded_and_can_be_increased(tmp_path):
    entry = tmp_path / "entry.py"
    entry.write_text("import first\ndef run(): return first.run()\nrun()\n")
    (tmp_path / "first.py").write_text("import second\ndef run(): return second.leaf()\n")
    (tmp_path / "second.py").write_text("def leaf(): return 1\n")
    diagnostics = []
    program = lower_file(entry, import_policy="opaque", max_import_depth=1, diagnostics=diagnostics)
    assert "first.run" in program.cfgs
    assert "second.leaf" not in program.cfgs
    assert any(item["code"] == "mir-import-depth" for item in diagnostics)
    deeper = lower_file(entry, import_policy="opaque", max_import_depth=2)
    assert "second.leaf" in deeper.cfgs


def test_direct_import_can_upgrade_a_previous_depth_boundary(tmp_path):
    entry = tmp_path / "entry.py"
    entry.write_text("import first\nimport second\n")
    (tmp_path / "first.py").write_text("import second\n")
    (tmp_path / "second.py").write_text("def leaf(): return 1\n")
    program = lower_file(entry, import_policy="opaque", max_import_depth=1)
    assert "second.leaf" in program.cfgs


def test_native_worker_reports_import_depth_and_clean_json(tmp_path, capsys):
    entry = tmp_path / "entry.py"
    entry.write_text("import helper\ndef run(): return helper.f()\nrun()\n")
    (tmp_path / "helper.py").write_text("def f(): return 1\n")
    args = parse_callgraph_args(
        entry, "--algorithm", "pycg-mir", "--max-import-depth", "0", "--format", "json"
    )
    assert callgraph.run_callgraph(entry, args) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out)
    assert "partial" in captured.err
    assert "RuntimeWarning" not in captured.err
