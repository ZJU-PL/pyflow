import os
from pathlib import Path
import subprocess
import sys


def _run_guard(script, *extra):
    repo = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo / "src")
    return subprocess.run(
        [sys.executable, "-m", "pyflow.cli.main", "capability-run", *extra, str(script)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_guarded_runner_allows_clean_script(tmp_path):
    script = tmp_path / "clean.py"
    script.write_text("answer = 42\n")
    assert _run_guard(script).returncode == 0


def test_guarded_runner_denies_file_write(tmp_path):
    script = tmp_path / "write.py"
    script.write_text("open('created.txt', 'w').write('x')\n")
    completed = _run_guard(script)
    assert completed.returncode == 126
    assert "denied capability 'file.write'" in completed.stderr


def test_guarded_runner_denies_dynamic_code(tmp_path):
    script = tmp_path / "eval.py"
    script.write_text("eval('1 + 1')\n")
    completed = _run_guard(script)
    assert completed.returncode == 126
    assert "denied capability 'code.execute'" in completed.stderr


def test_guarded_runner_denies_import(tmp_path):
    (tmp_path / "helper.py").write_text("value = 1\n")
    script = tmp_path / "importer.py"
    script.write_text("import helper\n")
    completed = _run_guard(script)
    assert completed.returncode == 126
    assert "denied capability 'module.dynamic_import'" in completed.stderr
