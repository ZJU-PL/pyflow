"""CLI regressions for common source forms in the user trial."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "source",
    [
        "def deco(f):\n    def wrapper(*args, **kwargs):\n        return f(*args, **kwargs)\n    return wrapper\n",
        "counter = 0\ndef bump():\n    global counter\n    counter += 1\n    return counter\nbump()\n",
        "class Null:\n    def fail(self): raise RuntimeError()\n    pop = clear = fail\n    del fail\n",
        "class Context:\n    def update(self):\n        self.value = fetch()\n    def get(self):\n        if (value := fetch()):\n            return value\n",
    ],
)
def test_optimize_accepts_closure_and_global_state(tmp_path, source):
    path = tmp_path / "sample.py"
    path.write_text(source)
    completed = subprocess.run(
        [sys.executable, "-m", "pyflow.cli.main", "optimize", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Analysis complete!" in completed.stdout


def test_optimize_set_literal_and_lambda_closure(tmp_path):
    path = tmp_path / "formats.py"
    path.write_text(
        "def format_value(value):\n    mapping = {value, str(value)}\n    return lambda key: key in mapping\n"
    )
    completed = subprocess.run(
        [sys.executable, "-m", "pyflow.cli.main", "optimize", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
