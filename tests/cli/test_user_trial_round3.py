"""Regressions for real-project timeouts, reports, and rule precision."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


def cli(*args):
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from pyflow.cli.main import entrypoint; raise SystemExit(entrypoint())",
            *map(str, args),
        ],
        capture_output=True,
        text=True,
        timeout=40,
    )


@pytest.mark.parametrize(
    "source,rule",
    [
        ('from pathlib import Path\nPath("out").write_text(f"Generated {date}")\n', "B611"),
        ('def format_prompt_preview(): return "hello"\n', "F108"),
        ('import os, tempfile\nos.path.join(tempfile.gettempdir(), "cache")\n', "B203"),
        ("import os\nos.path.isdir(get_system_path())\n", "B205"),
        ("def worker(token, secret): return token\n", "A104"),
    ],
)
def test_scanner_does_not_infer_unrelated_security_roles(tmp_path, source, rule):
    path = tmp_path / "sample.py"
    path.write_text(source)
    result = cli("security", path, "--format", "json")
    assert result.returncode == 0, result.stderr
    assert all(finding["test_id"] != rule for finding in json.loads(result.stdout)["results"])


@pytest.mark.parametrize(
    "source,rule",
    [
        ('from sqlalchemy import text\ntext(f"SELECT * FROM t WHERE id={user_id}")\n', "B611"),
        (
            'from flask import Flask\napp=Flask(__name__)\n@app.post("/form")\ndef submit(): pass\n',
            "F108",
        ),
        ('import os\nos.path.join("base", input())\n', "B203"),
        (
            'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/account")\ndef account(token): return token\n',
            "A104",
        ),
    ],
)
def test_scanner_keeps_supported_positive_matches(tmp_path, source, rule):
    path = tmp_path / "sample.py"
    path.write_text(source)
    result = cli("security", path, "--format", "json")
    assert result.returncode == 0, result.stderr
    assert any(finding["test_id"] == rule for finding in json.loads(result.stdout)["results"])


@pytest.mark.parametrize("engine", ["ast-dataflow", "ifds"])
def test_json_parsing_propagates_taint_without_being_an_execution_sink(tmp_path, engine):
    path = tmp_path / "sample.py"
    path.write_text(
        "import json\ndef run():\n    value = json.loads(input())\n    eval(value)\nrun()\n"
    )
    result = cli("security", path, "--engine", engine, "--format", "json")
    assert result.returncode == 0, result.stderr
    findings = json.loads(result.stdout)["findings"]
    assert findings
    assert {finding["sink_name"] for finding in findings} == {"eval"}


def test_opaque_mir_keeps_local_import_edges_and_strict_failure_is_friendly(tmp_path):
    (tmp_path / "helper.py").write_text("def helper(): return 1\n")
    path = tmp_path / "entry.py"
    path.write_text(
        "import unavailable_third_party\nfrom helper import helper\ndef run(): return helper()\nrun()\n"
    )
    result = cli("callgraph", path, "--engine", "pycg-mir", "--format", "json")
    assert result.returncode == 0, result.stderr
    assert "helper.helper" in json.loads(result.stdout)["entry.run"]
    strict = cli("callgraph", path, "--engine", "pycg-mir", "--mir-import-policy", "strict")
    assert strict.returncode == 1
    assert "no local source or MIR runtime model" in strict.stderr
    assert "Traceback" not in strict.stderr


def test_optimize_dump_refreshes_facts_and_accepts_keyword_tuples(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text(
        "import unavailable_library\ndef helper(x): return x\ndef run(x): return helper(x=x)\n"
    )
    output = tmp_path / "report"
    result = cli("optimize", path, "--dump", "--output", output)
    assert result.returncode == 0, result.stderr
    assert "Could not" not in result.stdout + result.stderr
    assert "Results dumped" in result.stdout
    assert list(tmp_path.rglob("*.html"))


def test_concolic_default_string_seed_uses_annotation(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("def main(value: str):\n    return len(value)\n")
    result = cli("concolic", path, "--max-iterations", "1", "--json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["runs"][0]["inputs"] == [""]


def test_alias_hides_generated_runtime_helpers_unless_verbose(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text('def f(a):\n    return f"value: {a}"\n')
    normal = cli("alias", path)
    detailed = cli("alias", path, "--verbose")
    assert normal.returncode == detailed.returncode == 0
    assert "interpreter_format" not in normal.stdout
    assert "interpreter_format" in detailed.stdout


def test_native_mir_budget_is_reported_without_internal_warning_stack(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("def f(): pass\nf()\n")
    result = cli(
        "callgraph",
        path,
        "--engine",
        "pycg-mir",
        "--mir-max-seconds",
        "0.000001",
        "--format",
        "json",
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)
    assert "MIR call graph is partial" in result.stderr
    assert "Time budget" in result.stderr
    assert "PyCGMIRConvergenceWarning" not in result.stderr
