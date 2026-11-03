"""CLI reporting regressions for ``pyflow alias --engine kcfa``.

The k-CFA result carries completeness metadata; the CLI used to drop it and to
enumerate only ``ast.Name`` nodes, which hid imported names and definitions.
"""

import argparse
import json

from pyflow.cli import alias


def _args(*argv):
    parser = argparse.ArgumentParser()
    alias.add_alias_parser(parser.add_subparsers())
    return parser.parse_args(["alias", *map(str, argv)])


def test_collect_variable_names_covers_bindings_without_name_nodes():
    names = alias._collect_variable_names("""
import os
import package.sub
import json.decoder as dec
from pathlib import Path as P

def handler(arg, *, kwarg):
    try:
        pass
    except ValueError as exc:
        pass

class Widget:
    pass

match object():
    case {"k": value}:
        pass
""")

    assert {
        "os",
        "package",
        "dec",
        "P",
        "handler",
        "arg",
        "kwarg",
        "exc",
        "Widget",
    } <= names
    assert "value" in names


def test_json_report_exposes_completeness(tmp_path, capsys):
    entry = tmp_path / "main.py"
    entry.write_text("x = [1]\ny = x[0]\n", encoding="utf-8")

    args = _args(entry, "--engine", "kcfa", "--json", "--max-seconds", "30")
    assert alias.run_alias_analysis(str(entry), args) == 0

    payload = json.loads(capsys.readouterr().out)
    report = payload[0]
    assert report["complete"] is True
    assert report["stop_reason"] == "fixpoint"
    assert "statistics" in report
    assert "incomplete_reasons" in report


def test_text_report_prints_solver_status(tmp_path, capsys):
    entry = tmp_path / "main.py"
    entry.write_text("x = [1]\n", encoding="utf-8")

    args = _args(entry, "--engine", "kcfa")
    assert alias.run_alias_analysis(str(entry), args) == 0

    out = capsys.readouterr().out
    assert "solver: complete=yes" in out or "solver: complete=no" in out
    assert "stop_reason=" in out


def test_package_directory_is_accepted_as_project_root(tmp_path, capsys):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        "class A:\n    def m(self):\n        return [1]\n", encoding="utf-8"
    )
    entry = tmp_path / "main.py"
    entry.write_text("from pkg.core import A\nr = A().m()\n", encoding="utf-8")

    args = _args(
        entry, "--engine", "kcfa", "--json", "--project-root", str(package), "--max-seconds", "30"
    )
    assert alias.run_alias_analysis(str(entry), args) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["call_edges"], "package root must resolve project imports"
    assert not any("<native" in item for item in payload[0]["variables"]["r"]["points_to"])


def test_budget_exhaustion_marks_remaining_files_as_skipped(tmp_path, capsys, monkeypatch):
    for index in range(3):
        (tmp_path / f"mod{index}.py").write_text(f"x{index} = [1]\n", encoding="utf-8")

    from pyflow.cli import analysis_budget

    class BudgetExceeded(analysis_budget.AnalysisBudgetExceeded):
        pass

    calls = {"count": 0}

    def fake_budget(seconds):
        class _Budget:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Budget()

    def fake_analyze(filepath, *args, **kwargs):
        calls["count"] += 1
        raise BudgetExceeded("Analysis exceeded 0.1 seconds")

    monkeypatch.setattr(alias, "analysis_time_budget", fake_budget)
    monkeypatch.setattr(alias, "_analyze_file_kcfa_json", fake_analyze)

    args = _args(tmp_path, "--engine", "kcfa", "--json", "-r", "--max-seconds", "30")
    assert alias.run_alias_analysis(str(tmp_path), args) == 0

    payload = json.loads(capsys.readouterr().out)
    statuses = [entry["status"] for entry in payload]
    assert statuses[0] == "partial"
    assert statuses[1:] == ["skipped", "skipped"]
