"""Source inspection and recursive CLI regressions from project evaluations."""

import argparse
import json

from pyflow.cli import callgraph, capabilities


def _parse(module, command, *values):
    parser = argparse.ArgumentParser()
    getattr(module, f"add_{command}_parser")(parser.add_subparsers())
    return parser.parse_args([command, *map(str, values)])


def test_default_constraint_graph_resolves_methods_using_source_module_names(tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text(
        "class App:\n    def run(self):\n        helper()\ndef helper():\n    pass\nApp().run()\n"
    )
    args = _parse(callgraph, "callgraph", source)
    assert args.algorithm == "constraint"
    assert callgraph.run_callgraph(source, args) == 0
    text = capsys.readouterr().out
    assert "app.App.run -> app.helper" in text
    assert "main.App.run" not in text


def test_recursive_callgraph_analyzes_library_without_unique_entry(tmp_path, capsys):
    for name in ("left", "right"):
        (tmp_path / f"{name}.py").write_text(f"def {name}():\n    pass\n")
    args = _parse(callgraph, "callgraph", tmp_path, "-r")
    assert callgraph.run_callgraph(tmp_path, args) == 0
    text = capsys.readouterr().out
    assert "left.left" in text and "right.right" in text


def test_constraint_errors_do_not_write_success_artifacts(tmp_path, capsys):
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n")
    output = tmp_path / "graph.txt"
    args = _parse(callgraph, "callgraph", source, "-o", output)
    assert callgraph.run_callgraph(source, args) == 2
    assert "Error analyzing" in capsys.readouterr().err
    assert not output.exists()


def test_recursive_capabilities_scan_uses_all_independent_files(tmp_path, capsys):
    for name in ("left", "right"):
        (tmp_path / f"{name}.py").write_text("import subprocess\nsubprocess.run(['id'])\n")
    hidden = tmp_path / ".venv"
    hidden.mkdir()
    (hidden / "ignored.py").write_text("eval('1')\n")
    args = _parse(
        capabilities, "capabilities", tmp_path, "-r", "--import-depth", "0", "--format", "json"
    )
    assert capabilities.run_capabilities(args) == 0
    findings = json.loads(capsys.readouterr().out)["findings"]
    direct = [item for item in findings if item["report_kind"] == "direct"]
    assert {item["location"]["file"] for item in direct} == {
        str(tmp_path / "left.py"),
        str(tmp_path / "right.py"),
    }
