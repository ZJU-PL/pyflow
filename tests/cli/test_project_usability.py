"""Source inspection and recursive CLI regressions from project evaluations."""

import argparse
import json

import pytest

from pyflow.cli import ir, callgraph, capabilities


def _parse(module, command, *values):
    parser = argparse.ArgumentParser()
    getattr(module, f"add_{command}_parser")(parser.add_subparsers())
    return parser.parse_args([command, *map(str, values)])


def test_source_mir_handles_common_imports_with_explicit_partial_semantics(tmp_path, capsys):
    source = tmp_path / "sample.py"
    source.write_text(
        "from collections.abc import Mapping\ndef worker(data):\n    ...\n    return data['x']\n"
    )
    output = tmp_path / "out"
    args = _parse(ir, "ir", source, "--dump-mir", "worker", "--dump-output", output)
    ir.run_ir_dump(source, args)
    content = next(output.glob("*_mir.text")).read_text()
    assert "sample.worker" in content
    assert "MIR partial inspection" in content
    error = capsys.readouterr().err
    assert "collections.abc" in error and "partial" in error
    assert "Traceback" not in error


def test_full_mir_export_still_rejects_unmodeled_imports(tmp_path, capsys):
    source = tmp_path / "sample.py"
    source.write_text("from collections.abc import Mapping\ndef worker(data):\n    return data\n")
    args = _parse(
        ir, "ir", source, "--dump-mir", "--dump-format", "json", "--dump-output", tmp_path / "out"
    )
    with pytest.raises(SystemExit) as error:
        ir.run_ir_dump(source, args)
    assert error.value.code == 1
    captured = capsys.readouterr()
    assert "collections.abc" in captured.err
    assert "Traceback" not in captured.err


def test_source_json_discloses_opaque_imports_and_literals(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("from collections.abc import Mapping\ndef worker():\n    return 1.5\n")
    output = tmp_path / "out"
    args = _parse(
        ir,
        "ir",
        source,
        "--dump-mir",
        "--mir-view",
        "source",
        "--dump-format",
        "json",
        "--dump-output",
        output,
    )
    ir.run_ir_dump(source, args)
    document = json.loads((output / "sample_mir.json").read_text())
    assert document["status"] == "partial"
    assert document["inspection_only"] is True
    assert {item["code"] for item in document["diagnostics"]} == {
        "mir-opaque-import",
        "mir-opaque-literal",
    }


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
