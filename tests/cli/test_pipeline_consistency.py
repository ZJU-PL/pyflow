"""Regression tests for directory discovery, graph JSON, and alert folding."""

import argparse
import json

import pytest

from pyflow.cli import callgraph
from pyflow.cli.security.parser import add_security_parser
from pyflow.cli.security.command import run_security


def _security(*values):
    parser = argparse.ArgumentParser()
    add_security_parser(parser.add_subparsers())
    return parser.parse_args(["security", *map(str, values)])


def _graph(*values):
    parser = argparse.ArgumentParser()
    callgraph.add_callgraph_parser(parser.add_subparsers())
    return parser.parse_args(["callgraph", *map(str, values)])


@pytest.mark.parametrize("engine", ["ast-scanner", "ast-dataflow", "cpg", "ifds"])
def test_directory_targets_discover_nested_sources_without_recursive_flag(engine, tmp_path, capsys):
    path = tmp_path / "src" / "app.py"
    path.parent.mkdir()
    path.write_text("def run():\n    value = input()\n    eval(value)\nrun()\n")
    values = [tmp_path, "--engine", engine, "--format", "json", "--json-schema", "unified"]
    if engine == "ifds":
        values += ["--entry", "src/app.py"]
    args = _security(*values)
    assert not args.recursive
    assert run_security(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"]
    assert all(item["location"]["filename"] == str(path) for item in report["findings"])
    assert not args.recursive  # Keep caller-owned options unchanged.


@pytest.mark.parametrize("algorithm", ["simple", "constraint", "pycg-mir"])
def test_callgraph_json_is_a_caller_to_callees_map(algorithm, tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("def helper():\n    pass\ndef run():\n    helper()\nrun()\n")
    args = _graph(source, "--algorithm", algorithm, "--format", "json", "--verbose")
    assert callgraph.run_callgraph(source, args) == 0
    captured = capsys.readouterr()
    graph = json.loads(captured.out)
    assert graph
    assert all(
        isinstance(values, list) and values == sorted(set(values)) for values in graph.values()
    )
    caller = next(name for name in graph if name == "run" or name.endswith(".run"))
    assert any(name == "helper" or name.endswith(".helper") for name in graph[caller])
    assert any(not callees for callees in graph.values())


def test_callgraph_json_supports_project_and_recursive_outputs(tmp_path, capsys):
    source = tmp_path / "main.py"
    source.write_text("def main():\n    helper()\ndef helper():\n    pass\nmain()\n")
    for recursive in (False, True):
        output = tmp_path / f"graph-{recursive}.json"
        options = [tmp_path, "--format", "json", "--verbose", "-o", output]
        if recursive:
            options += ["--recursive"]
        assert callgraph.run_callgraph(tmp_path, _graph(*options)) == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        graph = json.loads(output.read_text())
        assert "main.helper" in graph["main.main"]


def test_pycg_json_uses_public_graph_renderer(monkeypatch, tmp_path, capsys):
    from pyflow.analysis.callgraph.callgraph import CallGraph
    from pyflow.analysis.callgraph import pycg_based

    source = tmp_path / "app.py"
    source.write_text("pass\n")

    def extract(*_args, **_kwargs):
        print("PyCG progress")
        graph = CallGraph()
        graph.add_edge("app.run", "app.helper")
        return graph

    monkeypatch.setattr(pycg_based, "extract_call_graph_pycg", extract)
    assert (
        callgraph.run_callgraph(
            source, _graph(source, "-a", "pycg", "--format", "json", "--verbose")
        )
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"app.helper": [], "app.run": ["app.helper"]}
    assert "PyCG progress" in captured.err


@pytest.mark.parametrize("schema", ["legacy", "unified"])
def test_debug_mode_overlap_is_folded_with_all_rule_evidence(schema, tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("app.run(debug=True)\n")
    args = _security(source, "--format", "json", "--json-schema", schema, "--fail-on", "high")
    assert run_security(args) == 1
    report = json.loads(capsys.readouterr().out)
    findings = report.get("findings", report.get("results"))
    assert len(findings) == 1
    finding = findings[0].get("properties", findings[0])
    assert finding["test_id"] == "F101"
    assert finding["issue_severity"] == "HIGH"
    assert {item["rule_id"] for item in finding["related_rules"]} == {"B202", "F101", "F109"}
    totals = report.get("statistics", report.get("metrics", {}).get("_totals"))
    assert totals["SEVERITY.HIGH"] == 1
    assert totals["SEVERITY.MEDIUM"] == 0
    assert totals["raw_findings"] == 3
    assert totals["folded_findings"] == 2
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(report))
    args.baseline = baseline
    assert run_security(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report.get("findings", report.get("results")) == []


def test_raw_rule_output_and_single_rule_suppression_are_preserved(tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("app.run(debug=True)\n")
    args = _security(source, "--format", "json", "--no-deduplicate")
    assert run_security(args) == 0
    assert {item["test_id"] for item in json.loads(capsys.readouterr().out)["results"]} == {
        "B202",
        "F101",
        "F109",
    }
    args.no_deduplicate = False
    args.skip_rule = [["F101"]]
    assert run_security(args) == 0
    result = json.loads(capsys.readouterr().out)["results"]
    assert len(result) == 1 and result[0]["test_id"] == "F109"
    assert {item["rule_id"] for item in result[0]["related_rules"]} == {"B202", "F109"}


def test_different_nodes_and_unrelated_vulnerabilities_on_one_line_are_kept(tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("app.run(debug=True); app.run(debug=True); eval(value)\n")
    assert run_security(_security(source, "--format", "json")) == 0
    results = json.loads(capsys.readouterr().out)["results"]
    debug = [item for item in results if item.get("vulnerability_family") == "flask-debug-mode"]
    assert len(debug) == 2
    assert debug[0]["col_offset"] != debug[1]["col_offset"]
    assert any(item["test_id"] not in {"B202", "F101", "F109"} for item in results)


@pytest.mark.parametrize("format", ["text", "sarif"])
def test_folded_rules_are_visible_in_text_and_sarif(format, tmp_path, capsys):
    source = tmp_path / "app.py"
    source.write_text("app.run(debug=True)\n")
    assert run_security(_security(source, "--format", format)) == 0
    text = capsys.readouterr().out
    if format == "text":
        assert "Related rules: B202, F109" in text
        assert text.count(">> Issue:") == 1
    else:
        results = json.loads(text)["runs"][0]["results"]
        assert len(results) == 1
        assert {item["rule_id"] for item in results[0]["properties"]["relatedRules"]} == {
            "B202",
            "F101",
            "F109",
        }
