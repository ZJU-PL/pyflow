"""Cross-engine regression checks for shared report utilities."""

import io
import json
from types import SimpleNamespace

import pytest

from pyflow.checker.common.diagnostics import CheckerDiagnostic, diagnostics_to_dicts
from pyflow.checker.common.issue import Issue
from pyflow.checker.ast_dataflow.core.manager import ASTDataflowManager
from pyflow.checker.ast_dataflow.detectors.taint import (
    ASTDataflowTaintFinding,
    ASTDataflowTaintResult,
)
from pyflow.checker.cpg.taint.model import TaintFinding
from pyflow.checker.formatters import json as json_formatter
from pyflow.checker.formatters import sarif as sarif_formatter
from pyflow.checker.formatters import yaml as yaml_formatter
from pyflow.checker.formatters.cpg import finding_to_sarif
from pyflow.checker.formatters.security import ast_dataflow_report, security_sarif


@pytest.mark.parametrize(
    "severity,level", [("LOW", "note"), ("MEDIUM", "warning"), ("HIGH", "error")]
)
def test_engines_use_the_same_sarif_severity_mapping(severity, level):
    issue = Issue(severity, lineno=3, test_id="TEST", confidence="HIGH", text="A finding")
    issue.fname = "sample.py"
    manager = SimpleNamespace(get_issue_list=lambda **_: [issue])
    output = io.StringIO()
    sarif_formatter.report(manager, output, "LOW", "LOW")
    assert json.loads(output.getvalue())["runs"][0]["results"][0]["level"] == level

    cpg = TaintFinding("CWE-89", severity.lower(), "external", "database", None, None)
    assert finding_to_sarif(cpg)["level"] == level
    ast_finding = ASTDataflowTaintFinding(
        "f", "sample.py", "sink", 3, frozenset({"input"}), "TEST", "A finding", severity.lower()
    )
    ast_result = ASTDataflowTaintResult((ast_finding,))
    ast_manager = SimpleNamespace(analysis_result=ast_result)
    ast_doc = security_sarif("ast-dataflow", ast_manager)
    ifds_doc = security_sarif(
        "ifds", {"status": "partial", "findings": [{"rule_id": "TEST", "severity": severity}]}
    )
    cpg_doc = security_sarif("cpg", {"status": "complete", "findings": [cpg.to_dict()]})
    for document in (ast_doc, ifds_doc, cpg_doc):
        assert document["runs"][0]["results"][0]["level"] == level
    assert not ifds_doc["runs"][0]["invocations"][0]["executionSuccessful"]


def test_shared_diagnostics_preserve_source_and_precision_information():
    diagnostic = CheckerDiagnostic(
        "Incomplete graph", "graph-partial", True, "f", "graph", "sample.py", 3, "call"
    )
    result = ASTDataflowTaintResult((), status="partial", diagnostics=(diagnostic,))
    report = ast_dataflow_report(SimpleNamespace(analysis_result=result))
    serialized = report["diagnostics"][0]
    assert serialized["filename"] == "sample.py"
    assert serialized["line"] == 3
    assert serialized["level"] == "graph"
    assert serialized["affects_completeness"]
    assert diagnostics_to_dicts([serialized]) == [serialized]


def test_missing_analysis_result_is_a_failed_report():
    report = ast_dataflow_report(SimpleNamespace())
    assert report["status"] == "failed"
    assert report["findings"] == []
    assert report["diagnostics"][0]["code"] == "ast-dataflow-missing-result"


def test_cpg_formatter_preserves_full_code_flow_with_unknown_source_lines():
    nodes = [
        SimpleNamespace(ast_node=SimpleNamespace(lineno=index), label=f"step {index}", kind="flow")
        for index in range(12)
    ]
    finding = TaintFinding("CWE-89", "medium", "external", "database", None, None, path_nodes=nodes)
    result = finding_to_sarif(finding, artifact_uri="sample.py")
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == 12
    assert all(
        step["location"]["physicalLocation"]["region"]["startLine"] >= 1 for step in locations
    )


def test_json_and_yaml_share_baseline_candidates_and_order():
    yaml = pytest.importorskip("yaml")
    first = Issue("HIGH", confidence="HIGH", lineno=3, test_id="FIRST", text="First")
    second = Issue("HIGH", confidence="HIGH", lineno=4, test_id="SECOND", text="Second")
    first.fname, second.fname = "a.py", "z.py"
    manager = SimpleNamespace(
        get_issue_list=lambda **_: {second: [second], first: [first, second]},
        get_skipped=lambda: [("bad.py", "unreadable")],
        metrics=SimpleNamespace(data={"_totals": {}}),
    )
    json_output, yaml_output = io.StringIO(), io.StringIO()
    json_formatter.report(manager, json_output, "LOW", "LOW")
    yaml_formatter.report(manager, yaml_output, "LOW", "LOW")
    json_report, yaml_report = json.loads(json_output.getvalue()), yaml.safe_load(
        yaml_output.getvalue()
    )
    assert json_report["results"] == yaml_report["results"]
    assert json_report["errors"] == yaml_report["errors"]
    assert json_report["results"][0]["filename"] == "a.py"
    assert len(json_report["results"][0]["candidates"]) == 2


def test_manager_metrics_are_fresh_for_each_analysis(tmp_path, monkeypatch):
    sample = tmp_path / "sample.py"
    sample.write_text("first\nsecond\n")
    manager = ASTDataflowManager()
    issue = Issue("MEDIUM", confidence="HIGH", lineno=1, text="A finding")
    monkeypatch.setattr(manager.finder, "analyze", lambda _: [issue])
    for _ in range(2):
        manager.analyze([sample])
        assert manager.metrics.files == 1
        assert manager.metrics.lines == 2
        assert manager.metrics.issues == 1
        totals = manager.metrics.data["_totals"]
        assert totals["loc"] == 2
        assert totals["SEVERITY.MEDIUM"] == 1
        assert totals["CONFIDENCE.HIGH"] == 1
