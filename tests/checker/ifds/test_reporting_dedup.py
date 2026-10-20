"""Report identity is based on source locations rather than context node IDs."""

from types import SimpleNamespace

from pyflow.analysis.ifds.reporting import AnalysisFinding, FlowStep, SourceSpan
from pyflow.checker.ifds.reporting import taint_result_to_dict


def test_taint_reporting_deduplicates_contexts_but_preserves_distinct_sources(monkeypatch):
    from pyflow.checker.ifds import reporting

    normalized = []
    raw = []
    code = SimpleNamespace(codeName=lambda: "run")
    for node_id, source_line in enumerate([2, 2, 3]):
        sink = SimpleNamespace(node_id=node_id, kind="call", procedure=SimpleNamespace(code=code))
        raw.append(
            SimpleNamespace(
                sink=sink,
                sink_name="eval",
                source_kind="user_input",
                sink_kind="rce",
                tainted_arguments=(),
                tainted_argument_labels=("value",),
            )
        )
        normalized.append(
            AnalysisFinding(
                rule_id="TEST",
                kind="taint",
                severity="high",
                confidence="high",
                message="flow",
                primary_location=SourceSpan("sample.py", 10, 0),
                procedure="run",
                node_id=node_id,
                code_flow=(
                    FlowStep(
                        "source", "input", node_id, 0, SourceSpan("sample.py", source_line, 0)
                    ),
                ),
                properties={"tainted_arguments": ("value",)},
            )
        )
    monkeypatch.setattr(reporting, "normalized_taint_findings", lambda _: normalized)
    result = SimpleNamespace(
        findings=raw,
        statistics={},
        status="complete",
        termination_reason=None,
        _problem=SimpleNamespace(
            adapter=SimpleNamespace(supergraph=SimpleNamespace(node_id=lambda node: node.node_id))
        ),
    )
    report = taint_result_to_dict("sample.py", result)
    assert len(report["findings"]) == 2
    assert [f["code_flow"][0]["location"]["start_line"] for f in report["findings"]] == [2, 3]
