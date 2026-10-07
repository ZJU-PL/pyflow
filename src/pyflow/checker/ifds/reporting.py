"""Normalize IFDS security findings for report consumers."""

from __future__ import annotations

from pyflow.analysis.ifds.reporting import (
    AnalysisFinding,
    _finding_key,
    _procedure_name,
    flow_steps_for_traces,
    source_span_for_node,
)


def normalized_taint_findings(result) -> tuple[AnalysisFinding, ...]:
    adapter = result._problem.adapter
    findings: list[AnalysisFinding] = []
    for finding in result.findings:
        rule = finding.rule
        labels = (
            tuple(local.name or "<local>" for local in finding.tainted_arguments)
            or finding.tainted_argument_labels
        )
        traces = ()
        if finding.tainted_arguments:
            fact = result.fact_for_local(finding.sink, finding.tainted_arguments[0])
            if fact is not None:
                traces = result.explain_path(finding.sink, fact)
        findings.append(
            AnalysisFinding(
                rule_id=rule.rule_id,
                kind="taint",
                severity=finding.severity,
                confidence="high" if traces else "medium",
                message=(
                    f"{finding.source_kind} data reaches {finding.sink_kind} "
                    f"sink {finding.sink_name} through "
                    f"{', '.join(labels) or '<expression>'}"
                ),
                primary_location=source_span_for_node(adapter, finding.sink),
                procedure=_procedure_name(finding.sink),
                node_id=adapter.supergraph.node_id(finding.sink),
                code_flow=flow_steps_for_traces(adapter, traces),
                cwe=finding.cwe,
                suggestion=finding.suggestion,
                properties={
                    "tainted_arguments": labels,
                    "source_kind": finding.source_kind,
                    "sink_kind": finding.sink_kind,
                },
            )
        )
    return tuple(sorted(findings, key=_finding_key))
