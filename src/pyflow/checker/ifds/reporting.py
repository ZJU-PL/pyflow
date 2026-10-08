"""Normalize IFDS security findings for report consumers."""

from __future__ import annotations

from typing import Any, Dict
from pyflow.checker.common.reporting import code_name, result_status, statistics_to_dict

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


def taint_result_to_dict(entry: str, taint_result) -> Dict[str, Any]:
    """Convert an IFDS TaintAnalysisResult to a JSON-compatible dict."""
    from collections import defaultdict, deque

    problem = getattr(taint_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = defaultdict(deque)
    if enriched:
        for finding in normalized_taint_findings(taint_result):
            normalized[
                (
                    finding.node_id,
                    tuple(finding.properties.get("tainted_arguments", ())),
                )
            ].append(finding)
    findings = []
    for finding in taint_result.findings:
        tainted_arguments = [local.name or "<local>" for local in finding.tainted_arguments]
        if not tainted_arguments:
            tainted_arguments = list(finding.tainted_argument_labels)

        if enriched:
            node_id = adapter.supergraph.node_id(finding.sink)
            normalized_finding = normalized[(node_id, tuple(tainted_arguments))].popleft().to_dict()
        else:
            normalized_finding = {}
        normalized_finding.update(
            {
                "sink_name": finding.sink_name,
                "procedure": code_name(finding.sink.procedure.code),
                "block_kind": finding.sink.kind,
                "tainted_arguments": tainted_arguments,
                "explanations": normalized_finding.get("code_flow", []),
            }
        )
        findings.append(normalized_finding)

    statistics = statistics_to_dict(taint_result.statistics)

    status, termination_reason = result_status(taint_result)
    return {
        "entry": entry,
        "analysis": "taint",
        "findings": findings,
        "diagnostics": [diagnostic for diagnostic in getattr(taint_result, "diagnostics", ())],
        "statistics": statistics,
        "status": status,
        "termination_reason": termination_reason,
    }


def typestate_result_to_dict(entry: str, typestate_result) -> Dict[str, Any]:
    """Convert an IFDS TypestateAnalysisResult to a JSON-compatible dict."""
    from pyflow.analysis.ifds.reporting import normalized_typestate_findings

    problem = getattr(typestate_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = (
        {
            (
                finding.node_id,
                finding.kind,
                finding.properties.get("resource"),
                finding.properties.get("protocol"),
                finding.properties.get("state"),
            ): finding
            for finding in normalized_typestate_findings(typestate_result)
        }
        if enriched
        else {}
    )
    findings = []
    for finding in typestate_result.findings:
        if enriched:
            node_id = adapter.supergraph.node_id(finding.node)
            item = normalized[
                (
                    node_id,
                    finding.kind,
                    finding.resource_label,
                    finding.protocol,
                    finding.state,
                )
            ].to_dict()
        else:
            item = {}
        item.update(
            {
                "kind": finding.kind,
                "operation_name": finding.operation_name,
                "resource_label": finding.resource_label,
                "protocol": finding.protocol,
                "state": finding.state,
                "procedure": code_name(finding.node.procedure.code),
                "block_kind": finding.node.kind,
            }
        )
        findings.append(item)

    statistics = statistics_to_dict(typestate_result.statistics)

    status, termination_reason = result_status(typestate_result)
    return {
        "entry": entry,
        "analysis": "typestate",
        "findings": findings,
        "statistics": statistics,
        "status": status,
        "termination_reason": termination_reason,
    }


def nullness_result_to_dict(entry: str, nullness_result) -> Dict[str, Any]:
    """Convert an IFDS nullness result to a JSON-compatible dictionary."""
    from pyflow.analysis.ifds.reporting import normalized_nullness_findings

    problem = getattr(nullness_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = (
        {
            (
                finding.node_id,
                finding.kind,
                finding.properties.get("expression"),
            ): finding
            for finding in normalized_nullness_findings(nullness_result)
        }
        if enriched
        else {}
    )
    findings = []
    for finding in nullness_result.findings:
        if enriched:
            node_id = adapter.supergraph.node_id(finding.node)
            item = normalized[(node_id, finding.kind, finding.expression_label)].to_dict()
        else:
            item = {}
        item.update(
            {
                "kind": finding.kind,
                "expression_label": finding.expression_label,
                "procedure": code_name(finding.node.procedure.code),
                "block_kind": finding.node.kind,
            }
        )
        findings.append(item)
    status, termination_reason = result_status(nullness_result)
    return {
        "entry": entry,
        "analysis": "nullness",
        "findings": findings,
        "statistics": statistics_to_dict(nullness_result.statistics),
        "status": status,
        "termination_reason": termination_reason,
    }
