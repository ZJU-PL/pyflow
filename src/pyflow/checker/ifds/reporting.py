"""Normalize IFDS security findings for report consumers."""

from __future__ import annotations

from pyflow.frontend.source import read_python_source

from typing import Any, Dict
import json
import ast
from functools import lru_cache
from pathlib import Path
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
                procedure=_source_procedure(adapter, finding.sink),
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


@lru_cache(maxsize=256)
def _source_scopes(path: str, modified: int):
    tree = ast.parse(read_python_source(path))
    scopes = []

    def visit(node, parents=()):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            parents = (*parents, node.name)
            if not isinstance(node, ast.ClassDef):
                scopes.append((node.lineno, node.end_lineno, ".".join(parents)))
        for child in ast.iter_child_nodes(node):
            visit(child, parents)

    visit(tree)
    return scopes


def _source_procedure(adapter, node):
    """Use the source owner after helper bodies have been inlined into a module."""
    name = _procedure_name(node)
    span = source_span_for_node(adapter, node)
    if span is None:
        return name
    try:
        candidates = [
            (end - start, qualified)
            for start, end, qualified in _source_scopes(span.uri, Path(span.uri).stat().st_mtime_ns)
            if start <= span.start_line <= end
        ]
    except (OSError, ValueError, SyntaxError, UnicodeError):
        return name
    return min(candidates)[1] if candidates else name


def taint_finding_key(finding):
    """Identify a reported flow independently of analysis context/node numbering."""
    location = finding.get("primary_location")
    if not location:
        return json.dumps(finding, sort_keys=True)
    flow = finding.get("code_flow", ())
    sources = [step.get("location") for step in flow if step.get("kind") in {"source", "seed"}]
    if not sources and flow:
        sources = [flow[0].get("location")]
    properties = finding.get("properties", {})
    return json.dumps(
        [
            finding.get("rule_id"),
            location,
            finding.get("sink_name"),
            properties.get("source_kind"),
            properties.get("sink_kind"),
            sources,
        ],
        sort_keys=True,
    )


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
    seen = set()
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
                "rule_title": getattr(getattr(finding, "rule", None), "title", ""),
                "function": normalized_finding.get("procedure")
                or code_name(finding.sink.procedure.code),
                "procedure": normalized_finding.get("procedure")
                or code_name(finding.sink.procedure.code),
                "block_kind": finding.sink.kind,
                "tainted_arguments": tainted_arguments,
                "explanations": normalized_finding.get("code_flow", []),
            }
        )
        location = normalized_finding.get("primary_location")
        flow = normalized_finding.get("code_flow", ())
        sources = [step.get("location") for step in flow if step.get("kind") in {"source", "seed"}]
        if not sources and flow:
            sources = [flow[0].get("location")]
        identity = json.dumps(
            [
                normalized_finding.get("rule_id")
                or getattr(getattr(finding, "rule", None), "rule_id", None),
                location or id(finding.sink),
                finding.sink_name,
                getattr(finding, "source_kind", None),
                getattr(finding, "sink_kind", None),
                sources,
            ],
            sort_keys=True,
        )
        if identity not in seen:
            seen.add(identity)
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
    findings = []
    if enriched:
        # Normalized findings are folded per source location, so iterate the
        # folded entries and enrich each from its originating raw finding.
        raw_by_identity = {
            (
                adapter.supergraph.node_id(finding.node),
                finding.kind,
                finding.resource_label,
                finding.protocol,
                finding.state,
            ): finding
            for finding in typestate_result.findings
        }
        for normalized_finding in normalized_typestate_findings(typestate_result):
            raw = raw_by_identity[
                (
                    normalized_finding.node_id,
                    normalized_finding.kind,
                    normalized_finding.properties.get("resource"),
                    normalized_finding.properties.get("protocol"),
                    normalized_finding.properties.get("state"),
                )
            ]
            item = normalized_finding.to_dict()
            item.update(
                {
                    "kind": raw.kind,
                    "operation_name": raw.operation_name,
                    "resource_label": raw.resource_label,
                    "protocol": raw.protocol,
                    "state": raw.state,
                    "procedure": code_name(raw.node.procedure.code),
                    "block_kind": raw.node.kind,
                }
            )
            findings.append(item)
    else:
        for finding in typestate_result.findings:
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
    findings = []
    if enriched:
        # Normalized findings are folded per source location, so iterate the
        # folded entries and enrich each from its originating raw finding.
        raw_by_identity = {
            (
                adapter.supergraph.node_id(finding.node),
                finding.kind,
                finding.expression_label,
            ): finding
            for finding in nullness_result.findings
        }
        for normalized_finding in normalized_nullness_findings(nullness_result):
            raw = raw_by_identity[
                (
                    normalized_finding.node_id,
                    normalized_finding.kind,
                    normalized_finding.properties.get("expression"),
                )
            ]
            item = normalized_finding.to_dict()
            item.update(
                {
                    "kind": raw.kind,
                    "expression_label": raw.expression_label,
                    "procedure": code_name(raw.node.procedure.code),
                    "block_kind": raw.node.kind,
                }
            )
            findings.append(item)
    else:
        for finding in nullness_result.findings:
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
