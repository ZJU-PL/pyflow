"""Stable source locations and normalized findings for IFDS clients."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Mapping, Sequence

from pyflow.ir.core import SourceOrigin as IRSourceOrigin

from .frontend.cfg_adapter import CFGNode, CFGSupergraphAdapter

@dataclass(frozen=True, order=True)
class SourceSpan:
    """Normalized source position used by JSON and SARIF reporting."""

    uri: str
    start_line: int
    start_column: int = 0
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FlowStep:
    """One stable step in a reported interprocedural code flow."""

    kind: str
    message: str
    node_id: int
    procedure_id: int
    location: SourceSpan | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.location is None:
            data.pop("location", None)
        return data


@dataclass(frozen=True)
class AnalysisFinding:
    """Client-independent, serialization-stable IFDS finding."""

    rule_id: str
    kind: str
    severity: str
    confidence: str
    message: str
    primary_location: SourceSpan | None
    procedure: str
    node_id: int
    code_flow: tuple[FlowStep, ...] = ()
    related_locations: tuple[SourceSpan, ...] = ()
    cwe: str | None = None
    suggestion: str | None = None
    properties: Mapping[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        location = self.primary_location
        location_identity = (
            "|".join(
                (
                    location.uri,
                    str(location.start_line),
                    str(location.start_column),
                    str(location.end_line or ""),
                    str(location.end_column or ""),
                )
            )
            if location
            else f"node:{self.node_id}"
        )
        raw = "|".join(
            (
                self.rule_id,
                self.kind,
                self.procedure,
                location_identity,
                self.message,
            )
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "primary_location": (
                self.primary_location.to_dict() if self.primary_location else None
            ),
            "related_locations": [span.to_dict() for span in self.related_locations],
            "procedure": self.procedure,
            "node_id": self.node_id,
            "code_flow": [step.to_dict() for step in self.code_flow],
            "cwe": self.cwe,
            "suggestion": self.suggestion,
            "fingerprint": self.fingerprint,
            "properties": dict(self.properties),
        }


def source_span_for_node(
    adapter: CFGSupergraphAdapter, node: CFGNode
) -> SourceSpan | None:
    """Resolve the best source span available for a CFG-backed node."""
    candidates = (
        adapter.call_expression_of(node),
        adapter.operation_of(node),
        getattr(node.procedure, "code", None),
    )
    catalog = adapter.catalog_by_procedure.get(node.procedure)
    code = getattr(node.procedure, "code", None)
    if catalog is None or code is None:
        return None
    for candidate in candidates:
        if candidate is None or not catalog.has_node(candidate, code):
            continue
        origin = catalog.source_of(candidate, code=code)
        if isinstance(origin, IRSourceOrigin):
            span = origin.span
            if span.path and span.start_line:
                return SourceSpan(
                    span.path,
                    max(span.start_line, 1),
                    max(span.start_column, 0),
                    span.end_line,
                    span.end_column,
                )
    return None


def flow_steps_for_traces(
    adapter: CFGSupergraphAdapter, traces: Sequence[object]
) -> tuple[FlowStep, ...]:
    steps: list[FlowStep] = []
    seen: set[tuple[int, str]] = set()
    for trace in traces:
        edge = getattr(trace, "output_edge", None)
        node = getattr(edge, "node", None)
        if not isinstance(node, CFGNode):
            continue
        node_id = adapter.supergraph.node_id(node)
        kind = str(getattr(trace, "kind", "flow"))
        key = (node_id, kind)
        if key in seen:
            continue
        seen.add(key)
        procedure_id = adapter.supergraph.procedure_id(node.procedure)
        steps.append(
            FlowStep(
                kind=kind,
                message=str(getattr(trace, "note", None) or kind),
                node_id=node_id,
                procedure_id=procedure_id,
                location=source_span_for_node(adapter, node),
            )
        )
    return tuple(steps)


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


def normalized_nullness_findings(result) -> tuple[AnalysisFinding, ...]:
    adapter = result._problem.adapter
    findings = (
        AnalysisFinding(
            rule_id=f"PYFLOW-NULL-{finding.kind.upper()}",
            kind=finding.kind,
            severity="warning",
            confidence="medium",
            message=f"Potential nullness issue: {finding.expression_label}",
            primary_location=source_span_for_node(adapter, finding.node),
            procedure=_procedure_name(finding.node),
            node_id=adapter.supergraph.node_id(finding.node),
            properties={"expression": finding.expression_label},
        )
        for finding in result.findings
    )
    return tuple(sorted(findings, key=_finding_key))


def normalized_typestate_findings(result) -> tuple[AnalysisFinding, ...]:
    adapter = result._problem.adapter
    findings = (
        AnalysisFinding(
            rule_id=f"PYFLOW-TYPESTATE-{finding.protocol.upper()}-{finding.kind.upper()}",
            kind=finding.kind,
            severity="warning",
            confidence="high",
            message=(
                f"{finding.operation_name}: {finding.kind} for "
                f"{finding.resource_label}"
            ),
            primary_location=source_span_for_node(adapter, finding.node),
            procedure=_procedure_name(finding.node),
            node_id=adapter.supergraph.node_id(finding.node),
            properties={
                "protocol": finding.protocol,
                "state": finding.state,
                "resource": finding.resource_label,
            },
        )
        for finding in result.findings
    )
    return tuple(sorted(findings, key=_finding_key))


def _procedure_name(node: CFGNode) -> str:
    code = getattr(node.procedure, "code", None)
    code_name = getattr(code, "codeName", None)
    if callable(code_name):
        return str(code_name())
    return str(getattr(code, "name", "<procedure>"))


def _finding_key(finding: AnalysisFinding) -> tuple:
    location = finding.primary_location
    return (
        location.uri if location else "",
        location.start_line if location else 0,
        finding.rule_id,
        finding.node_id,
    )
