"""Stable source locations and normalized findings for IFDS clients."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Mapping, Sequence

from pyflow.ir.core import SourceOrigin as IRSourceOrigin
from pyflow.util.cwe import cwe_ancestors, cwe_identifiers

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
    procedure: str = ""
    nesting_level: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.location is None:
            data.pop("location", None)
        if not self.procedure:
            data.pop("procedure", None)
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
        cwes = cwe_identifiers(self.cwe)
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
            "cwes": list(cwes),
            "cwe_ancestors": list(cwe_ancestors(self.cwe)),
            "suggestion": self.suggestion,
            "fingerprint": self.fingerprint,
            "properties": dict(self.properties),
        }


def source_span_for_node(adapter: CFGSupergraphAdapter, node: CFGNode) -> SourceSpan | None:
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


def _humanize_flow_step(
    adapter: CFGSupergraphAdapter,
    node: CFGNode,
    kind: str,
    fact: object,
    raw_note: object,
    describe_fact,
) -> str:
    proc = _procedure_name(node)
    fact_label = ""
    if callable(describe_fact) and fact is not None:
        if not (isinstance(fact, str) and fact.startswith("ZERO_")):
            try:
                described = str(describe_fact(fact) or "").strip()
            except Exception:
                described = ""
            if described and described not in {"<expr>", "<unknown>", "ZERO"}:
                fact_label = described
    call_name = None
    try:
        effect = adapter.effect_of(node)
        call_name = getattr(effect, "call_name", None)
    except Exception:
        call_name = None

    if kind == "seed":
        if fact_label:
            return f"Originates in {proc} ({fact_label})"
        return f"Analysis entry in {proc}"
    if kind == "call_flow":
        if fact_label:
            return f"Enters {proc} carrying {fact_label}"
        return f"Enters {proc}"
    if kind in {"return_flow", "return_flow(summary_replay)"}:
        if fact_label:
            return f"Returns to {proc} carrying {fact_label}"
        return f"Returns to {proc}"
    if kind == "call_to_return":
        if call_name and fact_label:
            return f"Call {call_name} in {proc} propagates {fact_label}"
        if call_name:
            return f"Call {call_name} in {proc}"
        if fact_label:
            return f"Propagates {fact_label} across call in {proc}"
        return f"Propagates across call in {proc}"
    if kind == "normal_flow":
        if call_name and fact_label:
            return f"Evaluates {call_name} in {proc} ({fact_label})"
        if fact_label:
            return f"Flows via {fact_label} in {proc}"
        return f"Flows through {proc}"
    if raw_note and not str(raw_note).startswith(("CFGNode(", "<pyflow.")):
        return str(raw_note)
    return f"{kind} in {proc}"


def flow_steps_for_traces(
    adapter: CFGSupergraphAdapter,
    traces: Sequence[object],
    *,
    describe_fact=None,
) -> tuple[FlowStep, ...]:
    steps: list[FlowStep] = []
    seen_node_kind: set[tuple[int, str]] = set()
    last_semantic_key: tuple[Any, ...] | None = None
    nesting_level = 0
    total = len(traces)

    for index, trace in enumerate(traces):
        edge = getattr(trace, "output_edge", None)
        node = getattr(edge, "node", None)
        if not isinstance(node, CFGNode):
            continue
        node_id = adapter.supergraph.node_id(node)
        kind = str(getattr(trace, "kind", "flow"))
        if kind == "call_flow":
            nesting_level += 1
        elif kind in {"return_flow", "return_flow(summary_replay)"}:
            nesting_level = max(0, nesting_level - 1)

        node_key = (node_id, kind)
        if node_key in seen_node_kind:
            continue
        seen_node_kind.add(node_key)

        location = source_span_for_node(adapter, node)
        proc_name = _procedure_name(node)
        fact = getattr(edge, "fact", None)
        message = _humanize_flow_step(
            adapter,
            node,
            kind,
            fact,
            getattr(trace, "note", None),
            describe_fact,
        )
        # Collapse consecutive lowered-IR steps on the exact same source line
        # and message, while always keeping entry, interprocedural transitions,
        # and the terminal step.
        is_boundary = (
            index == 0
            or index == total - 1
            or kind in {"seed", "call_flow", "return_flow", "return_flow(summary_replay)"}
        )
        semantic_key = (
            location.uri if location else None,
            location.start_line if location else None,
            proc_name,
            message,
        )
        if location is not None and not is_boundary and semantic_key == last_semantic_key:
            continue
        last_semantic_key = semantic_key

        procedure_id = adapter.supergraph.procedure_id(node.procedure)
        steps.append(
            FlowStep(
                kind=kind,
                message=message,
                node_id=node_id,
                procedure_id=procedure_id,
                location=location,
                procedure=proc_name,
                nesting_level=nesting_level,
            )
        )
    return tuple(steps)


_NULLNESS_ACTION_TEXT: dict[str, str] = {
    "attribute_access": "accessing an attribute on it",
    "method_receiver": "calling a method on it",
    "call_target": "calling it as a function",
    "subscript_access": "indexing into it",
    "mutation_target": "mutating an attribute or element on it",
}

_TYPESTATE_METADATA: dict[str, tuple[str, str]] = {
    "use_after_close": (
        "CWE-672",
        "Avoid using a resource after it has been closed; keep all uses inside the open lifetime or a 'with' block.",
    ),
    "double_close": (
        "CWE-675",
        "Ensure the resource is closed once (e.g., guard close() or manage the resource with a 'with' statement).",
    ),
    "resource_leak": (
        "CWE-404",
        "Close the resource on all exit paths (including exceptions), preferably using a 'with' statement.",
    ),
    "lock_leak": (
        "CWE-667",
        "Release the lock in a finally block or manage it with a 'with' context manager.",
    ),
    "transaction_leak": (
        "CWE-404",
        "Commit or roll back the transaction on all exit paths, preferably via a context manager.",
    ),
}


def normalized_nullness_findings(result) -> tuple[AnalysisFinding, ...]:
    adapter = result._problem.adapter
    describe_fact = getattr(result._problem, "describe_fact", None)
    findings: list[AnalysisFinding] = []
    for finding in result.findings:
        traces = ()
        if getattr(finding, "fact", None) is not None and hasattr(result, "explain_path"):
            traces = result.explain_path(finding.node, finding.fact)
        action = _NULLNESS_ACTION_TEXT.get(finding.kind)
        if action:
            message = (
                f"Potential nullness issue: {finding.expression_label} may be None before {action}"
            )
        else:
            message = f"Potential nullness issue: {finding.expression_label}"
        findings.append(
            AnalysisFinding(
                rule_id=f"PYFLOW-NULL-{finding.kind.upper()}",
                kind=finding.kind,
                severity="warning",
                confidence="high" if traces else "medium",
                message=message,
                primary_location=source_span_for_node(adapter, finding.node),
                procedure=_procedure_name(finding.node),
                node_id=adapter.supergraph.node_id(finding.node),
                code_flow=flow_steps_for_traces(adapter, traces, describe_fact=describe_fact),
                cwe="CWE-476",
                suggestion=(
                    f"Guard '{finding.expression_label}' with 'if {finding.expression_label} is not None:' "
                    "or provide a non-None default before use."
                ),
                properties={"expression": finding.expression_label},
            )
        )
    return _fold_equivalent_findings(sorted(findings, key=_finding_key))


def normalized_typestate_findings(result) -> tuple[AnalysisFinding, ...]:
    adapter = result._problem.adapter
    describe_fact = getattr(result._problem, "describe_fact", None)
    findings: list[AnalysisFinding] = []
    for finding in result.findings:
        traces = ()
        if getattr(finding, "fact", None) is not None and hasattr(result, "explain_path"):
            traces = result.explain_path(finding.node, finding.fact)
        cwe, suggestion = _TYPESTATE_METADATA.get(
            finding.kind,
            (
                "CWE-404" if "leak" in finding.kind else "CWE-672",
                "Ensure resource lifecycle transitions (acquire/use/release) are properly paired.",
            ),
        )
        findings.append(
            AnalysisFinding(
                rule_id=(f"PYFLOW-TYPESTATE-{finding.protocol.upper()}-" f"{finding.kind.upper()}"),
                kind=finding.kind,
                severity="warning",
                confidence="high",
                message=(
                    f"{finding.operation_name}: {finding.kind} for " f"{finding.resource_label}"
                ),
                primary_location=source_span_for_node(adapter, finding.node),
                procedure=_procedure_name(finding.node),
                node_id=adapter.supergraph.node_id(finding.node),
                code_flow=flow_steps_for_traces(adapter, traces, describe_fact=describe_fact),
                cwe=cwe,
                suggestion=suggestion,
                properties={
                    "protocol": finding.protocol,
                    "state": finding.state,
                    "resource": finding.resource_label,
                },
            )
        )
    return _fold_equivalent_findings(sorted(findings, key=_finding_key))


def _fold_equivalent_findings(findings: Sequence[AnalysisFinding]) -> tuple[AnalysisFinding, ...]:
    """Collapse findings that describe the same user-visible issue.

    One source statement can lower to several supergraph nodes, and one
    statement can exercise one nullable variable through several source
    expressions. Clients render one issue per (rule, location, message), so
    findings sharing that identity fold into their first entry. Findings
    without a resolved location keep a node-based identity and never fold.
    """
    folded: list[AnalysisFinding] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        location = finding.primary_location
        if location is None:
            folded.append(finding)
            continue
        key = (
            finding.rule_id,
            location.uri,
            finding.procedure,
            location.start_line,
            finding.message,
            tuple(sorted(finding.properties.items())),
        )
        if key in seen:
            continue
        seen.add(key)
        folded.append(finding)
    return tuple(folded)


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
