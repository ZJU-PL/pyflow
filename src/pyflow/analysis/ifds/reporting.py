"""Stable source locations and normalized findings for IFDS clients."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from functools import lru_cache
import hashlib
from pathlib import Path
import re
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


def _is_zero_fact(fact: object) -> bool:
    if fact is None:
        return True
    if isinstance(fact, str) and (fact == "ZERO" or fact.startswith("ZERO_")):
        return True
    if getattr(fact, "is_zero", False):
        return True
    return type(fact).__name__.startswith("Zero")


def _is_internal_intrinsic(name: str | None) -> bool:
    if not name:
        return False
    base = name.rstrip("()")
    return base.startswith("interpreter_") or base in {"<expr>", "<unknown>", "ZERO"}


_INTERNAL_SYMBOL_RE = re.compile(r"(?:@/|/scope\d+/s\d+|<locals>\.)")
_INTERNAL_RET_RE = re.compile(r"^ret\d+$")


@lru_cache(maxsize=256)
def _cached_source_lines(path_str: str, mtime_ns: int) -> tuple[str, ...]:
    del mtime_ns
    try:
        return tuple(Path(path_str).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def _is_def_header_line(location: SourceSpan | None) -> bool:
    if location is None or not location.uri or location.start_line <= 0:
        return False
    try:
        path = Path(location.uri)
        if not path.is_file():
            return False
        lines = _cached_source_lines(str(path.resolve()), path.stat().st_mtime_ns)
        if 1 <= location.start_line <= len(lines):
            stripped = lines[location.start_line - 1].lstrip()
            return stripped.startswith(("def ", "async def ", "class "))
    except OSError:
        return False
    return False


def _clean_fact_label(described: str) -> str:
    text = described.strip()
    if not text or text in {"<expr>", "<unknown>", "ZERO"}:
        return ""
    if _is_internal_intrinsic(text):
        if "format" in text or "join_str" in text:
            return "formatted string"
        return ""
    if _INTERNAL_SYMBOL_RE.search(text):
        return ""
    if _INTERNAL_RET_RE.match(text):
        return "return value"
    return text


def _humanize_flow_step(
    adapter: CFGSupergraphAdapter,
    node: CFGNode,
    kind: str,
    fact: object,
    raw_note: object,
    describe_fact,
    *,
    is_origin: bool = False,
    is_sink: bool = False,
) -> tuple[str, str, str | None]:
    """Return ``(message, fact_label, call_name)`` for a single IFDS trace step."""
    proc = _procedure_name(node)
    fact_label = ""
    if callable(describe_fact) and not _is_zero_fact(fact):
        try:
            described = str(describe_fact(fact) or "")
        except Exception:
            described = ""
        fact_label = _clean_fact_label(described)

    raw_call_name = None
    try:
        effect = adapter.effect_of(node)
        raw_call_name = getattr(effect, "call_name", None)
    except Exception:
        raw_call_name = None
    call_name = None if _is_internal_intrinsic(raw_call_name) else raw_call_name

    if is_sink:
        if call_name and fact_label:
            return f"Reaches sink {call_name} in {proc} ({fact_label})", fact_label, call_name
        if call_name:
            return f"Reaches sink {call_name} in {proc}", fact_label, call_name
        if fact_label:
            return f"Reaches sink in {proc} ({fact_label})", fact_label, call_name
        return f"Reaches sink in {proc}", fact_label, call_name

    if is_origin or kind in {"seed", "source"}:
        if call_name and fact_label and fact_label != f"{call_name}()":
            return f"Originates from {call_name} in {proc} ({fact_label})", fact_label, call_name
        if fact_label:
            return f"Originates from {fact_label} in {proc}", fact_label, call_name
        if call_name:
            return f"Originates from {call_name} in {proc}", fact_label, call_name
        return f"Analysis entry in {proc}", fact_label, call_name
    if kind == "call_flow":
        if fact_label:
            return f"Enters {proc} carrying {fact_label}", fact_label, call_name
        return f"Enters {proc}", fact_label, call_name
    if kind in {"return_flow", "return_flow(summary_replay)"}:
        if fact_label:
            return f"Returns to {proc} carrying {fact_label}", fact_label, call_name
        return f"Returns to {proc}", fact_label, call_name
    if kind == "call_to_return":
        if call_name and fact_label:
            return f"Call {call_name} in {proc} propagates {fact_label}", fact_label, call_name
        if call_name:
            return f"Call {call_name} in {proc}", fact_label, call_name
        if fact_label:
            return f"Propagates {fact_label} across call in {proc}", fact_label, call_name
        return f"Propagates across call in {proc}", fact_label, call_name
    if kind == "normal_flow":
        if call_name and fact_label:
            return f"Calls {call_name} in {proc} ({fact_label})", fact_label, call_name
        if raw_call_name and ("format" in raw_call_name or "join_str" in raw_call_name):
            if fact_label and fact_label != "formatted string":
                return f"Formats string into {fact_label} in {proc}", fact_label, call_name
            return f"Formats tainted string in {proc}", fact_label, call_name
        if fact_label:
            return f"Flows via {fact_label} in {proc}", fact_label, call_name
        return f"Flows through {proc}", fact_label, call_name
    if raw_note and not str(raw_note).startswith(("CFGNode(", "<pyflow.")):
        return str(raw_note), fact_label, call_name
    return f"{kind} in {proc}", fact_label, call_name


def flow_steps_for_traces(
    adapter: CFGSupergraphAdapter,
    traces: Sequence[object],
    *,
    describe_fact=None,
    terminal_kind: str | None = None,
) -> tuple[FlowStep, ...]:
    # Extract valid trace entries with their real call-stack nesting depth.
    entries: list[tuple[CFGNode, str, object, object, int]] = []
    raw_depth = 0
    for trace in traces:
        edge = getattr(trace, "output_edge", None)
        node = getattr(edge, "node", None)
        if not isinstance(node, CFGNode):
            continue
        kind = str(getattr(trace, "kind", "flow"))
        if kind == "call_flow":
            raw_depth += 1
        elif kind in {"return_flow", "return_flow(summary_replay)"}:
            raw_depth = max(0, raw_depth - 1)
        entries.append(
            (node, kind, getattr(edge, "fact", None), getattr(trace, "note", None), raw_depth)
        )

    if not entries:
        return ()

    # Trim leading module/bootstrap ZERO-fact steps so the witness starts where
    # the tracked taint/nullness/resource fact is actually introduced.
    first_real_idx = next(
        (idx for idx, item in enumerate(entries) if not _is_zero_fact(item[2])),
        0,
    )
    trimmed = entries[first_real_idx:]
    min_depth = min(item[4] for item in trimmed)

    steps: list[FlowStep] = []
    seen_node_kind: set[tuple[int, str]] = set()
    prev_fact: object = object()
    prev_proc: str | None = None
    prev_line_key: tuple[str, int, str] | None = None
    total = len(trimmed)

    for index, (node, kind, fact, raw_note, depth) in enumerate(trimmed):
        is_first = index == 0
        is_last = index == total - 1
        is_interproc = kind in {"call_flow", "return_flow", "return_flow(summary_replay)"}
        is_boundary = is_first or is_last or is_interproc

        node_id = adapter.supergraph.node_id(node)
        node_key = (node_id, kind)
        if not is_boundary and node_key in seen_node_kind:
            continue
        seen_node_kind.add(node_key)

        proc_name = _procedure_name(node)

        # Drop same-procedure IFDS identity pass-through edges that neither
        # transform the tracked fact nor mark a call/return/source/sink boundary.
        if (
            not is_boundary
            and proc_name == prev_proc
            and fact == prev_fact
            and kind in {"normal_flow", "call_to_return"}
        ):
            continue

        location = source_span_for_node(adapter, node)
        # Skip lowered-IR fallback steps whose source span points back to a
        # function 'def' header (e.g. return-slot transfers), except at real
        # call entry/origin/sink boundaries.
        if not is_boundary and _is_def_header_line(location):
            prev_fact = fact
            prev_proc = proc_name
            continue

        effective_kind = kind
        if is_first and kind in {"normal_flow", "seed"}:
            effective_kind = "source"
        elif is_last and terminal_kind:
            effective_kind = terminal_kind

        message, fact_label, call_name = _humanize_flow_step(
            adapter,
            node,
            effective_kind,
            fact,
            raw_note,
            describe_fact,
            is_origin=is_first,
            is_sink=is_last and terminal_kind == "sink",
        )

        # Skip pure internal compiler intrinsic noise on intermediate steps
        # when the previous step already covered the exact same source line.
        line_key = (location.uri, location.start_line, proc_name) if location is not None else None
        nesting_level = max(0, depth - min_depth)
        procedure_id = adapter.supergraph.procedure_id(node.procedure)
        step = FlowStep(
            kind=effective_kind,
            message=message,
            node_id=node_id,
            procedure_id=procedure_id,
            location=location,
            procedure=proc_name,
            nesting_level=nesting_level,
        )

        if (
            line_key is not None
            and line_key == prev_line_key
            and steps
            and not is_interproc
            and not is_first
        ):
            # Same source line in the same procedure: replace if the new step
            # is the terminal sink or strictly more informative (e.g. carries a
            # concrete call or transformed variable rather than generic flow).
            prev_step = steps[-1]
            if is_last and terminal_kind:
                if prev_step.kind in {"source", "seed"}:
                    steps.append(step)
                else:
                    steps[-1] = step
            elif prev_step.kind not in {"source", "seed", "call_flow", "return_flow"} and (
                call_name or (fact_label and fact_label not in prev_step.message)
            ):
                steps[-1] = step
            prev_fact = fact
            prev_proc = proc_name
            continue

        steps.append(step)
        prev_fact = fact
        prev_proc = proc_name
        prev_line_key = line_key

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
