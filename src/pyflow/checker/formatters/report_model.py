"""Canonical engine-independent security report model and adapters.

All four security engines (``ast-scanner``, ``ast-dataflow``, ``ifds``, ``cpg``)
normalize into :class:`SecurityReport` once. Filtering, folding, baselining, and
all output renderers (text, screen, markdown, HTML, SARIF, JSON, CSV, XML, YAML,
custom templates) consume this single model.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import lru_cache
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from pyflow.checker.common import constants as b_constants
from pyflow.checker.common.diagnostics import affects_completeness, diagnostics_to_dicts
from pyflow.util.cwe import (
    cwe_ancestors,
    cwe_identifiers,
    cwe_url,
    default_cwe_for_rule_id,
    default_cwe_suggestion,
    normalize_cwe,
)

SCHEMA_VERSION = 2

PRECISION_DIAGNOSTIC_CODES = frozenset(
    {
        "unknown-call-effect",
        "cpg-unknown-call-effect",
        "ambiguous-call-target",
        "exception-prefix-overapproximation",
        "context-manager-exit-effects",
        "finally-abrupt-outcome-overapproximation",
        "cpg-expression-call-summary",
        "cpg-loop-convergence-threshold",
        "cpg-module-initializer-call-effects",
        "container-clear-alias-unknown",
    }
)

SEVERITY_ALIASES: dict[str, str] = {
    "warning": "medium",
    "error": "high",
    "note": "low",
    "informational": "info",
}


@lru_cache(maxsize=256)
def _read_source_lines_cached(path_str: str, mtime_ns: int) -> tuple[str, ...]:
    del mtime_ns
    try:
        return tuple(Path(path_str).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def read_source_lines(uri: str) -> tuple[str, ...]:
    """Return cached lines of *uri*, or an empty tuple if unreadable/virtual."""
    if not uri or uri.startswith("<") or "://" in uri:
        return ()
    try:
        path = Path(uri)
        if not path.is_file():
            return ()
        stat = path.stat()
        return _read_source_lines_cached(str(path.resolve()), stat.st_mtime_ns)
    except OSError:
        return ()


def read_source_line(uri: str, line: int) -> str:
    """Return the trimmed single source line at 1-based *line* in *uri*, or ``""``."""
    if line <= 0:
        return ""
    lines = read_source_lines(uri)
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def resolve_uri(uri: str) -> str:
    """Resolve real filesystem paths to canonical absolute strings."""
    if not uri or uri.startswith("<") or "://" in uri:
        return uri
    try:
        return str(Path(uri).resolve())
    except OSError:
        return uri


def normalize_severity(value: Any, *, default: str = "medium") -> str:
    raw = str(value or default).strip().lower()
    return SEVERITY_ALIASES.get(raw, raw) or default


def normalize_confidence(value: Any, *, default: str = "medium") -> tuple[str, float | None]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        score = round(float(value), 2)
        level = "high" if score >= 0.85 else "medium" if score >= 0.6 else "low"
        return level, score
    text = str(value or "").strip().lower()
    if text in {"high", "medium", "low", "undefined"}:
        return text, None
    return default, None


def step_importance(kind: str | None) -> str:
    """Map a flow step kind to SARIF 2.1.0 ``threadFlowLocation.importance``."""
    key = (kind or "").strip().lower()
    if key in {"source", "seed", "sink", "call_flow"}:
        return "essential"
    if key in {
        "call",
        "assign",
        "return_flow",
        "return_flow(summary_replay)",
        "call_to_return",
    }:
        return "important"
    return "unimportant"


def compute_fingerprint(*parts: object) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class FlowStep:
    """Single witness step in a security finding's dataflow path."""

    kind: str
    message: str
    uri: str = ""
    line: int = 0
    column: int | None = None
    procedure: str = ""
    nesting_level: int = 0
    importance: str = ""
    debug: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.importance:
            object.__setattr__(self, "importance", step_importance(self.kind))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "importance": self.importance,
            "message": self.message,
            "filename": resolve_uri(self.uri) if self.uri else "",
            "line": self.line,
            "nesting_level": self.nesting_level,
        }
        if self.column is not None:
            payload["column"] = self.column
        if self.procedure:
            payload["procedure"] = self.procedure
        snippet = read_source_line(self.uri, self.line)
        if snippet:
            payload["code_snippet"] = snippet
        if self.debug:
            payload["debug"] = dict(self.debug)
        return payload


@dataclass(frozen=True)
class SecurityFinding:
    """Canonical finding shared by all PyFlow security engines and formatters."""

    rule_id: str
    rule_title: str
    message: str
    severity: str
    confidence: str
    uri: str = ""
    line: int = 0
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    procedure: str = ""
    cwe: str | None = None
    suggestion: str = ""
    sink_name: str = ""
    source_kinds: tuple[str, ...] = ()
    tainted_arguments: tuple[str, ...] = ()
    precision_reasons: tuple[str, ...] = ()
    related_rules: tuple[str, ...] = ()
    vulnerability_family: str | None = None
    source_label: str = ""
    source_uri: str = ""
    source_line: int = 0
    sink_label: str = ""
    sink_uri: str = ""
    sink_line: int = 0
    confidence_score: float | None = None
    fingerprint: str = ""
    steps: tuple[FlowStep, ...] = ()
    tags: tuple[str, ...] = ()
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        eff_cwe = normalize_cwe(self.cwe) or default_cwe_for_rule_id(self.rule_id)
        object.__setattr__(self, "cwe", eff_cwe)
        if not self.suggestion and eff_cwe:
            object.__setattr__(self, "suggestion", default_cwe_suggestion(eff_cwe))
        if not self.fingerprint:
            fp = compute_fingerprint(
                self.rule_id,
                resolve_uri(self.uri) if self.uri else "",
                self.line,
                self.sink_name or self.sink_label,
                self.source_label or ",".join(self.source_kinds),
                self.message,
            )
            object.__setattr__(self, "fingerprint", fp)

    @property
    def cwe_url(self) -> str:
        return cwe_url(self.cwe)

    @property
    def cwes(self) -> tuple[str, ...]:
        return cwe_identifiers(self.cwe)

    @property
    def cwe_ancestors(self) -> tuple[str, ...]:
        return cwe_ancestors(self.cwe)

    @property
    def code_snippet(self) -> str:
        return read_source_line(self.uri, self.line)

    def debug_dict(self) -> dict[str, Any]:
        """Return engine-specific and debug-oriented metadata (hidden in default views)."""
        debug: dict[str, Any] = {}
        if self.confidence_score is not None:
            debug["confidence_score"] = self.confidence_score
        if self.cwe_ancestors:
            debug["cwe_ancestors"] = list(self.cwe_ancestors)
        if self.source_kinds:
            debug["source_kinds"] = list(self.source_kinds)
        if self.tainted_arguments:
            debug["tainted_arguments"] = list(self.tainted_arguments)
        if self.related_rules:
            debug["related_rules"] = list(self.related_rules)
        if self.precision_reasons:
            debug["precision_reasons"] = list(self.precision_reasons)
        if self.vulnerability_family:
            debug["vulnerability_family"] = self.vulnerability_family
        if self.tags:
            debug["tags"] = list(self.tags)
        if self.extra:
            debug.update(self.extra)
        return debug

    def to_dict(self) -> dict[str, Any]:
        resolved_uri = resolve_uri(self.uri) if self.uri else ""
        location: dict[str, Any] = {"filename": resolved_uri, "line": self.line}
        if self.column is not None:
            location["column"] = self.column
        if self.end_line is not None and self.end_line > 0:
            location["end_line"] = self.end_line
        if self.end_column is not None:
            location["end_column"] = self.end_column

        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "procedure": self.procedure,
            "location": location,
            "code_snippet": self.code_snippet,
            "cwe": self.cwe,
            "cwe_url": self.cwe_url or None,
            "cwes": list(self.cwes),
            "suggestion": self.suggestion,
            "sink_name": self.sink_name,
            "fingerprint": self.fingerprint,
            "code_flow": [step.to_dict() for step in self.steps],
        }
        if self.source_label or self.source_line > 0:
            payload["source"] = {
                "label": self.source_label,
                "filename": resolve_uri(self.source_uri) if self.source_uri else "",
                "line": self.source_line,
            }
        if self.sink_label or self.sink_line > 0:
            payload["sink"] = {
                "label": self.sink_label,
                "filename": resolve_uri(self.sink_uri) if self.sink_uri else "",
                "line": self.sink_line,
            }
        debug = self.debug_dict()
        if debug:
            payload["debug"] = debug
        return payload


@dataclass(frozen=True)
class SecurityReport:
    """Canonical envelope emitted by all security engines."""

    engine: str
    status: str = "complete"
    entry: str = ""
    termination_reason: str = ""
    findings: tuple[SecurityFinding, ...] = ()
    diagnostics: tuple[dict[str, Any], ...] = ()
    statistics: Mapping[str, Any] = field(default_factory=dict)
    debug: Mapping[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> tuple[dict[str, Any], ...]:
        return tuple(diag for diag in self.diagnostics if affects_completeness(diag))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "engine": self.engine,
            "status": self.status,
            "entry": self.entry,
            "termination_reason": self.termination_reason or None,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [dict(err) for err in self.errors],
            "diagnostics": [dict(diag) for diag in self.diagnostics],
            "statistics": dict(self.statistics),
        }
        if self.debug:
            payload["debug"] = dict(self.debug)
        return payload


# ── Engine Adapters ───────────────────────────────────────────────────────


def _normalize_diagnostics(
    raw_diagnostics: Sequence[Any], *, engine: str, default_incomplete: bool = False
) -> tuple[dict[str, Any], ...]:
    out: list[dict[str, Any]] = []
    for item in diagnostics_to_dicts(raw_diagnostics):
        if isinstance(item, dict):
            diag = dict(item)
            diag.setdefault("code", f"{engine}-diagnostic")
            diag.setdefault("message", diag.get("reason") or "")
            diag.setdefault("affects_completeness", default_incomplete)
            out.append(diag)
        else:
            out.append(
                {
                    "code": f"{engine}-diagnostic",
                    "message": str(item),
                    "affects_completeness": default_incomplete,
                }
            )
    return tuple(out)


def _extract_related_ids(raw_related: Any, primary_id: str) -> tuple[str, ...]:
    seen: list[str] = []
    for item in raw_related or ():
        rid = item.get("rule_id") if isinstance(item, Mapping) else str(item or "")
        if rid and rid != primary_id and rid not in seen:
            seen.append(str(rid))
    return tuple(seen)


def _from_ast_scanner(result: Any) -> SecurityReport:
    if isinstance(result, Mapping):
        raw_findings = result.get("findings") or result.get("results") or ()
        diagnostics = _normalize_diagnostics(
            result.get("diagnostics") or result.get("errors") or (),
            engine="ast-scanner",
            default_incomplete=True,
        )
        status = str(result.get("status") or ("partial" if diagnostics else "complete"))
        findings = tuple(_finding_from_scanner_dict(item) for item in raw_findings)
        return SecurityReport(
            engine="ast-scanner",
            status=status,
            entry=str(result.get("entry") or ""),
            termination_reason=str(result.get("termination_reason") or ""),
            findings=findings,
            diagnostics=diagnostics,
            statistics=dict(result.get("statistics") or {}),
        )

    issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
    raw_errors = (
        list(result.get_errors())
        if hasattr(result, "get_errors")
        else [
            {"filename": fn, "reason": reason}
            for fn, reason in getattr(result, "get_skipped", lambda: ())()
        ]
    )
    diagnostics = _normalize_diagnostics(
        [
            (
                {
                    "code": "ast-scanner-error",
                    "message": item.get("reason") or item.get("message") or "AST scan failed",
                    "filename": item.get("filename"),
                    "affects_completeness": True,
                }
                if isinstance(item, Mapping)
                else {
                    "code": "ast-scanner-error",
                    "message": str(item),
                    "affects_completeness": True,
                }
            )
            for item in raw_errors
        ],
        engine="ast-scanner",
        default_incomplete=True,
    )
    findings: list[SecurityFinding] = []
    for issue in issues:
        issue_cwe = (
            normalize_cwe(issue.cwe.id)
            if getattr(issue, "cwe", None) and getattr(issue.cwe, "id", 0) != 0
            else None
        )
        sev = normalize_severity(getattr(issue, "severity", "medium"))
        conf, _ = normalize_confidence(getattr(issue, "confidence", "medium"))
        rule_id = str(getattr(issue, "test_id", None) or "PYFLOW-AST")
        col = getattr(issue, "col_offset", None)
        if isinstance(col, int) and col < 0:
            col = None
        end_col = getattr(issue, "end_col_offset", None)
        if not isinstance(end_col, int) or end_col <= 0:
            end_col = None
        findings.append(
            SecurityFinding(
                rule_id=rule_id,
                rule_title=str(getattr(issue, "test", "") or ""),
                message=str(getattr(issue, "text", "") or "Security issue"),
                severity=sev,
                confidence=conf,
                uri=str(getattr(issue, "fname", "") or ""),
                line=int(getattr(issue, "lineno", 0) or 0),
                column=col,
                end_column=end_col,
                cwe=issue_cwe,
                related_rules=_extract_related_ids(getattr(issue, "related_rules", ()), rule_id),
                vulnerability_family=getattr(issue, "vulnerability_family", None),
            )
        )
    metrics_totals = dict(getattr(getattr(result, "metrics", None), "data", {}).get("_totals", {}))
    status = "partial" if diagnostics else "complete"
    return SecurityReport(
        engine="ast-scanner",
        status=status,
        findings=tuple(findings),
        diagnostics=diagnostics,
        statistics=metrics_totals,
    )


def _finding_from_scanner_dict(item: Mapping[str, Any]) -> SecurityFinding:
    loc = item.get("location") if isinstance(item.get("location"), Mapping) else {}
    cwe_val = item.get("cwe")
    if not cwe_val and isinstance(item.get("issue_cwe"), Mapping):
        cwe_val = item["issue_cwe"].get("id")
    rule_id = str(item.get("rule_id") or item.get("test_id") or "PYFLOW-AST")
    sev = normalize_severity(item.get("severity") or item.get("issue_severity") or "medium")
    conf, score = normalize_confidence(
        item.get("confidence") or item.get("issue_confidence") or "medium"
    )
    return SecurityFinding(
        rule_id=rule_id,
        rule_title=str(item.get("rule_title") or item.get("test_name") or ""),
        message=str(item.get("message") or item.get("text") or item.get("issue_text") or "Issue"),
        severity=sev,
        confidence=conf,
        confidence_score=score,
        uri=str(loc.get("filename") or item.get("filename") or ""),
        line=int(loc.get("line") or item.get("line") or item.get("line_number") or 0),
        column=loc.get("column") if loc.get("column") is not None else item.get("col_offset"),
        end_column=(
            loc.get("end_column")
            if loc.get("end_column") is not None
            else item.get("end_col_offset")
        ),
        cwe=normalize_cwe(cwe_val),
        suggestion=str(item.get("suggestion") or ""),
        related_rules=_extract_related_ids(item.get("related_rules"), rule_id),
        vulnerability_family=item.get("vulnerability_family"),
    )


def _merge_ast_dataflow_steps(raw_trace: Sequence[Any], default_uri: str) -> tuple[FlowStep, ...]:
    steps: list[FlowStep] = []
    for step in raw_trace:
        if isinstance(step, Mapping):
            op = str(step.get("operation") or step.get("kind") or "flow")
            detail = str(
                step.get("detail") or step.get("message") or step.get("location") or op or "flow"
            )
            uri = str(step.get("filename") or default_uri or "")
            line = int(step.get("line") or 0)
            col = step.get("column")
            proc = str(step.get("procedure") or "")
            nest = int(step.get("nesting_level") or 0)
            loc_var = str(step.get("location") or "")
        else:
            op = str(getattr(step, "operation", "flow") or "flow")
            loc_var = str(getattr(step, "location", "") or "")
            detail = str(getattr(step, "detail", "") or loc_var or op)
            uri = str(getattr(step, "filename", "") or default_uri or "")
            line = int(getattr(step, "line", 0) or 0)
            col = getattr(step, "column", None)
            proc = str(getattr(step, "procedure", "") or "")
            nest = int(getattr(step, "nesting_level", 0) or 0)

        # Merge redundant same-line assign immediately following source/call.
        if (
            steps
            and op == "assign"
            and steps[-1].uri == uri
            and steps[-1].line == line
            and steps[-1].kind in {"source", "call"}
            and steps[-1].nesting_level == nest
        ):
            if loc_var and not loc_var.startswith("(") and f"'{loc_var}'" not in steps[-1].message:
                prev = steps[-1]
                steps[-1] = replace(prev, message=f"{prev.message} -> '{loc_var}'")
            continue
        steps.append(
            FlowStep(
                kind=op,
                message=detail,
                uri=uri,
                line=line,
                column=col,
                procedure=proc,
                nesting_level=nest,
            )
        )
    return tuple(steps)


def _from_ast_dataflow(result: Any) -> SecurityReport:
    if isinstance(result, Mapping):
        status = str(result.get("status", "complete"))
        diagnostics = _normalize_diagnostics(
            result.get("diagnostics") or (),
            engine="ast-dataflow",
            default_incomplete=status != "complete",
        )
        findings: list[SecurityFinding] = []
        for item in result.get("findings") or ():
            rule_id = str(item.get("rule_id") or "PYFLOW-AST-DATAFLOW")
            rule_title = str(item.get("rule_title") or "")
            sink_name = str(item.get("sink_name") or "")
            sev = normalize_severity(item.get("severity") or "medium")
            conf, score = normalize_confidence(item.get("confidence") or "high")
            uri = str(item.get("filename") or (item.get("location") or {}).get("filename") or "")
            line = int(item.get("sink_line") or (item.get("location") or {}).get("line") or 0)
            steps = _merge_ast_dataflow_steps(item.get("trace") or item.get("code_flow") or (), uri)
            findings.append(
                SecurityFinding(
                    rule_id=rule_id,
                    rule_title=rule_title,
                    message=str(
                        item.get("message")
                        or rule_title
                        or (f"Tainted data reaches {sink_name}" if sink_name else "Taint finding")
                    ),
                    severity=sev,
                    confidence=conf,
                    confidence_score=score,
                    uri=uri,
                    line=line,
                    column=item.get("sink_column"),
                    end_column=item.get("sink_end_column"),
                    procedure=str(item.get("function") or item.get("procedure") or ""),
                    cwe=normalize_cwe(item.get("cwe")),
                    suggestion=str(item.get("suggestion") or ""),
                    sink_name=sink_name,
                    source_kinds=tuple(str(k) for k in (item.get("source_kinds") or ())),
                    precision_reasons=tuple(str(r) for r in (item.get("precision_reasons") or ())),
                    related_rules=_extract_related_ids(item.get("related_rules"), rule_id),
                    steps=steps,
                )
            )
        return SecurityReport(
            engine="ast-dataflow",
            status=status,
            entry=str(result.get("entry") or ""),
            termination_reason=str(result.get("termination_reason") or ""),
            findings=tuple(findings),
            diagnostics=diagnostics,
            statistics=dict(result.get("statistics") or {}),
        )

    analysis = getattr(result, "analysis_result", None)
    if analysis is None:
        return SecurityReport(
            engine="ast-dataflow",
            status="failed",
            diagnostics=(
                {
                    "code": "ast-dataflow-missing-result",
                    "message": "AST dataflow analysis did not produce a typed result",
                    "affects_completeness": True,
                    "function": None,
                },
            ),
        )
    findings = []
    for item in analysis.findings:
        sev = normalize_severity(item.severity)
        conf, score = normalize_confidence(item.confidence)
        rule_id = str(item.rule_id or "PYFLOW-AST-DATAFLOW")
        rule_title = str(item.rule_title or "")
        sink_name = str(item.sink_name or "")
        steps = _merge_ast_dataflow_steps(item.trace, item.filename)
        findings.append(
            SecurityFinding(
                rule_id=rule_id,
                rule_title=rule_title,
                message=rule_title or f"Tainted data reaches {sink_name}",
                severity=sev,
                confidence=conf,
                confidence_score=score,
                uri=str(item.filename or ""),
                line=int(item.sink_line or 0),
                column=getattr(item, "sink_column", None),
                end_column=getattr(item, "sink_end_column", None),
                procedure=str(item.function or ""),
                cwe=normalize_cwe(item.cwe),
                suggestion=str(item.suggestion or ""),
                sink_name=sink_name,
                source_kinds=tuple(sorted(str(k) for k in item.source_kinds)),
                precision_reasons=tuple(str(r) for r in item.precision_reasons),
                related_rules=tuple(
                    rid for rid, _title, _sev in item.related_rules if rid and rid != rule_id
                ),
                steps=steps,
            )
        )
    return SecurityReport(
        engine="ast-dataflow",
        status=str(analysis.status),
        findings=tuple(findings),
        diagnostics=_normalize_diagnostics(
            analysis.diagnostics,
            engine="ast-dataflow",
            default_incomplete=analysis.status != "complete",
        ),
        statistics=dict(analysis.statistics),
    )


def _from_ifds(result: Mapping[str, Any]) -> SecurityReport:
    status = str(result.get("status", "complete"))
    diagnostics = _normalize_diagnostics(
        result.get("diagnostics") or (),
        engine="ifds",
        default_incomplete=status != "complete",
    )
    findings: list[SecurityFinding] = []
    for item in result.get("findings") or ():
        loc = item.get("primary_location") or item.get("location") or {}
        if not isinstance(loc, Mapping):
            loc = {}
        props = item.get("properties") if isinstance(item.get("properties"), Mapping) else {}
        uri = str(loc.get("uri") or loc.get("filename") or item.get("filename") or "")
        line = int(
            loc.get("start_line")
            or loc.get("line")
            or item.get("sink_line")
            or item.get("line")
            or 0
        )
        col = loc.get("start_column") if loc.get("start_column") is not None else loc.get("column")
        end_line = loc.get("end_line")
        end_col = loc.get("end_column")
        rule_id = str(item.get("rule_id") or "PYFLOW-IFDS")
        sink_name = str(item.get("sink_name") or props.get("sink_name") or "")
        tainted_args = tuple(
            str(a) for a in (item.get("tainted_arguments") or props.get("tainted_arguments") or ())
        )
        source_kinds = (
            (str(props["source_kind"]),)
            if props.get("source_kind")
            else tuple(str(k) for k in (item.get("source_kinds") or ()))
        )
        raw_steps = item.get("code_flow") or item.get("explanations") or ()
        steps = tuple(
            FlowStep(
                kind=str(step.get("kind") or "flow"),
                message=str(step.get("message") or step.get("kind") or "flow"),
                uri=str(
                    (step.get("location") or {}).get("uri")
                    if isinstance(step.get("location"), Mapping)
                    else step.get("filename") or ""
                ),
                line=int(
                    (step.get("location") or {}).get("start_line")
                    if isinstance(step.get("location"), Mapping)
                    else step.get("line") or 0
                ),
                column=(
                    (step.get("location") or {}).get("start_column")
                    if isinstance(step.get("location"), Mapping)
                    else step.get("column")
                ),
                procedure=str(step.get("procedure") or ""),
                nesting_level=int(step.get("nesting_level") or 0),
                debug={k: step[k] for k in ("node_id", "procedure_id") if step.get(k) is not None},
            )
            for step in raw_steps
            if isinstance(step, Mapping)
        )
        sev = normalize_severity(item.get("severity") or "medium")
        conf, score = normalize_confidence(item.get("confidence") or "high")
        message = str(
            item.get("message") or item.get("sink_name") or item.get("kind") or "IFDS finding"
        )
        extra = {
            k: v
            for k, v in props.items()
            if k not in {"tainted_arguments", "sink_name", "source_kind"}
        }
        for debug_key in (
            "kind",
            "node_id",
            "block_kind",
            "protocol",
            "resource_label",
            "state",
            "operation_name",
            "proof_level",
            "mutation_kind",
            "key_origin",
            "target_origin",
            "key_language",
            "object_path",
            "dangerous_components",
            "value_controlled",
        ):
            if item.get(debug_key) is not None:
                extra.setdefault(debug_key, item[debug_key])
        findings.append(
            SecurityFinding(
                rule_id=rule_id,
                rule_title=str(item.get("rule_title") or ""),
                message=message,
                severity=sev,
                confidence=conf,
                confidence_score=score,
                uri=uri,
                line=line,
                column=col,
                end_line=end_line,
                end_column=end_col,
                procedure=str(item.get("procedure") or item.get("function") or ""),
                cwe=normalize_cwe(item.get("cwe")),
                suggestion=str(item.get("suggestion") or ""),
                sink_name=sink_name,
                source_kinds=source_kinds,
                tainted_arguments=tainted_args,
                related_rules=_extract_related_ids(item.get("related_rules"), rule_id),
                fingerprint=str(item.get("fingerprint") or ""),
                steps=steps,
                extra=extra,
            )
        )
    report_debug: dict[str, Any] = {}
    if result.get("analysis"):
        report_debug["analysis"] = result["analysis"]
    if result.get("entries"):
        report_debug["entries"] = list(result["entries"])
    return SecurityReport(
        engine="ifds",
        status=status,
        entry=str(result.get("entry") or ""),
        termination_reason=str(result.get("termination_reason") or ""),
        findings=tuple(findings),
        diagnostics=diagnostics,
        statistics=dict(result.get("statistics") or {}),
        debug=report_debug,
    )


def _from_cpg(result: Mapping[str, Any]) -> SecurityReport:
    status = str(result.get("status", "complete"))
    diagnostics = _normalize_diagnostics(
        result.get("diagnostics") or (),
        engine="cpg",
        default_incomplete=status != "complete",
    )
    findings: list[SecurityFinding] = []
    for item in result.get("findings") or ():
        if not isinstance(item, Mapping):
            item = item.to_dict()
        rule_obj = item.get("rule") if isinstance(item.get("rule"), Mapping) else {}
        rule_id = str(item.get("rule_id") or item.get("cwe") or "CPG-TAINT")
        rule_title = str(
            item.get("rule_title")
            or rule_obj.get("short_description")
            or rule_obj.get("name")
            or ""
        )
        source_label = str(item.get("source_label") or "")
        sink_label = str(item.get("sink_label") or item.get("sink_name") or "")
        source_uri = str(item.get("source_filename") or "")
        sink_uri = str(item.get("sink_filename") or item.get("filename") or "")
        source_line = int(item.get("source_line") or 0)
        sink_line = int(item.get("sink_line") or item.get("line") or 0)
        raw_conf = item.get("confidence")
        conf, score = normalize_confidence(raw_conf)
        if item.get("confidence_level"):
            conf = str(item["confidence_level"]).strip().lower()
        sev = normalize_severity(item.get("severity") or "medium")
        steps = tuple(
            FlowStep(
                kind=str(step.get("kind") or "flow"),
                message=str(step.get("label") or step.get("message") or step.get("kind") or "flow"),
                uri=str(step.get("filename") or sink_uri or source_uri),
                line=int(step.get("line") or 0),
                column=step.get("column"),
                procedure=str(step.get("procedure") or ""),
                nesting_level=int(step.get("nesting_level") or 0),
            )
            for step in (item.get("path_preview") or item.get("code_flow") or ())
            if isinstance(step, Mapping)
        )
        message = (
            f"Tainted data from {source_label or 'untrusted source'} reaches "
            f"{sink_label or 'dangerous sink'}"
            if (source_label or sink_label)
            else (rule_title or "CPG security finding")
        )
        findings.append(
            SecurityFinding(
                rule_id=rule_id,
                rule_title=rule_title,
                message=message,
                severity=sev,
                confidence=conf,
                confidence_score=score,
                uri=sink_uri or source_uri,
                line=sink_line or source_line,
                column=item.get("sink_column"),
                end_column=item.get("sink_end_column"),
                procedure=str(item.get("procedure") or ""),
                cwe=normalize_cwe(item.get("cwe")),
                suggestion=str(item.get("suggestion") or rule_obj.get("help_text") or ""),
                sink_name=sink_label,
                source_kinds=tuple(str(t) for t in (item.get("tags") or ())),
                precision_reasons=tuple(str(r) for r in (item.get("precision_reasons") or ())),
                related_rules=_extract_related_ids(item.get("related_rules"), rule_id),
                source_label=source_label,
                source_uri=source_uri,
                source_line=source_line,
                sink_label=sink_label,
                sink_uri=sink_uri,
                sink_line=sink_line,
                steps=steps,
                tags=tuple(str(t) for t in (item.get("tags") or ())),
                extra=({"precision": rule_obj["precision"]} if rule_obj.get("precision") else {}),
            )
        )
    return SecurityReport(
        engine="cpg",
        status=status,
        entry=str(result.get("entry") or ""),
        termination_reason=str(result.get("termination_reason") or ""),
        findings=tuple(findings),
        diagnostics=diagnostics,
        statistics=dict(result.get("statistics") or {}),
    )


def build_security_report(engine: str, raw: Any) -> SecurityReport:
    """Convert any engine result or raw dict into a canonical :class:`SecurityReport`."""
    if isinstance(raw, SecurityReport):
        return raw
    if engine == "ast-scanner":
        return _from_ast_scanner(raw)
    if engine == "ast-dataflow":
        return _from_ast_dataflow(raw)
    if engine == "ifds":
        return _from_ifds(raw if isinstance(raw, Mapping) else {})
    if engine == "cpg":
        return _from_cpg(raw if isinstance(raw, Mapping) else {})
    return SecurityReport(engine=engine, status="invalid")


__all__ = [
    "FlowStep",
    "PRECISION_DIAGNOSTIC_CODES",
    "SCHEMA_VERSION",
    "SecurityFinding",
    "SecurityReport",
    "build_security_report",
    "compute_fingerprint",
    "normalize_confidence",
    "normalize_severity",
    "read_source_line",
    "read_source_lines",
    "resolve_uri",
    "step_importance",
]
