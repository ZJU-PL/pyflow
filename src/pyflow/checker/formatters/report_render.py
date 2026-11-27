"""Unified, user-friendly bug report renderers for IFDS, AST-dataflow, CPG, and AST-scanner.

Supports four human-oriented outputs from a common normalized finding view:
- Plain text (``text``): structured findings with source context, caret underline,
  numbered Source -> Sink traces, CWE, and remediation suggestions.
- Colored terminal (``screen``): ANSI-colored variant of the rich text report.
- Markdown (``markdown``): GitHub-Flavored Markdown suitable for PR comments and CI.
- HTML (``html``): self-contained interactive audit report with severity filters and
  expandable dataflow timelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import html as html_lib
from pathlib import Path
from typing import Any, Mapping, Sequence

from pyflow.util.cwe import normalize_cwe

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "bold_red": "\033[1;31m",
    "yellow": "\033[33m",
    "bold_yellow": "\033[1;33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "magenta": "\033[35m",
}

_SEVERITY_ORDER = ("critical", "high", "medium", "warning", "low", "info", "note")


@dataclass(frozen=True)
class RenderedFlowStep:
    """Engine-independent step in a bug report's witness path."""

    kind: str
    message: str
    uri: str = ""
    line: int = 0
    column: int | None = None
    procedure: str = ""
    nesting_level: int = 0


@dataclass(frozen=True)
class RenderedFinding:
    """Engine-independent finding view consumed by text/screen/markdown/HTML renderers."""

    rule_id: str
    rule_title: str
    message: str
    severity: str
    confidence: str
    uri: str = ""
    line: int = 0
    column: int | None = None
    end_column: int | None = None
    procedure: str = ""
    cwe: str | None = None
    suggestion: str = ""
    sink_name: str = ""
    source_kinds: tuple[str, ...] = ()
    tainted_arguments: tuple[str, ...] = ()
    precision_reasons: tuple[str, ...] = ()
    related_rules: tuple[str, ...] = ()
    # CPG-specific endpoint metadata
    source_label: str = ""
    source_uri: str = ""
    source_line: int = 0
    sink_label: str = ""
    sink_uri: str = ""
    sink_line: int = 0
    confidence_score: float | None = None
    steps: tuple[RenderedFlowStep, ...] = ()


@dataclass(frozen=True)
class RenderedReport:
    """Engine-independent report envelope."""

    engine: str
    status: str
    entry: str = ""
    termination_reason: str = ""
    findings: tuple[RenderedFinding, ...] = ()
    diagnostics: tuple[dict[str, Any], ...] = ()
    statistics: Mapping[str, Any] = field(default_factory=dict)


def _cwe_url(cwe: str | None) -> str:
    norm = normalize_cwe(cwe)
    if not norm or not norm.startswith("CWE-"):
        return ""
    number = norm.split("-", 1)[1]
    return f"https://cwe.mitre.org/data/definitions/{number}.html" if number.isdigit() else ""


@lru_cache(maxsize=256)
def _read_source_lines_cached(path_str: str, mtime_ns: int) -> tuple[str, ...]:
    del mtime_ns
    try:
        return tuple(Path(path_str).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def _source_lines(uri: str) -> tuple[str, ...]:
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


def _single_source_line(uri: str, line: int) -> str:
    if line <= 0:
        return ""
    lines = _source_lines(uri)
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def _caret_span(
    source_line: str,
    column: int | None,
    end_column: int | None,
    hint_token: str = "",
) -> tuple[int, int] | None:
    """Return 0-based (start, length) caret highlight span on *source_line*."""
    if not source_line.strip():
        return None
    if column is not None and column >= 0 and column < len(source_line):
        if end_column is not None and end_column > column:
            length = min(end_column - column, len(source_line) - column)
        else:
            length = max(1, len(hint_token.rsplit(".", 1)[-1]) if hint_token else 1)
            length = min(length, len(source_line) - column)
        return column, max(length, 1)
    if hint_token:
        for needle in (hint_token, hint_token.rsplit(".", 1)[-1]):
            if needle:
                idx = source_line.find(needle)
                if idx >= 0:
                    return idx, len(needle)
    stripped = source_line.lstrip()
    leading = len(source_line) - len(stripped)
    return leading, max(1, min(len(stripped), 40))


def _style(text: str, code: str, *, color: bool) -> str:
    if not color or code not in _ANSI:
        return text
    return f"{_ANSI[code]}{text}{_ANSI['reset']}"


def _severity_color(severity: str) -> str:
    sev = severity.lower()
    if sev in {"critical", "high", "error"}:
        return "bold_red"
    if sev in {"medium", "warning"}:
        return "bold_yellow"
    return "cyan"


def _format_location(uri: str, line: int, column: int | None = None) -> str:
    if not uri and line <= 0:
        return "<source location unavailable>"
    if line <= 0:
        return "<source location unavailable>"
    display_uri = uri or "<unknown source>"
    if column is not None and column >= 0:
        return f"{display_uri}:{line}:{column + 1}"
    return f"{display_uri}:{line}"


def _step_badge(kind: str) -> str:
    mapping = {
        "source": "SOURCE",
        "seed": "SOURCE",
        "call": "CALL",
        "call_flow": "ENTER",
        "return_flow": "RETURN",
        "return_flow(summary_replay)": "RETURN",
        "call_to_return": "CALL",
        "normal_flow": "FLOW",
        "sink": "SINK",
        "assign": "ASSIGN",
        "propagate": "FLOW",
    }
    return mapping.get(kind.lower(), kind.upper()[:10] or "FLOW")


def normalize_report_for_render(engine: str, report: Mapping[str, Any]) -> RenderedReport:
    """Convert any engine's JSON-normalized report dict into a :class:`RenderedReport`."""
    status = str(report.get("status", "complete"))
    entry = str(report.get("entry") or "")
    termination_reason = str(report.get("termination_reason") or "")
    diagnostics: list[dict[str, Any]] = []
    for item in report.get("diagnostics") or ():
        if isinstance(item, dict):
            diagnostics.append(dict(item))
        else:
            diagnostics.append({"code": f"{engine}-diagnostic", "message": str(item)})
    statistics = dict(report.get("statistics") or {})
    rendered_findings: list[RenderedFinding] = []

    if engine == "ast-dataflow":
        for item in report.get("findings") or ():
            steps = tuple(
                RenderedFlowStep(
                    kind=str(step.get("operation") or "flow"),
                    message=str(
                        step.get("detail")
                        or step.get("location")
                        or step.get("operation")
                        or "flow"
                    ),
                    uri=str(step.get("filename") or item.get("filename") or ""),
                    line=int(step.get("line") or 0),
                    column=step.get("column"),
                )
                for step in (item.get("trace") or ())
            )
            related = tuple(
                str(r.get("rule_id"))
                for r in (item.get("related_rules") or ())
                if isinstance(r, dict)
                and r.get("rule_id")
                and r.get("rule_id") != item.get("rule_id")
            )
            source_kinds = tuple(str(k) for k in (item.get("source_kinds") or ()))
            sink_name = str(item.get("sink_name") or "")
            rule_title = str(item.get("rule_title") or "")
            rendered_findings.append(
                RenderedFinding(
                    rule_id=str(item.get("rule_id") or "PYFLOW-AST-DATAFLOW"),
                    rule_title=rule_title,
                    message=rule_title or f"Tainted data reaches {sink_name}",
                    severity=str(item.get("severity") or "medium"),
                    confidence=str(item.get("confidence") or "HIGH"),
                    uri=str(item.get("filename") or ""),
                    line=int(item.get("sink_line") or 0),
                    column=item.get("sink_column"),
                    procedure=str(item.get("function") or ""),
                    cwe=normalize_cwe(item.get("cwe")),
                    suggestion=str(item.get("suggestion") or ""),
                    sink_name=sink_name,
                    source_kinds=source_kinds,
                    precision_reasons=tuple(str(r) for r in (item.get("precision_reasons") or ())),
                    related_rules=related,
                    steps=steps,
                )
            )
    elif engine == "ifds":
        for item in report.get("findings") or ():
            loc = item.get("primary_location") or {}
            props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
            uri = str(loc.get("uri") or "") if isinstance(loc, dict) else ""
            line = int(loc.get("start_line") or 0) if isinstance(loc, dict) else 0
            col = loc.get("start_column") if isinstance(loc, dict) else None
            end_col = loc.get("end_column") if isinstance(loc, dict) else None
            sink_name = str(item.get("sink_name") or props.get("sink_name") or "")
            tainted_args = tuple(
                str(a)
                for a in (item.get("tainted_arguments") or props.get("tainted_arguments") or ())
            )
            raw_steps = item.get("code_flow") or item.get("explanations") or ()
            steps = tuple(
                RenderedFlowStep(
                    kind=str(step.get("kind") or "flow"),
                    message=str(step.get("message") or step.get("kind") or "flow"),
                    uri=str((step.get("location") or {}).get("uri") or ""),
                    line=int((step.get("location") or {}).get("start_line") or 0),
                    column=(step.get("location") or {}).get("start_column"),
                    procedure=str(step.get("procedure") or ""),
                    nesting_level=int(step.get("nesting_level") or 0),
                )
                for step in raw_steps
                if isinstance(step, dict)
            )
            rule_id = str(item.get("rule_id") or "PYFLOW-IFDS")
            related = tuple(
                str(r.get("rule_id"))
                for r in (item.get("related_rules") or ())
                if isinstance(r, dict) and r.get("rule_id") and r.get("rule_id") != rule_id
            )
            message = str(
                item.get("message") or item.get("sink_name") or item.get("kind") or "IFDS finding"
            )
            rendered_findings.append(
                RenderedFinding(
                    rule_id=rule_id,
                    rule_title=str(item.get("rule_title") or ""),
                    message=message,
                    severity=str(item.get("severity") or "unspecified"),
                    confidence=str(item.get("confidence") or ""),
                    uri=uri,
                    line=line,
                    column=col,
                    end_column=end_col,
                    procedure=str(item.get("procedure") or ""),
                    cwe=normalize_cwe(item.get("cwe")),
                    suggestion=str(item.get("suggestion") or ""),
                    sink_name=sink_name,
                    tainted_arguments=tainted_args,
                    related_rules=related,
                    steps=steps,
                )
            )
    elif engine == "cpg":
        for item in report.get("findings") or ():
            rule_obj = item.get("rule") if isinstance(item.get("rule"), dict) else {}
            rule_id = str(item.get("rule_id") or item.get("cwe") or "CPG-TAINT")
            rule_title = str(
                item.get("rule_title")
                or rule_obj.get("short_description")
                or rule_obj.get("name")
                or ""
            )
            source_label = str(item.get("source_label") or "")
            sink_label = str(item.get("sink_label") or "")
            source_uri = str(item.get("source_filename") or "")
            sink_uri = str(item.get("sink_filename") or "")
            source_line = int(item.get("source_line") or 0)
            sink_line = int(item.get("sink_line") or 0)
            raw_conf = item.get("confidence")
            conf_score = float(raw_conf) if isinstance(raw_conf, (int, float)) else None
            conf_level = str(item.get("confidence_level") or "")
            if not conf_level and conf_score is not None:
                conf_level = (
                    "HIGH" if conf_score >= 0.85 else "MEDIUM" if conf_score >= 0.6 else "LOW"
                )
            suggestion = str(item.get("suggestion") or rule_obj.get("help_text") or "")
            steps = tuple(
                RenderedFlowStep(
                    kind=str(step.get("kind") or "flow"),
                    message=str(step.get("label") or step.get("kind") or "flow"),
                    uri=str(step.get("filename") or sink_uri or source_uri),
                    line=int(step.get("line") or 0),
                    column=step.get("column"),
                )
                for step in (item.get("path_preview") or ())
                if isinstance(step, dict)
            )
            message = (
                f"Tainted data from {source_label or 'untrusted source'} reaches "
                f"{sink_label or 'dangerous sink'}"
                if (source_label or sink_label)
                else (rule_title or "CPG security finding")
            )
            rendered_findings.append(
                RenderedFinding(
                    rule_id=rule_id,
                    rule_title=rule_title,
                    message=message,
                    severity=str(item.get("severity") or "medium"),
                    confidence=conf_level,
                    uri=sink_uri or source_uri,
                    line=sink_line or source_line,
                    column=item.get("sink_column"),
                    end_column=item.get("sink_end_column"),
                    cwe=normalize_cwe(item.get("cwe")),
                    suggestion=suggestion,
                    sink_name=sink_label,
                    precision_reasons=tuple(str(r) for r in (item.get("precision_reasons") or ())),
                    source_label=source_label,
                    source_uri=source_uri,
                    source_line=source_line,
                    sink_label=sink_label,
                    sink_uri=sink_uri,
                    sink_line=sink_line,
                    confidence_score=conf_score,
                    steps=steps,
                )
            )
    elif engine == "ast-scanner":
        for item in report.get("results") or report.get("findings") or ():
            cwe_val = item.get("cwe")
            if not cwe_val and isinstance(item.get("issue_cwe"), dict):
                cwe_val = item["issue_cwe"].get("id")
            rendered_findings.append(
                RenderedFinding(
                    rule_id=str(item.get("test_id") or item.get("rule_id") or "PYFLOW-AST"),
                    rule_title=str(item.get("test_name") or item.get("rule_title") or ""),
                    message=str(item.get("text") or item.get("message") or "Security issue"),
                    severity=str(item.get("severity") or "medium"),
                    confidence=str(item.get("confidence") or "medium"),
                    uri=str(item.get("filename") or ""),
                    line=int(item.get("line") or item.get("line_number") or 0),
                    cwe=normalize_cwe(cwe_val),
                )
            )

    return RenderedReport(
        engine=engine,
        status=status,
        entry=entry,
        termination_reason=termination_reason,
        findings=tuple(rendered_findings),
        diagnostics=tuple(diagnostics),
        statistics=statistics,
    )


def _severity_counts(findings: Sequence[RenderedFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.lower()
        counts[key] = counts.get(key, 0) + 1
    ordered: dict[str, int] = {}
    for sev in _SEVERITY_ORDER:
        if sev in counts:
            ordered[sev] = counts.pop(sev)
    for sev in sorted(counts):
        ordered[sev] = counts[sev]
    return ordered


def _render_snippet_lines(
    uri: str,
    line: int,
    *,
    column: int | None = None,
    end_column: int | None = None,
    hint_token: str = "",
    context_lines: int = 1,
    indent: str = "       ",
    color: bool = False,
) -> list[str]:
    if line <= 0:
        return []
    lines = _source_lines(uri)
    if not lines or line > len(lines):
        return []
    start = max(1, line - context_lines)
    end = min(len(lines), line + context_lines)
    gutter_width = len(str(end))
    out: list[str] = []
    for lineno in range(start, end + 1):
        text = lines[lineno - 1]
        marker = ">" if lineno == line else " "
        prefix = f"{indent}{marker} {lineno:>{gutter_width}} | "
        if lineno == line:
            out.append(_style(prefix, "bold_red", color=color) + text)
            caret = _caret_span(text, column, end_column, hint_token)
            if caret is not None:
                c_start, c_len = caret
                pointer = "^" + "~" * max(0, c_len - 1)
                pad = " " * (len(indent) + 2 + gutter_width) + " | " + (" " * c_start)
                out.append(pad + _style(pointer, "bold_red", color=color))
        else:
            out.append(_style(prefix, "dim", color=color) + text)
    return out


def _render_flow_text(
    steps: Sequence[RenderedFlowStep],
    *,
    indent: str = "       ",
    color: bool = False,
) -> list[str]:
    if not steps:
        return []
    out = [indent + _style("Flow:", "bold", color=color)]
    for idx, step in enumerate(steps, 1):
        nest = "  " * min(max(step.nesting_level, 0), 6)
        badge = _style(f"[{_step_badge(step.kind)}]", "cyan", color=color)
        loc_part = ""
        if step.line > 0:
            loc_str = _format_location(step.uri, step.line)
            loc_part = f" {_style(loc_str, 'dim', color=color)}"
        out.append(f"{indent}  {nest}{idx}. {badge} {step.message}{loc_part}")
        code_line = _single_source_line(step.uri, step.line)
        if code_line:
            out.append(f"{indent}     {nest}| {code_line[:110]}")
    return out


def render_bug_report_text(
    engine: str,
    report: Mapping[str, Any],
    *,
    color: bool = False,
    verbose: bool = False,
    context_lines: int = 1,
) -> str:
    """Render a structured, user-friendly plain-text or ANSI-colored bug report."""
    doc = normalize_report_for_render(engine, report)
    lines: list[str] = []

    if engine == "ifds":
        lines.append(f"Entry: {doc.entry or '<unknown>'}")
        lines.append(f"Status: {doc.status}")
        lines.append(f"Findings: {len(doc.findings)}")
    else:
        lines.append(f"Status: {doc.status}")

    if doc.termination_reason:
        lines.append(_style(f"Notice: {doc.termination_reason}", "yellow", color=color))

    sev_counts = _severity_counts(doc.findings)
    if not doc.findings:
        if engine == "cpg":
            lines.append("No security findings.")
        elif engine != "ifds":
            lines.append("No issues found.")
    else:
        breakdown = ", ".join(f"{k}: {v}" for k, v in sev_counts.items())
        if engine == "cpg":
            lines.append(f"\n{len(doc.findings)} security finding(s) ({breakdown}):\n")
        elif engine == "ast-dataflow":
            lines.append(f"Found {len(doc.findings)} issue(s) ({breakdown}):\n")
        elif engine == "ifds":
            lines.append(f"Summary: {breakdown}")
            lines.append("")
        else:
            lines.append(f"Found {len(doc.findings)} issue(s) ({breakdown}):\n")

    for index, finding in enumerate(doc.findings, 1):
        sev_col = _severity_color(finding.severity)
        if engine == "cpg":
            conf_str = ""
            if finding.confidence_score is not None:
                filled = max(0, min(10, int(finding.confidence_score * 10)))
                bar = "█" * filled + "░" * (10 - filled)
                conf_str = f" confidence={finding.confidence_score:.0%} [{bar}]"
            elif finding.confidence:
                conf_str = f" confidence={finding.confidence}"
            cwe_part = finding.cwe or finding.rule_id
            title_suffix = f" - {finding.rule_title}" if finding.rule_title else ""
            header = (
                f"  [{index}] {_style(cwe_part, 'bold', color=color)} "
                f"[{_style(finding.severity, sev_col, color=color)}]{conf_str}{title_suffix}"
            )
            lines.append(header)
            src_pos = (
                f"{finding.source_uri or '<unknown source>'}:{finding.source_line}"
                if finding.source_line > 0
                else "<source location unavailable>"
            )
            snk_pos = (
                f"{finding.sink_uri or '<unknown source>'}:{finding.sink_line}"
                if finding.sink_line > 0
                else "<source location unavailable>"
            )
            lines.append(f"      source: {finding.source_label or 'unknown'} ({src_pos})")
            lines.append(f"      sink:   {finding.sink_label or 'unknown'} ({snk_pos})")
            snippet = _render_snippet_lines(
                finding.uri,
                finding.line,
                column=finding.column,
                end_column=finding.end_column,
                hint_token=finding.sink_name,
                context_lines=context_lines,
                indent="      ",
                color=color,
            )
            lines.extend(snippet)
            lines.extend(_render_flow_text(finding.steps, indent="      ", color=color))
            if finding.suggestion:
                lines.append(
                    f"      {_style('Suggestion:', 'green', color=color)} {finding.suggestion}"
                )
            if finding.precision_reasons:
                lines.append(f"      Notes: {', '.join(finding.precision_reasons)}")
            lines.append("")
        elif engine == "ast-dataflow":
            cwe_badge = f" ({finding.cwe})" if finding.cwe else ""
            lines.append(
                f"  [{index}] {_style(f'[{finding.rule_id}]', 'bold', color=color)} "
                f"{finding.rule_title or finding.message}{cwe_badge}"
            )
            lines.append(
                f"       Severity: {_style(finding.severity.upper(), sev_col, color=color)}  "
                f"Confidence: {finding.confidence}"
            )
            lines.append(
                f"       File: {_format_location(finding.uri, finding.line, finding.column)}"
                + (f"  Function: {finding.procedure}" if finding.procedure else "")
            )
            lines.append(
                f"       Sink: {finding.sink_name}  " f"Kinds: {', '.join(finding.source_kinds)}"
            )
            lines.extend(
                _render_snippet_lines(
                    finding.uri,
                    finding.line,
                    column=finding.column,
                    hint_token=finding.sink_name,
                    context_lines=context_lines,
                    color=color,
                )
            )
            lines.extend(_render_flow_text(finding.steps, color=color))
            if finding.suggestion:
                lines.append(
                    f"       {_style('Suggestion:', 'green', color=color)} {finding.suggestion}"
                )
            if finding.related_rules:
                lines.append(f"       Related rules: {', '.join(finding.related_rules)}")
            if finding.precision_reasons:
                lines.append(f"       Notes: {', '.join(finding.precision_reasons)}")
            lines.append("")
        else:
            # IFDS (taint, nullness, typestate, class-pollution) and fallback ast-scanner
            position = (
                f"{finding.uri}:{finding.line}"
                if finding.uri and finding.line > 0
                else "<source location unavailable>"
            )
            cwe_part = f"  CWE: {finding.cwe}" if finding.cwe else ""
            conf_part = f"  Confidence: {finding.confidence}" if finding.confidence else ""
            lines.append(
                f"  {_style(f'[{finding.rule_id}]', 'bold', color=color)} "
                f"Severity: {_style(finding.severity, sev_col, color=color)}{conf_part}{cwe_part}  "
                f"Location: {position}"
            )
            lines.append(f"       {finding.message}")
            if finding.procedure:
                lines.append(f"       Procedure: {finding.procedure}")
            if finding.sink_name:
                args_str = ", ".join(finding.tainted_arguments) or "<none>"
                proc_str = finding.procedure or "<unknown>"
                lines.append(
                    f"       sink={finding.sink_name} procedure={proc_str} args=[{args_str}]"
                )
            lines.extend(
                _render_snippet_lines(
                    finding.uri,
                    finding.line,
                    column=finding.column,
                    end_column=finding.end_column,
                    hint_token=finding.sink_name,
                    context_lines=context_lines,
                    color=color,
                )
            )
            lines.extend(_render_flow_text(finding.steps, color=color))
            if finding.suggestion:
                lines.append(
                    f"       {_style('Suggestion:', 'green', color=color)} {finding.suggestion}"
                )
            if finding.related_rules:
                lines.append(f"       Related rules: {', '.join(finding.related_rules)}")
            lines.append("")

    if doc.diagnostics:
        lines.append(_style("Diagnostics:", "bold", color=color))
        grouped: dict[tuple[str, str], list[str]] = {}
        for diag in doc.diagnostics:
            code = str(diag.get("code") or f"{engine}-diagnostic")
            msg = str(diag.get("message") or "")
            loc = ""
            if diag.get("filename") or diag.get("line"):
                loc = f" ({diag.get('filename') or '<unknown>'}:{diag.get('line') or 0})"
            grouped.setdefault((code, msg), []).append(loc)
        for (code, msg), locs in grouped.items():
            count = len(locs)
            if count > 1:
                lines.append(f"  [{code}] {msg} ({count} occurrences)")
            else:
                lines.append(f"  [{code}] {msg}{locs[0]}")

    if verbose and doc.statistics:
        lines.append("")
        lines.append(_style("Statistics:", "dim", color=color))
        for key, value in sorted(doc.statistics.items()):
            lines.append(f"  {key}: {value}")

    return "\n".join(lines).rstrip()


def render_bug_report_markdown(engine: str, report: Mapping[str, Any]) -> str:
    """Render a GitHub-Flavored Markdown bug report suitable for PR comments & reviews."""
    doc = normalize_report_for_render(engine, report)
    sev_counts = _severity_counts(doc.findings)
    lines: list[str] = [
        f"# PyFlow Security Report (`{doc.engine}`)",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Status | `{doc.status}` |",
        f"| Total Findings | **{len(doc.findings)}** |",
    ]
    if doc.entry:
        lines.append(f"| Entry | `{doc.entry}` |")
    if sev_counts:
        summary = ", ".join(f"`{k}`: {v}" for k, v in sev_counts.items())
        lines.append(f"| By Severity | {summary} |")
    if doc.termination_reason:
        lines.extend(["", f"> [!WARNING]\n> {doc.termination_reason}"])

    if not doc.findings:
        lines.extend(["", "No security findings reported."])
    else:
        lines.extend(["", "## Findings", ""])
        for index, finding in enumerate(doc.findings, 1):
            title = finding.rule_title or finding.message
            lines.append(f"### {index}. `{finding.rule_id}` — {title}")
            meta = [f"**Severity:** `{finding.severity}`"]
            if finding.confidence:
                meta.append(f"**Confidence:** `{finding.confidence}`")
            if finding.cwe:
                url = _cwe_url(finding.cwe)
                meta.append(
                    f"**CWE:** [{finding.cwe}]({url})" if url else f"**CWE:** `{finding.cwe}`"
                )
            meta.append(
                f"**Location:** `{_format_location(finding.uri, finding.line, finding.column)}`"
            )
            if finding.procedure:
                meta.append(f"**Procedure:** `{finding.procedure}`")
            lines.append("- " + " | ".join(meta))
            if finding.message and finding.message != title:
                lines.append(f"- **Details:** {finding.message}")
            if finding.source_label or finding.sink_label:
                src_pos = _format_location(finding.source_uri, finding.source_line)
                snk_pos = _format_location(finding.sink_uri, finding.sink_line)
                lines.append(
                    f"- **Endpoint:** `{finding.source_label or 'source'}` (`{src_pos}`) "
                    f"-> `{finding.sink_label or 'sink'}` (`{snk_pos}`)"
                )
            elif finding.sink_name:
                extra = (
                    f" (tainted args: `{', '.join(finding.tainted_arguments)}`)"
                    if finding.tainted_arguments
                    else ""
                )
                lines.append(f"- **Sink:** `{finding.sink_name}`{extra}")

            snippet = _render_snippet_lines(
                finding.uri,
                finding.line,
                column=finding.column,
                end_column=finding.end_column,
                hint_token=finding.sink_name,
                context_lines=2,
                indent="",
                color=False,
            )
            if snippet:
                lines.extend(["", "```python", *snippet, "```"])

            if finding.steps:
                lines.extend(
                    [
                        "",
                        "<details open>",
                        f"<summary>Dataflow Trace ({len(finding.steps)} step(s))</summary>",
                        "",
                        "| # | Step | Location | Detail | Code |",
                        "| --- | --- | --- | --- | --- |",
                    ]
                )
                for step_idx, step in enumerate(finding.steps, 1):
                    indent_prefix = "&nbsp;&nbsp;" * min(max(step.nesting_level, 0), 5)
                    loc = _format_location(step.uri, step.line) if step.line > 0 else "-"
                    code_cell = _single_source_line(step.uri, step.line).replace("|", "\\|")
                    msg_cell = step.message.replace("|", "\\|")
                    code_fmt = f"`{code_cell[:90]}`" if code_cell else "-"
                    lines.append(
                        f"| {step_idx} | `{_step_badge(step.kind)}` | `{loc}` | "
                        f"{indent_prefix}{msg_cell} | {code_fmt} |"
                    )
                lines.extend(["", "</details>"])

            if finding.suggestion:
                lines.extend(["", f"> **Suggestion:** {finding.suggestion}"])
            lines.append("")

    if doc.diagnostics:
        lines.extend(["## Diagnostics", ""])
        for diag in doc.diagnostics:
            code = diag.get("code") or f"{engine}-diagnostic"
            msg = diag.get("message") or ""
            lines.append(f"- `{code}`: {msg}")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_bug_report_html(engine: str, report: Mapping[str, Any]) -> str:
    """Render a self-contained, XSS-safe HTML5 interactive bug report."""
    doc = normalize_report_for_render(engine, report)
    sev_counts = _severity_counts(doc.findings)
    esc = html_lib.escape

    cards_html: list[str] = []
    for index, finding in enumerate(doc.findings, 1):
        sev_key = finding.severity.lower()
        cwe_html = ""
        if finding.cwe:
            url = _cwe_url(finding.cwe)
            if url:
                cwe_html = (
                    f'<a class="badge cwe" href="{esc(url)}" target="_blank" '
                    f'rel="noopener noreferrer">{esc(finding.cwe)}</a>'
                )
            else:
                cwe_html = f'<span class="badge cwe">{esc(finding.cwe)}</span>'

        conf_html = (
            f'<span class="badge conf">Confidence: {esc(finding.confidence)}</span>'
            if finding.confidence
            else ""
        )
        proc_html = f" &middot; <code>{esc(finding.procedure)}</code>" if finding.procedure else ""
        loc_text = _format_location(finding.uri, finding.line, finding.column)

        snippet_html = ""
        source_lines = _source_lines(finding.uri)
        if source_lines and 1 <= finding.line <= len(source_lines):
            start = max(1, finding.line - 2)
            end = min(len(source_lines), finding.line + 2)
            rows = []
            for lineno in range(start, end + 1):
                cls = "code-line highlight" if lineno == finding.line else "code-line"
                rows.append(
                    f'<div class="{cls}"><span class="ln">{lineno}</span>'
                    f'<span class="src">{esc(source_lines[lineno - 1])}</span></div>'
                )
            snippet_html = f'<div class="snippet">{"".join(rows)}</div>'

        trace_html = ""
        if finding.steps:
            step_items = []
            for step_idx, step in enumerate(finding.steps, 1):
                pad_px = min(max(step.nesting_level, 0), 6) * 18
                step_loc = _format_location(step.uri, step.line) if step.line > 0 else ""
                step_code = _single_source_line(step.uri, step.line)
                code_el = (
                    f'<code class="step-code">{esc(step_code[:110])}</code>' if step_code else ""
                )
                loc_el = f'<span class="step-loc">{esc(step_loc)}</span>' if step_loc else ""
                step_items.append(
                    f'<li style="margin-left:{pad_px}px">'
                    f'<span class="step-num">{step_idx}</span>'
                    f'<span class="step-kind">{esc(_step_badge(step.kind))}</span>'
                    f'<span class="step-msg">{esc(step.message)}</span> '
                    f"{loc_el}{code_el}</li>"
                )
            trace_html = (
                f'<details class="trace" open>'
                f"<summary>Dataflow Trace ({len(finding.steps)} step(s))</summary>"
                f'<ol class="trace-list">{"".join(step_items)}</ol>'
                f"</details>"
            )

        suggestion_html = (
            f'<div class="suggestion"><strong>Suggestion:</strong> {esc(finding.suggestion)}</div>'
            if finding.suggestion
            else ""
        )

        title = finding.rule_title or finding.message
        msg_html = (
            f'<p class="message">{esc(finding.message)}</p>'
            if finding.message and finding.message != title
            else ""
        )
        cards_html.append(
            f'<article class="finding" data-severity="{esc(sev_key)}">'
            f'<div class="finding-header">'
            f'<span class="badge sev-{esc(sev_key)}">{esc(finding.severity.upper())}</span>'
            f'<code class="rule-id">{esc(finding.rule_id)}</code>'
            f'<span class="finding-title">#{index} {esc(title)}</span>'
            f'<span class="badges-right">{cwe_html}{conf_html}</span>'
            f"</div>"
            f'<div class="location">Location: <code>{esc(loc_text)}</code>{proc_html}</div>'
            f"{msg_html}{snippet_html}{trace_html}{suggestion_html}"
            f"</article>"
        )

    if not cards_html:
        cards_html.append('<div class="empty">No security findings reported.</div>')

    diag_html = ""
    if doc.diagnostics:
        items = "".join(
            f'<li><code>{esc(str(d.get("code") or "diagnostic"))}</code>: '
            f'{esc(str(d.get("message") or ""))}</li>'
            for d in doc.diagnostics
        )
        diag_html = f'<section class="diagnostics"><h2>Diagnostics</h2><ul>{items}</ul></section>'

    filter_buttons = ['<button class="filter active" data-sev="all">All</button>']
    for sev, count in sev_counts.items():
        filter_buttons.append(
            f'<button class="filter" data-sev="{esc(sev)}">'
            f"{esc(sev.upper())} ({count})</button>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PyFlow Security Report ({esc(doc.engine)})</title>
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #e2e8f0;
    --muted: #94a3b8; --code-bg: #0b1120; --hl: rgba(239, 68, 68, 0.18);
    --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #38bdf8; --ok: #22c55e;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0; --text: #0f172a;
      --muted: #475569; --code-bg: #f1f5f9; --hl: rgba(239, 68, 68, 0.12);
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 24px; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }}
  .container {{ max-width: 1080px; margin: 0 auto; }}
  header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 18px; }}
  h1 {{ margin: 0; font-size: 20px; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
  .stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; }}
  .stat .label {{ font-size: 11px; text-transform: uppercase; color: var(--muted); }}
  .stat .value {{ font-size: 18px; font-weight: 700; }}
  .filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
  button.filter {{ background: var(--card); color: var(--text); border: 1px solid var(--border); border-radius: 999px; padding: 4px 12px; cursor: pointer; font-size: 12px; }}
  button.filter.active {{ background: #2563eb; border-color: #2563eb; color: #fff; }}
  .finding {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }}
  .finding-header {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }}
  .finding-title {{ font-weight: 600; font-size: 15px; }}
  .badges-right {{ margin-left: auto; display: flex; gap: 6px; }}
  .badge {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; text-decoration: none; }}
  .sev-critical {{ background: var(--crit); color: #fff; }}
  .sev-high, .sev-error {{ background: var(--high); color: #fff; }}
  .sev-medium, .sev-warning {{ background: var(--med); color: #0f172a; }}
  .sev-low, .sev-info, .sev-note, .sev-unspecified {{ background: var(--low); color: #0f172a; }}
  .badge.cwe {{ background: rgba(56, 189, 248, 0.16); color: var(--low); border: 1px solid rgba(56, 189, 248, 0.35); }}
  .badge.conf {{ background: rgba(148, 163, 184, 0.16); color: var(--muted); }}
  .rule-id {{ background: var(--code-bg); padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  .location {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
  .message {{ margin: 6px 0 10px; }}
  .snippet {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; overflow-x: auto; margin-bottom: 10px; }}
  .code-line {{ display: flex; padding: 1px 10px; white-space: pre; }}
  .code-line.highlight {{ background: var(--hl); border-left: 3px solid var(--crit); padding-left: 7px; }}
  .code-line .ln {{ width: 42px; color: var(--muted); user-select: none; text-align: right; padding-right: 12px; flex-shrink: 0; }}
  .trace {{ margin: 8px 0; }}
  .trace summary {{ cursor: pointer; font-weight: 600; font-size: 13px; color: var(--muted); }}
  .trace-list {{ list-style: none; padding-left: 4px; margin: 8px 0 0; }}
  .trace-list li {{ padding: 4px 8px; border-left: 2px solid var(--border); margin-bottom: 4px; font-size: 13px; }}
  .step-num {{ display: inline-block; width: 20px; color: var(--muted); font-weight: 600; }}
  .step-kind {{ font-size: 10px; font-weight: 700; background: rgba(56, 189, 248, 0.15); color: var(--low); padding: 1px 6px; border-radius: 4px; margin-right: 6px; }}
  .step-loc {{ color: var(--muted); font-size: 12px; margin-left: 6px; }}
  .step-code {{ display: block; margin: 3px 0 0 26px; background: var(--code-bg); padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  .suggestion {{ margin-top: 8px; padding: 8px 10px; border-radius: 6px; background: rgba(34, 197, 94, 0.12); border-left: 3px solid var(--ok); font-size: 13px; }}
  .diagnostics {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 16px; margin-top: 18px; }}
  .empty {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; text-align: center; color: var(--muted); }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>PyFlow Security Report &mdash; <code>{esc(doc.engine)}</code></h1>
    <span class="badge conf">Status: {esc(doc.status)}</span>
  </header>
  <section class="summary">
    <div class="stat"><div class="label">Findings</div><div class="value">{len(doc.findings)}</div></div>
    {"".join(f'<div class="stat"><div class="label">{esc(k)}</div><div class="value">{v}</div></div>' for k, v in sev_counts.items())}
  </section>
  <div class="filters">{"".join(filter_buttons)}</div>
  <main>{"".join(cards_html)}</main>
  {diag_html}
</div>
<script>
document.querySelectorAll('button.filter').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('button.filter').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const sev = btn.dataset.sev;
    document.querySelectorAll('article.finding').forEach(el => {{
      el.style.display = (sev === 'all' || el.dataset.severity === sev) ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>"""


__all__ = [
    "RenderedFinding",
    "RenderedFlowStep",
    "RenderedReport",
    "normalize_report_for_render",
    "render_bug_report_html",
    "render_bug_report_markdown",
    "render_bug_report_text",
]
