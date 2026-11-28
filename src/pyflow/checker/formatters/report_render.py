"""Unified bug report renderers consuming :class:`SecurityReport`.

Supports all human-oriented and tabular/line-oriented output formats uniformly
across every PyFlow security engine (``ast-scanner``, ``ast-dataflow``,
``ifds``, and ``cpg``):

- ``text`` / ``screen``: structured findings with source snippets, sink caret
  underlines, indented Source -> Sink witness traces, CWEs, and remediation tips.
- ``markdown``: GitHub-Flavored Markdown for PR reviews and CI summaries.
- ``html``: self-contained XSS-safe interactive audit report with severity filters.
- ``custom``, ``csv``, ``xml``, ``yaml``: line-oriented and structured exports.
"""

from __future__ import annotations

import csv
import html as html_lib
import io
import os
from pathlib import Path
import re
import string
from typing import Any, Mapping, Sequence
from xml.etree import ElementTree as ET

from .custom import SafeMapper
from .report_model import (
    FlowStep,
    PRECISION_DIAGNOSTIC_CODES,
    SecurityFinding,
    SecurityReport,
    build_security_report,
    read_source_line,
    read_source_lines,
)

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

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _coerce_report(
    report: SecurityReport | Mapping[str, Any], engine: str | None = None
) -> SecurityReport:
    if isinstance(report, SecurityReport):
        return report
    return build_security_report(engine or str(report.get("engine") or "ifds"), report)


def _expand_call_span(source_line: str, idx: int, token_len: int) -> tuple[int, int]:
    """Expand a matched sink token to cover dotted receiver and single-line call args."""
    start = idx
    while start > 0 and (source_line[start - 1].isalnum() or source_line[start - 1] in "_."):
        start -= 1
    while start < idx and source_line[start] == ".":
        start += 1
    end = idx + token_len
    if end < len(source_line) and source_line[end] == "(":
        depth = 0
        pos = end
        while pos < len(source_line):
            ch = source_line[pos]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
            pos += 1
    return start, max(1, end - start)


def _expand_call_from_start(source_line: str, col: int) -> tuple[int, int]:
    end = col
    while end < len(source_line) and (source_line[end].isalnum() or source_line[end] in "_."):
        end += 1
    if end < len(source_line) and source_line[end] == "(":
        depth = 0
        pos = end
        while pos < len(source_line):
            ch = source_line[pos]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
            pos += 1
    return col, max(1, end - col)


def _find_token_in_segment(segment: str, hint_token: str) -> tuple[int, int] | None:
    for needle in (hint_token, hint_token.rsplit(".", 1)[-1]):
        if not needle:
            continue
        match = re.search(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])", segment)
        if match is not None:
            return match.start(), len(needle)
    return None


def _caret_span(
    source_line: str,
    column: int | None,
    end_column: int | None,
    hint_token: str = "",
) -> tuple[int, int] | None:
    """Return 0-based (start, length) caret highlight span on *source_line*."""
    if not source_line.strip():
        return None
    if column is not None and 0 <= column < len(source_line):
        if hint_token:
            rest = source_line[column:]
            rest_stripped = rest.lstrip()
            is_compound_stmt = rest_stripped.startswith(
                ("return ", "await ", "yield ", "with ", "async with ")
            )
            has_assignment = "=" in rest and not rest_stripped.startswith(("==", "!="))
            if is_compound_stmt or has_assignment:
                found = _find_token_in_segment(rest, hint_token)
                if found is not None and found[0] > 0:
                    return _expand_call_span(source_line, column + found[0], found[1])
        if end_column is not None and end_column > column:
            length = min(end_column - column, len(source_line) - column)
            return column, max(length, 1)
        return _expand_call_from_start(source_line, column)
    if hint_token:
        found = _find_token_in_segment(source_line, hint_token)
        if found is not None:
            return _expand_call_span(source_line, found[0], found[1])
    stripped = source_line.lstrip()
    leading = len(source_line) - len(stripped)
    return leading, max(1, min(len(stripped), 40))


def _resolve_base_dir(doc: SecurityReport, base_dir: str | Path | None) -> Path | None:
    if base_dir is not None:
        try:
            resolved = Path(base_dir).resolve()
            return resolved if resolved.is_dir() else resolved.parent
        except OSError:
            return None
    abs_dirs: list[str] = []
    for finding in doc.findings:
        for candidate in (finding.uri, finding.source_uri, finding.sink_uri):
            if candidate and os.path.isabs(candidate) and not candidate.startswith("<"):
                try:
                    abs_dirs.append(str(Path(candidate).resolve().parent))
                except OSError:
                    continue
        for step in finding.steps:
            if step.uri and os.path.isabs(step.uri) and not step.uri.startswith("<"):
                try:
                    abs_dirs.append(str(Path(step.uri).resolve().parent))
                except OSError:
                    continue
    if not abs_dirs:
        return None
    try:
        common = Path(os.path.commonpath(abs_dirs))
    except ValueError:
        return None
    if len(common.parts) <= 1:
        return None
    return common


def _display_uri(uri: str, base_dir: Path | None) -> str:
    if not uri or uri.startswith("<") or "://" in uri or base_dir is None:
        return uri
    if not os.path.isabs(uri):
        return uri
    try:
        return Path(uri).resolve().relative_to(base_dir).as_posix()
    except (OSError, ValueError):
        return uri


def _relativize_text(text: str, base_dir: Path | None) -> str:
    if not text or base_dir is None:
        return text
    prefix = str(base_dir)
    if not prefix or prefix == os.sep:
        return text
    text = text.replace(prefix + os.sep, "")
    return text.replace(prefix, ".")


def _format_location(
    uri: str,
    line: int,
    column: int | None = None,
    *,
    base_dir: Path | None = None,
) -> str:
    if line <= 0:
        return "<source location unavailable>"
    display_uri = _display_uri(uri, base_dir) or "<unknown source>"
    if column is not None and column >= 0:
        return f"{display_uri}:{line}:{column + 1}"
    return f"{display_uri}:{line}"


_UNKNOWN_CALL_RE = re.compile(r"Unknown call(?: effects for)?\s+([^\s]+)", re.IGNORECASE)


def _visible_diagnostics(
    diagnostics: Sequence[Mapping[str, Any]], *, verbose: bool = False
) -> list[Mapping[str, Any]]:
    """Hide engine-internal precision/over-approximation diagnostics unless *verbose*."""
    if verbose:
        return list(diagnostics)
    return [
        diag
        for diag in diagnostics
        if str(diag.get("code") or "") not in PRECISION_DIAGNOSTIC_CODES
    ]


_SUMMARY_CATEGORY_LABELS = {
    "unknown-call-effect": "unmodeled calls (taint conservatively preserved)",
    "cpg-unknown-call-effect": "unmodeled calls (taint conservatively preserved)",
    "ambiguous-call-target": "ambiguous local call targets",
    "exception-prefix-overapproximation": "conservative exception-edge joins",
    "context-manager-exit-effects": "conservative context-manager __exit__ effects",
    "finally-abrupt-outcome-overapproximation": "conservative finally-block abrupt outcomes",
    "cpg-expression-call-summary": "conservative nested-call summaries",
    "cpg-loop-convergence-threshold": (
        "loops exceeded convergence-reporting threshold (continued to convergence)"
    ),
    "container-clear-alias-unknown": "conservative container-clear alias checks",
}


def _humanize_diagnostic(
    diag: Mapping[str, Any], *, verbose: bool = False, base_dir: Path | None = None
) -> str:
    code = str(diag.get("code") or "")
    raw_msg = str(diag.get("message") or "").strip()
    if not raw_msg:
        return raw_msg
    if verbose:
        return _relativize_text(raw_msg, base_dir)
    if code in {"unknown-call-effect", "cpg-unknown-call-effect"}:
        match = _UNKNOWN_CALL_RE.search(raw_msg)
        callee = match.group(1) if match else "external call"
        return f"Unmodeled call '{callee}' — taint conservatively preserved"
    if code == "cpg-expression-call-summary":
        return (
            "Nested local call used a conservative summary "
            "(some side effects may be over-approximated)"
        )
    return _relativize_text(raw_msg, base_dir)


def _group_diagnostics(
    diagnostics: Sequence[Mapping[str, Any]],
    *,
    engine: str,
    base_dir: Path | None = None,
    verbose: bool = False,
) -> list[tuple[str, str, list[str]]]:
    filtered = _visible_diagnostics(diagnostics, verbose=verbose)
    if not filtered:
        return []
    grouped: dict[tuple[str, str], list[str]] = {}
    for diag in filtered:
        code = str(diag.get("code") or f"{engine}-diagnostic")
        msg = _humanize_diagnostic(diag, verbose=verbose, base_dir=base_dir)
        loc = ""
        if diag.get("filename") or diag.get("line"):
            uri = _display_uri(str(diag.get("filename") or "<unknown>"), base_dir)
            line = diag.get("line") or 0
            loc = f"{uri}:{line}" if line else uri
        grouped.setdefault((code, msg), []).append(loc)
    return [(code, msg, locs) for (code, msg), locs in grouped.items()]


def _style(text: str, code: str, *, color: bool) -> str:
    if not color or code not in _ANSI:
        return text
    return f"{_ANSI[code]}{text}{_ANSI['reset']}"


def _severity_color(severity: str) -> str:
    sev = severity.lower()
    if sev in {"critical", "high"}:
        return "bold_red"
    if sev == "medium":
        return "bold_yellow"
    return "cyan"


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
        "branch": "BRANCH",
        "ellipsis": "...",
    }
    return mapping.get(kind.lower(), kind.upper()[:10] or "FLOW")


def _severity_counts(findings: Sequence[SecurityFinding]) -> dict[str, int]:
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
    lines = read_source_lines(uri)
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
    steps: Sequence[FlowStep],
    *,
    indent: str = "       ",
    color: bool = False,
    base_dir: Path | None = None,
) -> list[str]:
    if not steps:
        return []
    out = [indent + _style("Flow:", "bold", color=color)]
    for idx, step in enumerate(steps, 1):
        nest = "  " * min(max(step.nesting_level, 0), 6)
        badge = _style(f"[{_step_badge(step.kind)}]", "cyan", color=color)
        loc_part = ""
        if step.line > 0:
            loc_str = _format_location(step.uri, step.line, base_dir=base_dir)
            loc_part = f" {_style(loc_str, 'dim', color=color)}"
        out.append(f"{indent}  {nest}{idx}. {badge} {step.message}{loc_part}")
        code_line = read_source_line(step.uri, step.line)
        if code_line:
            out.append(f"{indent}     {nest}| {code_line[:110]}")
    return out


def render_bug_report_text(
    report: SecurityReport | Mapping[str, Any],
    *,
    engine: str | None = None,
    color: bool = False,
    verbose: bool = False,
    context_lines: int = 1,
    base_dir: str | Path | None = None,
) -> str:
    """Render a unified plain-text or ANSI-colored bug report for any engine."""
    doc = _coerce_report(report, engine)
    resolved_base = _resolve_base_dir(doc, base_dir)
    lines: list[str] = []

    sev_counts = _severity_counts(doc.findings)
    breakdown = ", ".join(f"{k}: {v}" for k, v in sev_counts.items())
    summary_suffix = f" ({breakdown})" if breakdown else ""
    lines.append(
        f"Engine: {doc.engine}  Status: {doc.status}  "
        f"Findings: {len(doc.findings)}{summary_suffix}"
    )
    if doc.entry:
        lines.append(f"Entry: {_display_uri(doc.entry, resolved_base)}")
    if doc.termination_reason:
        lines.append(
            _style(
                f"Notice: {_relativize_text(doc.termination_reason, resolved_base)}",
                "yellow",
                color=color,
            )
        )

    if not doc.findings:
        lines.append("No security findings.")
    else:
        lines.append("")

    for index, finding in enumerate(doc.findings, 1):
        sev_col = _severity_color(finding.severity)
        cwe_badge = f" ({finding.cwe})" if finding.cwe else ""
        title = finding.rule_title or finding.message
        header_rule = _style(f"[{finding.rule_id}]", "bold", color=color)
        lines.append(f"  [{index}] {header_rule} {title}{cwe_badge}")

        meta_parts = [f"Severity: {_style(finding.severity, sev_col, color=color)}"]
        if verbose and finding.confidence_score is not None:
            filled = max(0, min(10, int(finding.confidence_score * 10)))
            bar = "█" * filled + "░" * (10 - filled)
            meta_parts.append(
                f"Confidence: {finding.confidence_score:.0%} [{bar}] ({finding.confidence.upper()})"
            )
        elif finding.confidence:
            meta_parts.append(f"Confidence: {finding.confidence}")
        lines.append("       " + "  ".join(meta_parts))

        loc_str = _format_location(
            finding.uri, finding.line, finding.column, base_dir=resolved_base
        )
        proc_suffix = f"  Function: {finding.procedure}" if finding.procedure else ""
        lines.append(f"       Location: {loc_str}{proc_suffix}")

        if finding.source_label or finding.sink_label:
            src_pos = _format_location(
                finding.source_uri, finding.source_line, base_dir=resolved_base
            )
            snk_pos = _format_location(finding.sink_uri, finding.sink_line, base_dir=resolved_base)
            lines.append(f"       Source: {finding.source_label or 'unknown'} ({src_pos})")
            lines.append(f"       Sink:   {finding.sink_label or 'unknown'} ({snk_pos})")
        else:
            if finding.message and finding.message != title:
                lines.append(f"       Detail: {finding.message}")
            if finding.sink_name:
                sink_parts = [f"Sink: {finding.sink_name}"]
                if verbose and finding.source_kinds:
                    sink_parts.append(f"Sources: {', '.join(finding.source_kinds)}")
                if verbose and finding.tainted_arguments:
                    sink_parts.append(f"Tainted args: {', '.join(finding.tainted_arguments)}")
                lines.append("       " + "  ".join(sink_parts))

        lines.extend(
            _render_snippet_lines(
                finding.uri,
                finding.line,
                column=finding.column,
                end_column=finding.end_column,
                hint_token=finding.sink_name or finding.sink_label,
                context_lines=context_lines,
                indent="       ",
                color=color,
            )
        )
        lines.extend(
            _render_flow_text(finding.steps, indent="       ", color=color, base_dir=resolved_base)
        )
        if finding.suggestion:
            lines.append(
                f"       {_style('Suggestion:', 'green', color=color)} {finding.suggestion}"
            )
        if verbose and finding.related_rules:
            lines.append(f"       Related rules: {', '.join(finding.related_rules)}")
        if verbose and finding.precision_reasons:
            lines.append(f"       Notes: {', '.join(finding.precision_reasons)}")
        lines.append("")

    grouped_diags = _group_diagnostics(
        doc.diagnostics, engine=doc.engine, base_dir=resolved_base, verbose=verbose
    )
    if grouped_diags:
        lines.append(_style("Diagnostics:", "bold", color=color))
        for code, msg, locs in grouped_diags:
            if len(locs) > 1:
                lines.append(f"  [{code}] {msg} ({len(locs)} occurrences)")
            else:
                loc_suffix = f" ({locs[0]})" if locs and locs[0] else ""
                lines.append(f"  [{code}] {msg}{loc_suffix}")

    if verbose and doc.statistics:
        lines.append("")
        lines.append(_style("Statistics:", "dim", color=color))
        for key, value in sorted(doc.statistics.items()):
            lines.append(f"  {key}: {value}")

    return "\n".join(lines).rstrip()


def render_bug_report_markdown(
    report: SecurityReport | Mapping[str, Any],
    *,
    engine: str | None = None,
    base_dir: str | Path | None = None,
    verbose: bool = False,
) -> str:
    """Render a GitHub-Flavored Markdown bug report."""
    doc = _coerce_report(report, engine)
    resolved_base = _resolve_base_dir(doc, base_dir)
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
        lines.append(f"| Entry | `{_display_uri(doc.entry, resolved_base)}` |")
    if sev_counts:
        summary = ", ".join(f"`{k}`: {v}" for k, v in sev_counts.items())
        lines.append(f"| By Severity | {summary} |")
    if doc.termination_reason:
        lines.extend(
            ["", f"> [!WARNING]\n> {_relativize_text(doc.termination_reason, resolved_base)}"]
        )

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
                meta.append(
                    f"**CWE:** [{finding.cwe}]({finding.cwe_url})"
                    if finding.cwe_url
                    else f"**CWE:** `{finding.cwe}`"
                )
            loc_md = _format_location(
                finding.uri, finding.line, finding.column, base_dir=resolved_base
            )
            meta.append(f"**Location:** `{loc_md}`")
            if finding.procedure:
                meta.append(f"**Function:** `{finding.procedure}`")
            lines.append("- " + " | ".join(meta))
            if finding.message and finding.message != title:
                lines.append(f"- **Details:** {finding.message}")
            if finding.source_label or finding.sink_label:
                src_pos = _format_location(
                    finding.source_uri, finding.source_line, base_dir=resolved_base
                )
                snk_pos = _format_location(
                    finding.sink_uri, finding.sink_line, base_dir=resolved_base
                )
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
                hint_token=finding.sink_name or finding.sink_label,
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
                    loc = (
                        _format_location(step.uri, step.line, base_dir=resolved_base)
                        if step.line > 0
                        else "-"
                    )
                    code_cell = read_source_line(step.uri, step.line).replace("|", "\\|")
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

    grouped_md_diags = _group_diagnostics(
        doc.diagnostics, engine=doc.engine, base_dir=resolved_base, verbose=verbose
    )
    if grouped_md_diags:
        lines.extend(["## Diagnostics", ""])
        for code, msg, locs in grouped_md_diags:
            if len(locs) > 1:
                lines.append(f"- `{code}`: {msg} ({len(locs)} occurrences)")
            else:
                loc_suffix = f" (`{locs[0]}`)" if locs and locs[0] else ""
                lines.append(f"- `{code}`: {msg}{loc_suffix}")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_bug_report_html(
    report: SecurityReport | Mapping[str, Any],
    *,
    engine: str | None = None,
    base_dir: str | Path | None = None,
    verbose: bool = False,
) -> str:
    """Render a self-contained, XSS-safe HTML5 interactive bug report."""
    doc = _coerce_report(report, engine)
    resolved_base = _resolve_base_dir(doc, base_dir)
    sev_counts = _severity_counts(doc.findings)
    esc = html_lib.escape

    cards_html: list[str] = []
    for index, finding in enumerate(doc.findings, 1):
        sev_key = finding.severity.lower()
        cwe_html = ""
        if finding.cwe:
            if finding.cwe_url:
                cwe_html = (
                    f'<a class="badge cwe" href="{esc(finding.cwe_url)}" target="_blank" '
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
        loc_text = _format_location(
            finding.uri, finding.line, finding.column, base_dir=resolved_base
        )

        endpoint_html = ""
        if finding.source_label or finding.sink_label:
            src_pos = _format_location(
                finding.source_uri, finding.source_line, base_dir=resolved_base
            )
            snk_pos = _format_location(finding.sink_uri, finding.sink_line, base_dir=resolved_base)
            endpoint_html = (
                f'<div class="location">Endpoint: <code>{esc(finding.source_label or "source")}</code> '
                f"({esc(src_pos)}) &rarr; <code>{esc(finding.sink_label or 'sink')}</code> "
                f"({esc(snk_pos)})</div>"
            )

        snippet_html = ""
        source_lines = read_source_lines(finding.uri)
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
                step_loc = (
                    _format_location(step.uri, step.line, base_dir=resolved_base)
                    if step.line > 0
                    else ""
                )
                step_code = read_source_line(step.uri, step.line)
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
            f"{endpoint_html}{msg_html}{snippet_html}{trace_html}{suggestion_html}"
            f"</article>"
        )

    if not cards_html:
        cards_html.append('<div class="empty">No security findings reported.</div>')

    diag_html = ""
    grouped_diags = _group_diagnostics(
        doc.diagnostics, engine=doc.engine, base_dir=resolved_base, verbose=verbose
    )
    if grouped_diags:
        items_list = []
        for code, msg, locs in grouped_diags:
            if len(locs) > 1:
                suffix = f" ({len(locs)} occurrences)"
            elif locs and locs[0]:
                suffix = f" (<code>{esc(locs[0])}</code>)"
            else:
                suffix = ""
            items_list.append(f"<li><code>{esc(code)}</code>: {esc(msg)}{suffix}</li>")
        diag_html = (
            f'<section class="diagnostics"><h2>Diagnostics</h2>'
            f'<ul>{"".join(items_list)}</ul></section>'
        )

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


def render_bug_report_custom(
    report: SecurityReport | Mapping[str, Any],
    *,
    engine: str | None = None,
    template: str | None = None,
) -> str:
    """Render findings with a user-supplied format template string."""
    doc = _coerce_report(report, engine)
    tmpl = template or "{abspath}:{line}: {test_id} [{severity}] {msg}"
    try:
        parsed = list(string.Formatter().parse(tmpl))
        string.Formatter().vformat(tmpl, (), SafeMapper(line=0))
    except ValueError as error:
        raise ValueError(f"Template is not in valid format: {error}") from error
    if not any(field_name is not None for _, field_name, _, _ in parsed):
        raise ValueError("No tags were found in the template. Are you missing '{}'?")

    rows: list[str] = []
    for finding in doc.findings:
        filename = finding.uri or ""
        values = SafeMapper(
            abspath=os.path.abspath(filename) if filename else "",
            relpath=os.path.relpath(filename) if filename else "",
            line=finding.line,
            col=finding.column or 0,
            end_col=finding.end_column or 0,
            test_id=finding.rule_id,
            rule_id=finding.rule_id,
            severity=finding.severity,
            msg=finding.message,
            confidence=finding.confidence,
            range=finding.line,
            cwe=finding.cwe or "",
            suggestion=finding.suggestion,
            procedure=finding.procedure,
        )
        rows.append(tmpl.format_map(values))
    return "\n".join(rows)


def render_bug_report_csv(
    report: SecurityReport | Mapping[str, Any], *, engine: str | None = None
) -> str:
    """Render findings as RFC 4180 CSV."""
    doc = _coerce_report(report, engine)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "filename",
            "line",
            "column",
            "rule_id",
            "severity",
            "confidence",
            "cwe",
            "procedure",
            "message",
            "suggestion",
        ]
    )
    for finding in doc.findings:
        writer.writerow(
            [
                finding.uri,
                finding.line,
                "" if finding.column is None else finding.column + 1,
                finding.rule_id,
                finding.severity,
                finding.confidence,
                finding.cwe or "",
                finding.procedure,
                finding.message,
                finding.suggestion,
            ]
        )
    return buf.getvalue().rstrip("\r\n")


def render_bug_report_xml(
    report: SecurityReport | Mapping[str, Any], *, engine: str | None = None
) -> str:
    """Render findings as JUnit-compatible XML."""
    doc = _coerce_report(report, engine)
    suite = ET.Element(
        "testsuite",
        attrib={
            "name": f"pyflow-security-{doc.engine}",
            "tests": str(len(doc.findings)),
            "failures": str(len(doc.findings)),
            "status": doc.status,
        },
    )
    for finding in doc.findings:
        tc = ET.SubElement(
            suite,
            "testcase",
            attrib={
                "classname": finding.uri or "<unknown>",
                "name": f"{finding.rule_id}:{finding.line}",
            },
        )
        err = ET.SubElement(
            tc,
            "error",
            attrib={
                "type": finding.severity,
                "message": finding.message,
            },
        )
        details = [f"Location: {finding.uri}:{finding.line}"]
        if finding.cwe:
            details.append(f"CWE: {finding.cwe}")
        if finding.suggestion:
            details.append(f"Suggestion: {finding.suggestion}")
        err.text = "\n".join(details)
    return ET.tostring(suite, encoding="unicode")


def render_bug_report_yaml(
    report: SecurityReport | Mapping[str, Any], *, engine: str | None = None
) -> str:
    """Render the canonical report dict as YAML."""
    import yaml

    doc = _coerce_report(report, engine)
    return yaml.safe_dump(doc.to_dict(), sort_keys=False, allow_unicode=True).rstrip()


__all__ = [
    "render_bug_report_csv",
    "render_bug_report_custom",
    "render_bug_report_html",
    "render_bug_report_markdown",
    "render_bug_report_text",
    "render_bug_report_xml",
    "render_bug_report_yaml",
]
