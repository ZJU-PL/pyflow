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
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from pyflow.util.cwe import default_cwe_for_rule_id, default_cwe_suggestion, normalize_cwe

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
    """Expand from *col* over a dotted identifier/call expression on *source_line*."""
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
    """Locate *hint_token* (or its terminal attribute name) at a word boundary in *segment*."""
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
    if column is not None and column >= 0 and column < len(source_line):
        slice_end = (
            min(end_column, len(source_line))
            if end_column is not None and end_column > column
            else len(source_line)
        )
        segment = source_line[column:slice_end]
        # Narrow whole-statement spans (e.g. "return cur.execute(q)",
        # "with open(path) as f:", "resp = requests.get(url)", or multiline
        # assignments where end_column belongs to a later line) to the actual
        # sink call expression when the hint token appears on the line.
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


def _resolve_base_dir(doc: RenderedReport, base_dir: str | Path | None) -> Path | None:
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
    # Avoid collapsing against filesystem root or top-level temp folders alone.
    if len(common.parts) <= 1:
        return None
    return common


def _display_uri(uri: str, base_dir: Path | None) -> str:
    if not uri or uri.startswith("<") or "://" in uri or base_dir is None:
        return uri
    if not os.path.isabs(uri):
        return uri
    try:
        rel = Path(uri).resolve().relative_to(base_dir)
        return rel.as_posix()
    except (OSError, ValueError):
        return uri


def _format_location(
    uri: str,
    line: int,
    column: int | None = None,
    *,
    base_dir: Path | None = None,
) -> str:
    if not uri and line <= 0:
        return "<source location unavailable>"
    if line <= 0:
        return "<source location unavailable>"
    display_uri = _display_uri(uri, base_dir) or "<unknown source>"
    if column is not None and column >= 0:
        return f"{display_uri}:{line}:{column + 1}"
    return f"{display_uri}:{line}"


_UNKNOWN_CALL_RE = re.compile(
    r"Unknown call(?: effects for)?\s+([^\s]+)",
    re.IGNORECASE,
)


def _relativize_text(text: str, base_dir: Path | None) -> str:
    if not text or base_dir is None:
        return text
    prefix = str(base_dir)
    if not prefix or prefix == os.sep:
        return text
    text = text.replace(prefix + os.sep, "")
    text = text.replace(prefix, ".")
    return text


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


_SUMMARY_DIAGNOSTIC_CODES = frozenset(
    {
        "unknown-call-effect",
        "cpg-unknown-call-effect",
        "ambiguous-call-target",
        "exception-prefix-overapproximation",
        "context-manager-exit-effects",
        "finally-abrupt-outcome-overapproximation",
        "cpg-expression-call-summary",
        "cpg-loop-convergence-threshold",
        "container-clear-alias-unknown",
    }
)

_SUMMARY_CATEGORY_LABELS = {
    "unknown-call-effect": "unmodeled calls (taint conservatively preserved)",
    "cpg-unknown-call-effect": "unmodeled calls (taint conservatively preserved)",
    "ambiguous-call-target": "ambiguous local call targets",
    "exception-prefix-overapproximation": "conservative exception-edge joins",
    "context-manager-exit-effects": "conservative context-manager __exit__ effects",
    "finally-abrupt-outcome-overapproximation": "conservative finally-block abrupt outcomes",
    "cpg-expression-call-summary": "conservative nested-call summaries",
    "cpg-loop-convergence-threshold": "loops exceeded convergence-reporting threshold (continued to convergence)",
    "container-clear-alias-unknown": "conservative container-clear alias checks",
}


def _group_diagnostics(
    diagnostics: Sequence[Mapping[str, Any]],
    *,
    engine: str,
    base_dir: Path | None = None,
    verbose: bool = False,
) -> list[tuple[str, str, list[str]]]:
    if not verbose and len(diagnostics) > 5:
        important: dict[tuple[str, str], list[str]] = {}
        summarized_counts: dict[str, int] = {}
        summarized_examples: dict[str, list[str]] = {}
        for diag in diagnostics:
            code = str(diag.get("code") or f"{engine}-diagnostic")
            raw_msg = str(diag.get("message") or "").strip()
            if code in _SUMMARY_DIAGNOSTIC_CODES:
                summarized_counts[code] = summarized_counts.get(code, 0) + 1
                ex = summarized_examples.setdefault(code, [])
                if len(ex) < 3:
                    match = _UNKNOWN_CALL_RE.search(raw_msg)
                    token = match.group(1) if match else ""
                    if not token and "'" in raw_msg:
                        parts = raw_msg.split("'")
                        if len(parts) >= 2 and parts[1]:
                            token = parts[1]
                    if token and token != "<dynamic>" and token not in ex:
                        ex.append(token)
                continue
            msg = _humanize_diagnostic(diag, verbose=False, base_dir=base_dir)
            loc = ""
            if diag.get("filename") or diag.get("line"):
                uri = _display_uri(str(diag.get("filename") or "<unknown>"), base_dir)
                line = diag.get("line") or 0
                loc = f"{uri}:{line}" if line else uri
            important.setdefault((code, msg), []).append(loc)

        out: list[tuple[str, str, list[str]]] = [
            (code, msg, locs) for (code, msg), locs in important.items()
        ]
        for code in sorted(summarized_counts):
            count = summarized_counts[code]
            label = _SUMMARY_CATEGORY_LABELS.get(code, code)
            examples = summarized_examples.get(code) or []
            ex_suffix = f" (e.g. {', '.join(examples)})" if examples else ""
            out.append((code, f"{count} {label}{ex_suffix}", [""]))
        if summarized_counts:
            out.append(("hint", "Re-run with --verbose to list all individual diagnostics", [""]))
        return out

    grouped: dict[tuple[str, str], list[str]] = {}
    for diag in diagnostics:
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
    if sev in {"critical", "high", "error"}:
        return "bold_red"
    if sev in {"medium", "warning"}:
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
            raw_steps: list[RenderedFlowStep] = []
            for step in item.get("trace") or ():
                op = str(step.get("operation") or "flow")
                msg = str(
                    step.get("detail") or step.get("location") or step.get("operation") or "flow"
                )
                step_uri = str(step.get("filename") or item.get("filename") or "")
                step_line = int(step.get("line") or 0)
                step_nest = int(step.get("nesting_level") or 0)
                # Merge redundant same-line assign immediately following source/call.
                if (
                    raw_steps
                    and op == "assign"
                    and raw_steps[-1].uri == step_uri
                    and raw_steps[-1].line == step_line
                    and raw_steps[-1].kind in {"source", "call"}
                    and raw_steps[-1].nesting_level == step_nest
                ):
                    loc_var = str(step.get("location") or "")
                    if (
                        loc_var
                        and not loc_var.startswith("(")
                        and f"'{loc_var}'" not in raw_steps[-1].message
                    ):
                        prev = raw_steps[-1]
                        raw_steps[-1] = RenderedFlowStep(
                            kind=prev.kind,
                            message=f"{prev.message} -> '{loc_var}'",
                            uri=prev.uri,
                            line=prev.line,
                            column=prev.column,
                            procedure=prev.procedure,
                            nesting_level=prev.nesting_level,
                        )
                    continue
                raw_steps.append(
                    RenderedFlowStep(
                        kind=op,
                        message=msg,
                        uri=step_uri,
                        line=step_line,
                        column=step.get("column"),
                        procedure=str(step.get("procedure") or ""),
                        nesting_level=step_nest,
                    )
                )
            steps = tuple(raw_steps)
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
            rule_id = str(item.get("rule_id") or "PYFLOW-AST-DATAFLOW")
            cwe = normalize_cwe(item.get("cwe")) or default_cwe_for_rule_id(rule_id)
            rendered_findings.append(
                RenderedFinding(
                    rule_id=rule_id,
                    rule_title=rule_title,
                    message=rule_title or f"Tainted data reaches {sink_name}",
                    severity=str(item.get("severity") or "medium"),
                    confidence=str(item.get("confidence") or "HIGH"),
                    uri=str(item.get("filename") or ""),
                    line=int(item.get("sink_line") or 0),
                    column=item.get("sink_column"),
                    end_column=item.get("sink_end_column"),
                    procedure=str(item.get("function") or ""),
                    cwe=cwe,
                    suggestion=str(item.get("suggestion") or default_cwe_suggestion(cwe)),
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
            cwe = normalize_cwe(item.get("cwe")) or default_cwe_for_rule_id(rule_id)
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
                    cwe=cwe,
                    suggestion=str(item.get("suggestion") or default_cwe_suggestion(cwe)),
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
            cwe = normalize_cwe(item.get("cwe")) or default_cwe_for_rule_id(rule_id)
            suggestion = str(
                item.get("suggestion") or rule_obj.get("help_text") or default_cwe_suggestion(cwe)
            )
            steps = tuple(
                RenderedFlowStep(
                    kind=str(step.get("kind") or "flow"),
                    message=str(step.get("label") or step.get("kind") or "flow"),
                    uri=str(step.get("filename") or sink_uri or source_uri),
                    line=int(step.get("line") or 0),
                    column=step.get("column"),
                    procedure=str(step.get("procedure") or ""),
                    nesting_level=int(step.get("nesting_level") or 0),
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
                    procedure=str(item.get("procedure") or ""),
                    cwe=cwe,
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
            rule_id = str(item.get("test_id") or item.get("rule_id") or "PYFLOW-AST")
            cwe = normalize_cwe(cwe_val) or default_cwe_for_rule_id(rule_id)
            rendered_findings.append(
                RenderedFinding(
                    rule_id=rule_id,
                    rule_title=str(item.get("test_name") or item.get("rule_title") or ""),
                    message=str(item.get("text") or item.get("message") or "Security issue"),
                    severity=str(item.get("severity") or "medium"),
                    confidence=str(item.get("confidence") or "medium"),
                    uri=str(item.get("filename") or ""),
                    line=int(item.get("line") or item.get("line_number") or 0),
                    cwe=cwe,
                    suggestion=default_cwe_suggestion(cwe),
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
    base_dir: str | Path | None = None,
) -> str:
    """Render a structured, user-friendly plain-text or ANSI-colored bug report."""
    doc = normalize_report_for_render(engine, report)
    resolved_base = _resolve_base_dir(doc, base_dir)
    lines: list[str] = []

    if engine == "ifds":
        lines.append(f"Entry: {doc.entry or '<unknown>'}")
        lines.append(f"Status: {doc.status}")
        lines.append(f"Findings: {len(doc.findings)}")
    else:
        lines.append(f"Status: {doc.status}")

    if doc.termination_reason:
        lines.append(
            _style(
                f"Notice: {_relativize_text(doc.termination_reason, resolved_base)}",
                "yellow",
                color=color,
            )
        )

    sev_counts = _severity_counts(doc.findings)
    if not doc.findings:
        if engine == "cpg":
            lines.append("No security findings.")
        elif engine != "ifds":
            lines.append("No issues found.")
    else:
        breakdown = ", ".join(f"{k}: {v}" for k, v in sev_counts.items())
        if engine == "ifds":
            lines.append(f"Summary: {breakdown}")
            lines.append("")
        elif engine == "cpg":
            lines.append(f"\n{len(doc.findings)} security finding(s) ({breakdown}):\n")
        else:
            lines.append(f"Found {len(doc.findings)} issue(s) ({breakdown}):\n")

    for index, finding in enumerate(doc.findings, 1):
        sev_col = _severity_color(finding.severity)
        cwe_badge = f" ({finding.cwe})" if finding.cwe else ""
        title = finding.rule_title or finding.message
        header_rule = _style(f"[{finding.rule_id}]", "bold", color=color)
        lines.append(f"  [{index}] {header_rule} {title}{cwe_badge}")

        # Unified metadata block across IFDS, AST-dataflow, CPG, and AST-scanner
        meta_parts = [f"Severity: {_style(finding.severity, sev_col, color=color)}"]
        if finding.confidence_score is not None:
            filled = max(0, min(10, int(finding.confidence_score * 10)))
            bar = "█" * filled + "░" * (10 - filled)
            conf_tag = f" ({finding.confidence})" if finding.confidence else ""
            meta_parts.append(f"Confidence: {finding.confidence_score:.0%} [{bar}]{conf_tag}")
        elif finding.confidence:
            meta_parts.append(f"Confidence: {finding.confidence}")
        lines.append("       " + "  ".join(meta_parts))

        if engine == "cpg":
            if finding.line > 0:
                loc_str = _format_location(
                    finding.uri, finding.line, finding.column, base_dir=resolved_base
                )
                proc_suffix = f"  Function: {finding.procedure}" if finding.procedure else ""
                lines.append(f"       Location: {loc_str}{proc_suffix}")
            src_pos = (
                _format_location(finding.source_uri, finding.source_line, base_dir=resolved_base)
                if finding.source_line > 0
                else "<source location unavailable>"
            )
            snk_pos = (
                _format_location(finding.sink_uri, finding.sink_line, base_dir=resolved_base)
                if finding.sink_line > 0
                else "<source location unavailable>"
            )
            lines.append(f"       Source: {finding.source_label or 'unknown'} ({src_pos})")
            lines.append(f"       Sink:   {finding.sink_label or 'unknown'} ({snk_pos})")
        else:
            loc_str = _format_location(
                finding.uri,
                finding.line,
                finding.column if engine == "ast-dataflow" else None,
                base_dir=resolved_base,
            )
            proc_suffix = f"  Function: {finding.procedure}" if finding.procedure else ""
            lines.append(f"       Location: {loc_str}{proc_suffix}")
            if finding.message and finding.message != title:
                lines.append(f"       Detail: {finding.message}")
            if finding.sink_name:
                sink_parts = [f"Sink: {finding.sink_name}"]
                if finding.source_kinds:
                    sink_parts.append(f"Sources: {', '.join(finding.source_kinds)}")
                if finding.tainted_arguments:
                    sink_parts.append(f"Tainted args: {', '.join(finding.tainted_arguments)}")
                lines.append("       " + "  ".join(sink_parts))

        lines.extend(
            _render_snippet_lines(
                finding.uri,
                finding.line,
                column=finding.column,
                end_column=finding.end_column,
                hint_token=finding.sink_name,
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
        if finding.related_rules:
            lines.append(f"       Related rules: {', '.join(finding.related_rules)}")
        if finding.precision_reasons:
            lines.append(f"       Notes: {', '.join(finding.precision_reasons)}")
        lines.append("")

    if doc.diagnostics:
        lines.append(_style("Diagnostics:", "bold", color=color))
        for code, msg, locs in _group_diagnostics(
            doc.diagnostics, engine=engine, base_dir=resolved_base, verbose=verbose
        ):
            count = len(locs)
            if count > 1:
                lines.append(f"  [{code}] {msg} ({count} occurrences)")
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
    engine: str,
    report: Mapping[str, Any],
    *,
    base_dir: str | Path | None = None,
) -> str:
    """Render a GitHub-Flavored Markdown bug report suitable for PR comments & reviews."""
    doc = normalize_report_for_render(engine, report)
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
                    loc = (
                        _format_location(step.uri, step.line, base_dir=resolved_base)
                        if step.line > 0
                        else "-"
                    )
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
        for code, msg, locs in _group_diagnostics(
            doc.diagnostics, engine=engine, base_dir=resolved_base, verbose=False
        ):
            if len(locs) > 1:
                lines.append(f"- `{code}`: {msg} ({len(locs)} occurrences)")
            else:
                loc_suffix = f" (`{locs[0]}`)" if locs and locs[0] else ""
                lines.append(f"- `{code}`: {msg}{loc_suffix}")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_bug_report_html(
    engine: str,
    report: Mapping[str, Any],
    *,
    base_dir: str | Path | None = None,
) -> str:
    """Render a self-contained, XSS-safe HTML5 interactive bug report."""
    doc = normalize_report_for_render(engine, report)
    resolved_base = _resolve_base_dir(doc, base_dir)
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
        loc_text = _format_location(
            finding.uri, finding.line, finding.column, base_dir=resolved_base
        )

        endpoint_html = ""
        if finding.source_label or finding.sink_label:
            src_pos = _format_location(
                finding.source_uri, finding.source_line, base_dir=resolved_base
            )
            snk_pos = _format_location(finding.sink_uri, finding.sink_line, base_dir=resolved_base)
            src_label_esc = esc(finding.source_label or "source")
            snk_label_esc = esc(finding.sink_label or "sink")
            endpoint_html = (
                f'<div class="location">Endpoint: <code>{src_label_esc}</code> '
                f"({esc(src_pos)}) &rarr; <code>{snk_label_esc}</code> "
                f"({esc(snk_pos)})</div>"
            )

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
                step_loc = (
                    _format_location(step.uri, step.line, base_dir=resolved_base)
                    if step.line > 0
                    else ""
                )
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
            f"{endpoint_html}{msg_html}{snippet_html}{trace_html}{suggestion_html}"
            f"</article>"
        )

    if not cards_html:
        cards_html.append('<div class="empty">No security findings reported.</div>')

    diag_html = ""
    if doc.diagnostics:
        grouped_diags = _group_diagnostics(
            doc.diagnostics, engine=engine, base_dir=resolved_base, verbose=False
        )
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


__all__ = [
    "RenderedFinding",
    "RenderedFlowStep",
    "RenderedReport",
    "normalize_report_for_render",
    "render_bug_report_html",
    "render_bug_report_markdown",
    "render_bug_report_text",
]
