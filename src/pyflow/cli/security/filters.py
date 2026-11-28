"""Engine-independent filtering, folding, and baselining over :class:`SecurityReport`."""

from __future__ import annotations

from dataclasses import replace
import json
from typing import Any, Sequence

from pyflow.checker.common import constants
from pyflow.checker.common.overlaps import fold_overlapping_issues
from pyflow.checker.formatters.report_model import (
    SecurityFinding,
    SecurityReport,
    build_security_report,
    resolve_uri,
)

SEVERITY_RANK = {
    "undefined": 0,
    "info": 1,
    "note": 1,
    "low": 1,
    "warning": 2,
    "medium": 2,
    "error": 3,
    "high": 3,
    "critical": 4,
}
CONFIDENCE_RANK = {"undefined": 0, "low": 1, "medium": 2, "high": 3}

_GENERIC_RULE_PREFIXES = (
    "PYFLOW-INJECTION-",
    "PYFLOW-SQL-",
    "PYFLOW-XML-",
    "PYFLOW-SERIALIZATION-",
    "PYFLOW-NETWORK-",
    "PYFLOW-REQUESTS-",
    "PYFLOW-NOSQL-",
)


def rule_ids(values) -> frozenset[str]:
    from pyflow.frontend.file_selection import exclusion_patterns

    if isinstance(values, str):
        values = [values]
    flattened = [
        item for group in values or () for item in (group if isinstance(group, list) else [group])
    ]
    return frozenset(exclusion_patterns(flattened))


def _finding_identity(finding: SecurityFinding) -> tuple[str, str, int]:
    return (
        finding.rule_id,
        resolve_uri(finding.uri) if finding.uri else "",
        int(finding.line or 0),
    )


def load_baseline(path) -> frozenset[tuple[str, str, int]]:
    """Load suppressed finding identities from a canonical JSON report."""
    if path is None:
        return frozenset()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON report object")
    findings = data.get("findings")
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ValueError("baseline must contain a findings array")
    identities: set[tuple[str, str, int]] = set()
    for item in findings:
        loc = item.get("location") if isinstance(item.get("location"), dict) else {}
        filename = resolve_uri(str(loc.get("filename") or "")) if loc.get("filename") else ""
        line = int(loc.get("line") or 0)
        rule_id = str(item.get("rule_id") or "")
        if rule_id:
            identities.add((rule_id, filename, line))
        debug = item.get("debug") if isinstance(item.get("debug"), dict) else {}
        for related in item.get("related_rules") or debug.get("related_rules") or ():
            rel_id = related.get("rule_id") if isinstance(related, dict) else str(related or "")
            if rel_id:
                identities.add((rel_id, filename, line))
    return frozenset(identities)


def _accept(finding: SecurityFinding, args, baseline: frozenset[tuple[str, str, int]]) -> bool:
    excluded = rule_ids(getattr(args, "skip_rule", ()))
    if finding.rule_id in excluded or finding.rule_title in excluded:
        return False
    min_sev = SEVERITY_RANK[getattr(args, "severity", "low").lower()]
    if SEVERITY_RANK.get(finding.severity, 0) < min_sev:
        return False
    min_conf = CONFIDENCE_RANK[getattr(args, "confidence", "low").lower()]
    if CONFIDENCE_RANK.get(finding.confidence, 0) < min_conf:
        return False
    return _finding_identity(finding) not in baseline


def _rule_pack_priority(rule_id: str, sink_name: str) -> tuple[int, str]:
    """Rank overlapping rules so sink-matching and stdlib/core packs win over unrelated frameworks."""
    upper = rule_id.upper()
    sink_root = (sink_name or "").split(".", 1)[0].upper()
    if sink_root and upper.startswith(f"PYFLOW-{sink_root}-"):
        return (0, rule_id)
    if upper.startswith("PYFLOW-STDLIB-"):
        return (1, rule_id)
    if any(upper.startswith(prefix) for prefix in _GENERIC_RULE_PREFIXES):
        return (2, rule_id)
    return (3, rule_id)


def _fold_findings(findings: Sequence[SecurityFinding]) -> list[SecurityFinding]:
    """Fold equivalent sink reports across rule packs while preserving related rule provenance."""
    grouped: dict[tuple[Any, ...], SecurityFinding] = {}
    ordered = sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            0 if item.cwe else 1,
            _rule_pack_priority(item.rule_id, item.sink_name or item.sink_label),
        ),
    )
    for finding in ordered:
        sink = finding.sink_name or finding.sink_label
        resolved_uri = resolve_uri(finding.uri) if finding.uri else ""
        if resolved_uri and finding.line > 0 and sink:
            key: tuple[Any, ...] = (resolved_uri, finding.line, sink, finding.cwe)
        else:
            key = (id(finding),)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = finding
        else:
            related = list(existing.related_rules)
            for candidate in (finding.rule_id, *finding.related_rules):
                if candidate and candidate != existing.rule_id and candidate not in related:
                    related.append(candidate)
            grouped[key] = replace(existing, related_rules=tuple(related))
    return list(grouped.values())


def _severity_confidence_totals(
    base_stats: dict[str, Any],
    findings: Sequence[SecurityFinding],
    *,
    raw_count: int,
    filtered_count: int,
) -> dict[str, Any]:
    stats = dict(base_stats)
    for key in list(stats):
        if key.startswith(("SEVERITY.", "CONFIDENCE.")):
            stats[key] = 0
    for finding in findings:
        sev_key = f"SEVERITY.{finding.severity.upper()}"
        conf_key = f"CONFIDENCE.{finding.confidence.upper()}"
        stats[sev_key] = stats.get(sev_key, 0) + 1
        stats[conf_key] = stats.get(conf_key, 0) + 1
    stats["raw_findings"] = raw_count
    stats["folded_findings"] = filtered_count - len(findings)
    stats["reported_findings"] = len(findings)
    return stats


def _filter_ast_scanner_manager(manager, args, baseline) -> SecurityReport:
    """Filter AST-scanner issues before overlap folding so AST node-level spans are preserved."""
    raw_issues = list(manager.get_issue_list(constants.LOW, constants.LOW))
    excluded = rule_ids(getattr(args, "skip_rule", ()))
    min_sev = SEVERITY_RANK[getattr(args, "severity", "low").lower()]
    min_conf = CONFIDENCE_RANK[getattr(args, "confidence", "low").lower()]

    filtered_issues = []
    for issue in raw_issues:
        rid = str(getattr(issue, "test_id", "") or "")
        title = str(getattr(issue, "test", "") or "")
        if rid in excluded or title in excluded:
            continue
        sev = str(getattr(issue, "severity", "medium") or "medium").lower()
        conf = str(getattr(issue, "confidence", "medium") or "medium").lower()
        if SEVERITY_RANK.get(sev, 0) < min_sev or CONFIDENCE_RANK.get(conf, 0) < min_conf:
            continue
        uri = resolve_uri(str(getattr(issue, "fname", "") or ""))
        line = int(getattr(issue, "lineno", 0) or 0)
        if (rid, uri, line) in baseline:
            continue
        filtered_issues.append(issue)

    folded_issues = (
        filtered_issues
        if getattr(args, "no_deduplicate", False)
        else fold_overlapping_issues(filtered_issues)
    )
    # Build canonical report from folded issues while preserving scanner errors & metrics.
    base_report = build_security_report("ast-scanner", manager)
    folded_report = build_security_report(
        "ast-scanner",
        _IssueListView(folded_issues, manager),
    )
    stats = _severity_confidence_totals(
        dict(base_report.statistics),
        folded_report.findings,
        raw_count=len(raw_issues),
        filtered_count=len(filtered_issues),
    )
    return replace(
        folded_report,
        diagnostics=base_report.diagnostics,
        status=base_report.status,
        statistics=stats,
    )


class _IssueListView:
    """Tiny adapter letting ``build_security_report`` read a pre-filtered scanner issue list."""

    def __init__(self, issues, manager):
        self._issues = issues
        self._manager = manager

    def get_issue_list(self, *_args, **_kwargs):
        return self._issues

    def get_errors(self):
        return (
            self._manager.get_errors()
            if hasattr(self._manager, "get_errors")
            else [
                {"filename": fn, "reason": reason}
                for fn, reason in getattr(self._manager, "get_skipped", lambda: ())()
            ]
        )

    @property
    def metrics(self):
        return getattr(self._manager, "metrics", None)


def filter_report(engine: str, result: Any, args, baseline) -> SecurityReport:
    """Normalize, filter, fold, and baseline any engine result into a :class:`SecurityReport`."""
    if (
        engine == "ast-scanner"
        and not isinstance(result, SecurityReport)
        and hasattr(result, "get_issue_list")
    ):
        return _filter_ast_scanner_manager(result, args, baseline)

    doc = build_security_report(engine, result)
    raw_count = len(doc.findings)
    accepted = [finding for finding in doc.findings if _accept(finding, args, baseline)]
    folded = accepted if getattr(args, "no_deduplicate", False) else _fold_findings(accepted)
    stats = _severity_confidence_totals(
        dict(doc.statistics),
        folded,
        raw_count=raw_count,
        filtered_count=len(accepted),
    )
    return replace(doc, findings=tuple(folded), statistics=stats)


def has_failing_findings(report: SecurityReport, args) -> bool:
    threshold = getattr(args, "fail_on", None)
    if threshold == "none":
        return False
    min_rank = SEVERITY_RANK[threshold or "low"]
    return any(SEVERITY_RANK.get(finding.severity, 0) >= min_rank for finding in report.findings)
