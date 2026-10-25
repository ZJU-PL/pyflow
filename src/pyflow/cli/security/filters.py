"""Engine-independent filtering, baselines, and JSON report projection."""

from __future__ import annotations

from dataclasses import replace
from copy import copy, deepcopy
from functools import cached_property
import json
from pathlib import Path

from pyflow.checker.common import constants
from pyflow.checker.formatters.security import security_json
from pyflow.checker.formatters.utils import issue_report
from pyflow.util.cwe import normalize_cwe
from pyflow.checker.common.overlaps import fold_overlapping_issues

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


def rule_ids(values) -> frozenset[str]:
    from pyflow.frontend.file_selection import exclusion_patterns

    if isinstance(values, str):
        values = [values]
    flattened = [
        item for group in values or () for item in (group if isinstance(group, list) else [group])
    ]
    return frozenset(exclusion_patterns(flattened))


def normalize_finding(finding: dict) -> dict:
    location = finding.get("primary_location") or finding.get("location") or {}
    filename = (
        location.get("uri")
        or location.get("filename")
        or finding.get("filename")
        or finding.get("sink_filename")
        or ""
    )
    line = (
        location.get("start_line")
        or location.get("line")
        or finding.get("line_number")
        or finding.get("sink_line")
        or finding.get("line")
    )
    severity = str(finding.get("severity") or finding.get("issue_severity") or "medium").lower()
    severity = {"warning": "medium", "error": "high", "note": "low"}.get(severity, severity)
    confidence = (
        finding.get("confidence_level")
        or finding.get("confidence")
        or finding.get("issue_confidence")
        or "medium"
    )
    if isinstance(confidence, (int, float)):
        confidence = "high" if confidence >= 0.85 else "medium" if confidence >= 0.6 else "low"
    return {
        "rule_id": finding.get("rule_id") or finding.get("test_id") or "PYFLOW-IFDS",
        "rule_title": finding.get("rule_title")
        or finding.get("rule", {}).get("name")
        or finding.get("test_name")
        or "",
        "severity": severity,
        "confidence": str(confidence).lower(),
        "message": finding.get("message")
        or finding.get("issue_text")
        or finding.get("text")
        or finding.get("sink_label")
        or finding.get("sink_name")
        or finding.get("kind")
        or "Security finding",
        "location": {"filename": filename, "line": line},
        "cwe": normalize_cwe(finding.get("cwe") or finding.get("issue_cwe", {}).get("id")),
        "properties": finding,
    }


def _identity(finding):
    normalized = normalize_finding(finding)
    location = normalized["location"]
    return normalized["rule_id"], location["filename"], location["line"]


def load_baseline(path):
    if path is None:
        return frozenset()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON report object")
    findings = data.get("findings", data.get("results"))
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ValueError("baseline must contain a findings or results array")
    identities = {_identity(item) for item in findings}
    for item in findings:
        rule, filename, line = _identity(item)
        properties = item.get("properties") or item
        identities.update(
            (related["rule_id"], filename, line) for related in properties.get("related_rules", ())
        )
    return frozenset(identities)


def _accept(finding, args, baseline):
    item = normalize_finding(finding)
    excluded = rule_ids(getattr(args, "skip_rule", ()))
    if item["rule_id"] in excluded or item["rule_title"] in excluded:
        return False
    if (
        SEVERITY_RANK.get(item["severity"], 0)
        < SEVERITY_RANK[getattr(args, "severity", "low").lower()]
    ):
        return False
    if (
        CONFIDENCE_RANK.get(item["confidence"], 0)
        < CONFIDENCE_RANK[getattr(args, "confidence", "low").lower()]
    ):
        return False
    return _identity(finding) not in baseline


class FilteredScannerResult:
    def __init__(self, manager, args, baseline):
        self.manager, self.args, self.baseline = manager, args, baseline

    def __getattr__(self, name):
        return getattr(self.manager, name)

    def _filtered_raw(self, sev_level=constants.LOW, conf_level=constants.LOW):
        return [
            issue
            for issue in self.manager.get_issue_list(sev_level, conf_level)
            if _accept(
                {
                    "test_id": issue.test_id,
                    "test_name": issue.test,
                    "issue_severity": issue.severity,
                    "issue_confidence": issue.confidence,
                    "filename": issue.fname,
                    "line_number": issue.lineno,
                },
                self.args,
                self.baseline,
            )
        ]

    def get_issue_list(self, sev_level=constants.LOW, conf_level=constants.LOW):
        issues = self._filtered_raw(sev_level, conf_level)
        return (
            issues
            if getattr(self.args, "no_deduplicate", False)
            else fold_overlapping_issues(issues)
        )

    @cached_property
    def metrics(self):
        metrics = deepcopy(self.manager.metrics)
        totals = metrics.data["_totals"]
        for key in totals:
            if key.startswith(("SEVERITY.", "CONFIDENCE.")):
                totals[key] = 0
        reported = self.get_issue_list()
        for issue in reported:
            for criterion, level in (
                ("SEVERITY", issue.severity),
                ("CONFIDENCE", issue.confidence),
            ):
                key = f"{criterion}.{level}"
                totals[key] = totals.get(key, 0) + 1
        totals["raw_findings"] = len(self.manager.get_issue_list())
        totals["folded_findings"] = len(self._filtered_raw()) - len(reported)
        if hasattr(metrics, "issues"):
            metrics.issues = len(reported)
        for attribute, criterion in (
            ("issues_by_severity", "SEVERITY"),
            ("issues_by_confidence", "CONFIDENCE"),
        ):
            if hasattr(metrics, attribute):
                setattr(
                    metrics,
                    attribute,
                    {
                        key.split(".", 1)[1]: value
                        for key, value in totals.items()
                        if key.startswith(criterion + ".")
                    },
                )
        return metrics

    def results_count(self, *args, **kwargs):
        return len(self.get_issue_list(*args, **kwargs))


def _fold_taint_findings(findings):
    """Fold equivalent sink reports across packs, retaining rule provenance."""
    grouped = {}
    for finding in sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(normalize_finding(item)["severity"], 0),
            normalize_finding(item)["rule_id"],
        ),
    ):
        normalized = normalize_finding(finding)
        location = normalized["location"]
        sink = finding.get("sink_name") or finding.get("sink_label")
        if not sink:
            sink = (finding.get("properties") or {}).get("sink_name")
        key = (
            location["filename"],
            location["line"],
            sink,
            normalized["cwe"],
        )
        # Missing identities must not collapse unrelated findings.
        if not all((location["filename"], location["line"], sink)):
            key += (id(finding),)
        representative = grouped.setdefault(key, {**finding, "related_rules": []})
        related = {
            "rule_id": normalized["rule_id"],
            "rule_title": normalized["rule_title"],
            "severity": normalized["severity"],
        }
        if related not in representative["related_rules"]:
            representative["related_rules"].append(related)
    return list(grouped.values())


def filter_report(engine, result, args, baseline):
    if engine == "ast-scanner":
        return FilteredScannerResult(result, args, baseline)
    if engine == "ast-dataflow":
        report = security_json(engine, result)
        accepted = [item for item in report["findings"] if _accept(item, args, baseline)]
        if not getattr(args, "no_deduplicate", False):
            accepted = _fold_taint_findings(accepted)
        result = copy(result)
        if getattr(result, "analysis_result", None) is not None:
            originals = {
                (
                    item.rule_id,
                    item.filename,
                    item.sink_line,
                    item.sink_name,
                    item.cwe,
                    tuple(sorted(item.source_kinds)),
                ): item
                for item in result.analysis_result.findings
            }
            result.analysis_result = replace(
                result.analysis_result,
                findings=tuple(
                    replace(
                        originals[
                            (
                                item["rule_id"],
                                item["filename"],
                                item["sink_line"],
                                item["sink_name"],
                                item["cwe"],
                                tuple(sorted(item["source_kinds"])),
                            )
                        ],
                        related_rules=tuple(
                            (rule["rule_id"], rule["rule_title"], rule["severity"])
                            for rule in item.get("related_rules", ())
                        ),
                    )
                    for item in accepted
                ),
                statistics={
                    **result.analysis_result.statistics,
                    "raw_findings": len(report["findings"]),
                    "reported_findings": len(accepted),
                },
            )
            from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector

            result.results = ASTDataflowTaintDetector().issues_from_result(result.analysis_result)
        return FilteredScannerResult(result, args, baseline)
    result = dict(result)
    result["findings"] = [
        item for item in result.get("findings", ()) if _accept(item, args, baseline)
    ]
    if not getattr(args, "no_deduplicate", False):
        result["findings"] = _fold_taint_findings(result["findings"])
    result["statistics"] = {
        **result.get("statistics", {}),
        "reported_findings": len(result["findings"]),
    }
    if "entry_results" in result:
        result["entry_results"] = [
            filter_report(engine, item, args, baseline) for item in result["entry_results"]
        ]
    return result


def unified_report(engine, result):
    if engine == "ast-scanner":
        report = issue_report(result, constants.LOW, constants.LOW)
        findings = report["results"]
        status = "partial" if report["errors"] else "complete"
        errors, statistics = report["errors"], report["metrics"].get("_totals", {})
        diagnostics = errors
    else:
        report = security_json(engine, result)
        findings = report.get("findings", ())
        status = report.get("status", "complete")
        diagnostics = [
            (
                {
                    "code": item.get("code", "analysis-diagnostic"),
                    "message": item.get("message") or item.get("reason", ""),
                    **item,
                }
                if isinstance(item, dict)
                else {
                    "code": "analysis-diagnostic",
                    "message": str(item),
                    "affects_completeness": status != "complete",
                }
            )
            for item in report.get("diagnostics", [])
        ]
        errors = [
            item
            for item in diagnostics
            if isinstance(item, dict) and item.get("affects_completeness")
        ]
        statistics = report.get("statistics", {})
    normalized_findings = [normalize_finding(item) for item in findings]
    for finding in normalized_findings:
        filename = finding["location"]["filename"]
        if filename and not filename.startswith("<") and "://" not in filename:
            finding["location"]["filename"] = str(Path(filename).resolve())
    return {
        "schema_version": 1,
        "engine": engine,
        "status": status,
        "findings": normalized_findings,
        "errors": errors,
        "diagnostics": diagnostics,
        "statistics": statistics,
    }


def has_failing_findings(engine, result, args):
    threshold = getattr(args, "fail_on", None)
    if threshold == "none":
        return False
    if engine in {"ast-scanner", "ast-dataflow"}:
        severities = (item.severity for item in result.get_issue_list())
    else:
        severities = (item.get("severity", "medium") for item in result.get("findings", ()))
    return any(
        SEVERITY_RANK.get(str(severity).lower(), 0) >= SEVERITY_RANK[threshold or "low"]
        for severity in severities
    )
