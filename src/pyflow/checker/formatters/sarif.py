# SPDX-License-Identifier: Apache-2.0
"""SARIF v2.1.0 formatter shared across all PyFlow security engines."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict

from pyflow.util.cwe import cwe_sarif_tags, cwe_url, default_cwe_suggestion, normalize_cwe
from .report_model import (
    PRECISION_DIAGNOSTIC_CODES,
    SecurityFinding,
    SecurityReport,
    read_source_line,
    step_importance,
)
from .utils import issue_sort_key, wrap_file_object

LOG = logging.getLogger(__name__)

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


def severity_level(severity: str | None, *, default: str = "warning") -> str:
    """Normalize checker rankings and SARIF levels at the reporting boundary."""
    levels = {
        "undefined": "none",
        "none": "none",
        "low": "note",
        "note": "note",
        "info": "note",
        "informational": "note",
        "medium": "warning",
        "warning": "warning",
        "high": "error",
        "critical": "error",
        "error": "error",
    }
    return levels.get((severity or "").lower(), default)


def format_rule_help(
    suggestion: str,
    *,
    title: str = "",
    cwe: str | None = None,
    help_uri: str = "",
) -> Dict[str, str]:
    """Build SARIF ``rule.help`` with both plain ``text`` and rich ``markdown`` for IDEs."""
    text = (suggestion or title or "").strip()
    md_parts: list[str] = []
    if suggestion:
        md_parts.append(f"**Remediation:** {suggestion}")
    elif title:
        md_parts.append(title)
    norm_cwe = normalize_cwe(cwe)
    uri = help_uri or cwe_url(norm_cwe)
    if norm_cwe and uri:
        md_parts.append(f"**Reference:** [{norm_cwe}]({uri})")
    elif norm_cwe:
        md_parts.append(f"**Reference:** `{norm_cwe}`")
    elif uri:
        md_parts.append(f"**Reference:** {uri}")
    return {"text": text, "markdown": "\n\n".join(md_parts) or text}


def physical_location(
    uri,
    *,
    line=None,
    column=None,
    end_line=None,
    end_column=None,
    snippet: str | None = None,
    logical_name: str | None = None,
):
    """Build a SARIF location from zero-based source columns."""
    physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
    region: Dict[str, Any] = {}
    if line is not None and line > 0:
        region["startLine"] = line
    if column is not None and column >= 0:
        region["startColumn"] = column + 1
    if end_line is not None and end_line > 0:
        region["endLine"] = end_line
    if end_column is not None and end_column >= 0:
        region["endColumn"] = end_column + 1
    if region and snippet:
        region["snippet"] = {"text": snippet}
    if region:
        physical["region"] = region
    location: Dict[str, Any] = {"physicalLocation": physical}
    if logical_name:
        location["logicalLocations"] = [{"name": logical_name, "kind": "function"}]
    return location


def location_from_span(span, *, snippet: str | None = None, logical_name: str | None = None):
    if not span:
        return None
    return physical_location(
        span.get("uri", ""),
        line=max(int(span.get("start_line") or 1), 1),
        column=max(int(span["start_column"]), 0) if span.get("start_column") is not None else None,
        end_line=int(span["end_line"]) if span.get("end_line") is not None else None,
        end_column=int(span["end_column"]) if span.get("end_column") is not None else None,
        snippet=snippet,
        logical_name=logical_name,
    )


def sarif_document(
    tool_name,
    results,
    *,
    rules=None,
    artifacts=None,
    invocations=None,
    driver_properties=None,
    run_properties=None,
    schema=SARIF_SCHEMA,
    omit_empty_run=False,
):
    """Assemble the shared SARIF envelope without engine or CLI dependencies."""
    results = list(results)
    document = {"$schema": schema, "version": "2.1.0", "runs": []}
    if omit_empty_run and not results:
        return document
    driver = {"name": tool_name, **(driver_properties or {})}
    if rules is not None:
        driver["rules"] = list(rules)
    run = {"tool": {"driver": driver}, "results": results}
    if artifacts is not None:
        run["artifacts"] = list(artifacts)
    if invocations is not None:
        run["invocations"] = list(invocations)
    if run_properties is not None:
        run["properties"] = dict(run_properties)
    document["runs"].append(run)
    return document


def _build_sarif_rule(finding: SecurityFinding) -> Dict[str, Any]:
    short_desc = finding.rule_title or finding.message or finding.rule_id
    tags = list(dict.fromkeys([*cwe_sarif_tags(finding.cwe), "security", *finding.tags]))
    rule_props: Dict[str, Any] = {"tags": tags}
    if finding.extra.get("precision"):
        rule_props["precision"] = finding.extra["precision"]
    rule: Dict[str, Any] = {
        "id": finding.rule_id,
        "name": (finding.rule_title or finding.rule_id)[:80],
        "shortDescription": {"text": short_desc},
        "defaultConfiguration": {"level": severity_level(finding.severity)},
        "properties": rule_props,
    }
    if finding.cwe_url:
        rule["helpUri"] = finding.cwe_url
    if finding.suggestion or short_desc:
        rule["help"] = format_rule_help(
            finding.suggestion,
            title=short_desc,
            cwe=finding.cwe,
            help_uri=finding.cwe_url,
        )
    return rule


def _build_sarif_result(
    finding: SecurityFinding,
    *,
    rule_index: int,
    analysis_status: str,
    artifact_uri: str = "",
) -> Dict[str, Any]:
    uri = finding.uri or finding.sink_uri or finding.source_uri or artifact_uri
    line = max(finding.line or finding.sink_line or finding.source_line or 1, 1)
    locations = []
    if uri or finding.line > 0:
        locations.append(
            physical_location(
                uri,
                line=line,
                column=finding.column,
                end_line=finding.end_line,
                end_column=finding.end_column,
                snippet=read_source_line(uri, line) or None,
                logical_name=finding.procedure or None,
            )
        )

    props: Dict[str, Any] = {
        "confidence": finding.confidence,
        "analysisStatus": analysis_status,
    }
    if finding.procedure:
        props["procedure"] = finding.procedure
    if finding.cwe:
        props["cwe"] = finding.cwe
        props["cwes"] = list(finding.cwes)
    if finding.cwe_url:
        props["cweUrl"] = finding.cwe_url
    if finding.suggestion:
        props["suggestion"] = finding.suggestion
    if finding.sink_name:
        props["sinkName"] = finding.sink_name
    if finding.source_label:
        props["sourceLabel"] = finding.source_label
    if finding.sink_label:
        props["sinkLabel"] = finding.sink_label

    debug_props = finding.debug_dict()
    if debug_props:
        props["debug"] = debug_props

    result: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": severity_level(finding.severity),
        "message": {"text": finding.message or finding.rule_title or finding.rule_id},
        "locations": locations,
        "partialFingerprints": {"pyflow/v1": finding.fingerprint},
        "properties": props,
    }

    thread_locations = []
    for step in finding.steps:
        if step.kind == "ellipsis":
            continue
        step_uri = step.uri or uri or artifact_uri
        if not step_uri and step.line <= 0:
            continue
        step_line = max(step.line, 1)
        loc = physical_location(
            step_uri,
            line=step_line,
            column=step.column,
            snippet=read_source_line(step_uri, step_line) or None,
            logical_name=step.procedure or None,
        )
        loc["message"] = {"text": step.message or step.kind}
        step_props: Dict[str, Any] = {"kind": step.kind}
        if step.debug:
            step_props["debug"] = dict(step.debug)
        loc["properties"] = step_props
        thread_locations.append(
            {
                "location": loc,
                "nestingLevel": step.nesting_level,
                "importance": step.importance or step_importance(step.kind),
            }
        )
    if thread_locations:
        result["codeFlows"] = [{"threadFlows": [{"locations": thread_locations}]}]
    return result


def render_sarif(
    report: SecurityReport,
    *,
    tool_name: str | None = None,
    artifact_uri: str = "",
) -> Dict[str, Any]:
    """Render any canonical :class:`SecurityReport` as SARIF v2.1.0."""
    from pyflow import __version__

    rules: list[Dict[str, Any]] = []
    rule_indexes: dict[str, int] = {}
    results: list[Dict[str, Any]] = []
    artifacts_seen: dict[str, Dict[str, Any]] = {}

    for finding in report.findings:
        if finding.rule_id not in rule_indexes:
            rule_indexes[finding.rule_id] = len(rules)
            rules.append(_build_sarif_rule(finding))
        uri = finding.uri or finding.sink_uri or finding.source_uri or artifact_uri
        if uri and uri not in artifacts_seen:
            artifacts_seen[uri] = {"location": {"uri": uri}}
        results.append(
            _build_sarif_result(
                finding,
                rule_index=rule_indexes[finding.rule_id],
                analysis_status=report.status,
                artifact_uri=artifact_uri,
            )
        )

    invocation_props: Dict[str, Any] = {"analysisStatus": report.status}
    notifications = []
    debug_diagnostics = []
    if report.termination_reason:
        notifications.append({"level": "warning", "message": {"text": report.termination_reason}})
    for diag in report.diagnostics:
        code = str(diag.get("code") or f"{report.engine}-diagnostic")
        if code in PRECISION_DIAGNOSTIC_CODES:
            debug_diagnostics.append(dict(diag))
            continue
        msg = str(diag.get("message") or "").strip()
        if not msg:
            continue
        notif: Dict[str, Any] = {
            "level": "warning" if diag.get("affects_completeness") else "note",
            "message": {"text": msg},
            "descriptor": {"id": code},
        }
        diag_props = {
            k: diag[k]
            for k in ("level", "function", "operation", "filename", "line")
            if diag.get(k) is not None
        }
        if diag_props:
            notif["properties"] = diag_props
        notifications.append(notif)
    if debug_diagnostics:
        invocation_props["debugDiagnostics"] = debug_diagnostics
    if report.statistics:
        invocation_props["statistics"] = dict(report.statistics)
    invocation: Dict[str, Any] = {
        "executionSuccessful": report.status == "complete",
        "properties": invocation_props,
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return sarif_document(
        tool_name or f"pyflow-security-{report.engine}",
        results,
        rules=rules,
        artifacts=list(artifacts_seen.values()) if artifacts_seen else None,
        invocations=[invocation],
        driver_properties={
            "version": __version__,
            "informationUri": "https://pyflow.readthedocs.io/",
        },
    )


# ── Standalone scanner-manager SARIF entrypoints ──────────────────────────


def _map_confidence_to_sarif_properties(confidence: str) -> Dict[str, str]:
    return {"confidence": confidence.lower()}


def _create_sarif_rule(test_id: str, test_name: str, *, cwe: str | None = None) -> Dict[str, Any]:
    norm_cwe = normalize_cwe(cwe)
    uri = cwe_url(norm_cwe) or "https://pyflow.readthedocs.io/"
    rule: Dict[str, Any] = {
        "id": test_id,
        "name": test_name,
        "shortDescription": {"text": f"Security issue detected by {test_id}"},
        "helpUri": uri,
    }
    suggestion = default_cwe_suggestion(norm_cwe)
    if suggestion:
        rule["help"] = format_rule_help(suggestion, cwe=norm_cwe, help_uri=uri)
    if norm_cwe:
        rule["properties"] = {"tags": ["security", *cwe_sarif_tags(norm_cwe)]}
    return rule


def _create_sarif_artifact(file_path: str) -> Dict[str, Any]:
    return {"location": {"uri": file_path}}


def _create_sarif_location(issue) -> Dict[str, Any]:
    return physical_location(
        issue.fname,
        line=issue.lineno,
        column=issue.col_offset,
        end_column=(
            issue.end_col_offset if issue.end_col_offset and issue.end_col_offset > 0 else None
        ),
    )


def _create_sarif_result(issue) -> Dict[str, Any]:
    result = {
        "ruleId": issue.test_id,
        "message": {"text": issue.text},
        "level": severity_level(issue.severity),
        "locations": [_create_sarif_location(issue)],
        "properties": _map_confidence_to_sarif_properties(issue.confidence),
    }
    if getattr(issue, "related_rules", None):
        result["properties"]["relatedRules"] = issue.related_rules
        result["properties"]["vulnerabilityFamily"] = issue.vulnerability_family
    if issue.cwe and issue.cwe.id != 0:
        result["properties"]["cwe"] = {"id": issue.cwe.id, "url": issue.cwe.link()}
        suggestion = default_cwe_suggestion(issue.cwe.id)
        if suggestion:
            result["properties"]["suggestion"] = suggestion
    return result


def _collect_unique_rules_and_artifacts(
    issues,
) -> tuple[Dict[str, Dict], Dict[str, Dict]]:
    rules = {}
    artifacts = {}
    for issue in issues:
        rule_key = issue.test_id
        if rule_key not in rules:
            issue_cwe = (
                normalize_cwe(issue.cwe.id)
                if getattr(issue, "cwe", None) and getattr(issue.cwe, "id", 0) != 0
                else None
            )
            rules[rule_key] = _create_sarif_rule(issue.test_id, issue.test, cwe=issue_cwe)
        artifact_key = issue.fname
        if artifact_key not in artifacts:
            artifacts[artifact_key] = _create_sarif_artifact(issue.fname)
    return dict(sorted(rules.items())), dict(sorted(artifacts.items()))


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Write SARIF output for a standalone scanner manager."""
    del lines
    results = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    if not isinstance(results, list):
        issues = [item for group in results.values() for item in group]
    else:
        issues = results
    issues = sorted(issues, key=issue_sort_key)

    rules, artifacts = _collect_unique_rules_and_artifacts(issues)
    from pyflow import __version__

    errors = (
        list(manager.get_errors())
        if hasattr(manager, "get_errors")
        else [
            {"filename": filename, "reason": reason}
            for filename, reason in getattr(manager, "get_skipped", lambda: ())()
        ]
    )
    sarif_output = sarif_document(
        "PyFlow",
        [_create_sarif_result(issue) for issue in issues],
        rules=rules.values(),
        artifacts=artifacts.values(),
        driver_properties={
            "version": __version__,
            "informationUri": "https://pyflow.readthedocs.io/",
        },
        invocations=[
            {
                "executionSuccessful": not errors,
                "properties": {"analysisStatus": "partial" if errors else "complete"},
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": item["reason"]}} for item in errors
                ],
            }
        ],
        schema="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        omit_empty_run=not errors,
    )
    rendered = json.dumps(sarif_output, indent=2, separators=(",", ": "), ensure_ascii=False)
    writer = wrap_file_object(fileobj)
    writer.write(rendered)
    if writer is not fileobj and hasattr(writer, "flush"):
        writer.flush()
    if hasattr(fileobj, "name") and fileobj.name != sys.stdout.name:
        LOG.info("SARIF output written to file: %s", fileobj.name)
