"""Rendering of typed security reports from AST, IFDS, and CPG engines."""

import hashlib
from typing import Any, Dict, List

from pyflow.checker.common import constants as b_constants
from pyflow.checker.common.diagnostics import diagnostics_to_dicts
from pyflow.util.cwe import (
    cwe_ancestors,
    cwe_identifiers,
    cwe_sarif_tags,
    cwe_url,
    default_cwe_for_rule_id,
    default_cwe_suggestion,
    normalize_cwe,
)
from .report_render import (
    _single_source_line,
    render_bug_report_html,
    render_bug_report_markdown,
    render_bug_report_text,
)
from .sarif import (
    format_rule_help,
    location_from_span,
    physical_location,
    sarif_document,
    severity_level,
    step_importance,
)


def _fingerprint(*parts: object) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def security_text(
    engine: str,
    result,
    *,
    color: bool = False,
    verbose: bool = False,
    context_lines: int = 1,
    base_dir=None,
) -> str:
    """Format analysis results as user-friendly plain text or ANSI-colored terminal text."""
    if engine == "ast-scanner":
        return render_bug_report_text(
            engine,
            security_json(engine, result),
            color=color,
            verbose=verbose,
            context_lines=context_lines,
            base_dir=base_dir,
        )
    if engine == "ast-dataflow":
        report = ast_dataflow_report(result) if not isinstance(result, dict) else result
        return render_bug_report_text(
            engine,
            report,
            color=color,
            verbose=verbose,
            context_lines=context_lines,
            base_dir=base_dir,
        )
    if engine in {"ifds", "cpg"}:
        return render_bug_report_text(
            engine,
            result,
            color=color,
            verbose=verbose,
            context_lines=context_lines,
            base_dir=base_dir,
        )
    return ""


def security_markdown(engine: str, result, *, base_dir=None) -> str:
    """Format analysis results as GitHub-Flavored Markdown."""
    report = security_json(engine, result) if not isinstance(result, dict) else result
    return render_bug_report_markdown(engine, report, base_dir=base_dir)


def security_html(engine: str, result, *, base_dir=None) -> str:
    """Format analysis results as a standalone interactive HTML bug report."""
    report = security_json(engine, result) if not isinstance(result, dict) else result
    return render_bug_report_html(engine, report, base_dir=base_dir)


def security_json(engine: str, result) -> Any:
    """Normalize engine results to a JSON-compatible structure."""
    if engine == "ast-scanner":
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        return {
            "engine": "ast-scanner",
            "results": [
                {
                    "test_id": iss.test_id,
                    "text": iss.text,
                    "severity": iss.severity,
                    "confidence": iss.confidence,
                    "filename": iss.fname,
                    "line": iss.lineno,
                    "issue_cwe": iss.cwe.as_dict(),
                    "cwe": normalize_cwe(iss.cwe.id),
                    "cwe_url": cwe_url(iss.cwe.id) or None,
                    "cwes": list(cwe_identifiers(iss.cwe.id)),
                    "cwe_ancestors": list(cwe_ancestors(iss.cwe.id)),
                    "suggestion": default_cwe_suggestion(iss.cwe.id) or None,
                }
                for iss in issues
            ],
        }
    if engine == "ast-dataflow":
        return ast_dataflow_report(result)
    if engine == "ifds":
        return {"engine": "ifds", **result}
    if engine == "cpg":
        return result
    return {}


def ast_dataflow_report(manager) -> Dict[str, Any]:
    analysis = getattr(manager, "analysis_result", None)
    if analysis is None:
        return {
            "engine": "ast-dataflow",
            "status": "failed",
            "findings": [],
            "diagnostics": [
                {
                    "code": "ast-dataflow-missing-result",
                    "message": "AST dataflow analysis did not produce a typed result",
                    "affects_completeness": True,
                    "function": None,
                }
            ],
            "statistics": {},
        }
    return {
        "engine": "ast-dataflow",
        "status": analysis.status,
        "findings": [
            {
                "function": finding.function,
                "filename": finding.filename,
                "sink_name": finding.sink_name,
                "sink_line": finding.sink_line,
                "sink_column": getattr(finding, "sink_column", None),
                "sink_end_column": getattr(finding, "sink_end_column", None),
                "source_kinds": sorted(finding.source_kinds),
                "rule_id": finding.rule_id,
                "rule_title": finding.rule_title,
                "severity": finding.severity,
                "cwe": finding.cwe,
                "cwe_url": cwe_url(finding.cwe or default_cwe_for_rule_id(finding.rule_id)) or None,
                "cwes": list(
                    cwe_identifiers(finding.cwe or default_cwe_for_rule_id(finding.rule_id))
                ),
                "cwe_ancestors": list(
                    cwe_ancestors(finding.cwe or default_cwe_for_rule_id(finding.rule_id))
                ),
                "suggestion": (
                    finding.suggestion
                    or default_cwe_suggestion(
                        finding.cwe or default_cwe_for_rule_id(finding.rule_id)
                    )
                    or None
                ),
                "confidence": finding.confidence,
                "precision_reasons": list(finding.precision_reasons),
                "related_rules": [
                    {"rule_id": rule_id, "rule_title": title, "severity": severity}
                    for rule_id, title, severity in finding.related_rules
                ],
                "trace": [
                    {
                        "operation": step.operation,
                        "location": step.location,
                        "filename": step.filename,
                        "line": step.line,
                        "column": getattr(step, "column", None),
                        "detail": step.detail,
                        "procedure": getattr(step, "procedure", ""),
                        "nesting_level": int(getattr(step, "nesting_level", 0) or 0),
                    }
                    for step in finding.trace
                ],
            }
            for finding in analysis.findings
        ],
        "diagnostics": diagnostics_to_dicts(analysis.diagnostics),
        "statistics": dict(analysis.statistics),
    }


def security_sarif(engine: str, result, *, artifact_uri: str = "") -> Dict[str, Any]:
    """Convert engine results to SARIF v2.1.0 format."""
    if engine == "ast-dataflow":
        report = ast_dataflow_report(result)
        rules: List[Dict[str, Any]] = []
        rule_indexes: Dict[str, int] = {}
        sarif_results: List[Dict[str, Any]] = []
        for finding in report["findings"]:
            rule_id = finding["rule_id"]
            effective_cwe = normalize_cwe(finding.get("cwe")) or default_cwe_for_rule_id(rule_id)
            help_uri = cwe_url(effective_cwe)
            suggestion = finding.get("suggestion") or default_cwe_suggestion(effective_cwe)
            if rule_id not in rule_indexes:
                rule_indexes[rule_id] = len(rules)
                rule_entry: Dict[str, Any] = {
                    "id": rule_id,
                    "shortDescription": {"text": finding["rule_title"]},
                    "help": format_rule_help(
                        suggestion,
                        title=finding["rule_title"],
                        cwe=effective_cwe,
                        help_uri=help_uri,
                    ),
                }
                if help_uri:
                    rule_entry["helpUri"] = help_uri
                if effective_cwe:
                    rule_entry["properties"] = {
                        "tags": [*cwe_sarif_tags(effective_cwe), "security", "taint"]
                    }
                rules.append(rule_entry)
            sink_line = finding["sink_line"] or 1
            sink_loc = physical_location(
                finding["filename"],
                line=sink_line,
                column=finding.get("sink_column"),
                end_column=finding.get("sink_end_column"),
                snippet=_single_source_line(finding["filename"], sink_line) or None,
                logical_name=finding.get("function") or None,
            )
            result_props: Dict[str, Any] = {
                "sourceKinds": finding["source_kinds"],
                "confidence": finding["confidence"],
                "precisionReasons": finding["precision_reasons"],
                "analysisStatus": report["status"],
            }
            if finding.get("function"):
                result_props["procedure"] = finding["function"]
            if effective_cwe:
                result_props["cwe"] = effective_cwe
            if help_uri:
                result_props["cweUrl"] = help_uri
            if suggestion:
                result_props["suggestion"] = suggestion
            related = [
                r["rule_id"]
                for r in finding.get("related_rules", ())
                if isinstance(r, dict) and r.get("rule_id") and r.get("rule_id") != rule_id
            ]
            if related:
                result_props["relatedRules"] = related

            tf_locs = []
            for step in finding.get("trace", []):
                step_uri = step.get("filename") or finding["filename"]
                step_line = step.get("line") or 1
                tf_locs.append(
                    {
                        "location": {
                            "message": {"text": (step.get("detail") or step["operation"])},
                            **physical_location(
                                step_uri,
                                line=step_line,
                                column=step.get("column"),
                                snippet=_single_source_line(step_uri, step_line) or None,
                                logical_name=step.get("procedure") or None,
                            ),
                        },
                        "nestingLevel": int(step.get("nesting_level") or 0),
                        "importance": step_importance(step.get("operation")),
                    }
                )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_indexes[rule_id],
                    "level": severity_level(finding.get("severity")),
                    "message": {"text": f"Tainted data reaches {finding['sink_name']}"},
                    "locations": [sink_loc],
                    "partialFingerprints": {
                        "pyflow/v1": _fingerprint(
                            rule_id,
                            finding["filename"],
                            finding["sink_line"],
                            finding["sink_name"],
                            ",".join(finding["source_kinds"]),
                        )
                    },
                    "properties": result_props,
                    "codeFlows": ([{"threadFlows": [{"locations": tf_locs}]}] if tf_locs else []),
                }
            )
        return sarif_document(
            "pyflow-security-ast-dataflow",
            sarif_results,
            rules=rules,
            invocations=[
                {
                    "executionSuccessful": report["status"] == "complete",
                    "properties": {"analysisStatus": report["status"]},
                }
            ],
        )

    if engine == "ifds":
        findings = result.get("findings", [])
        rules: List[Dict[str, Any]] = []
        rule_indexes: Dict[str, int] = {}
        sarif_results: List[Dict[str, Any]] = []

        for finding in findings:
            rule_id = finding.get("rule_id") or "PYFLOW-IFDS"
            effective_cwe = normalize_cwe(finding.get("cwe")) or default_cwe_for_rule_id(rule_id)
            help_uri = cwe_url(effective_cwe)
            help_text = finding.get("suggestion") or default_cwe_suggestion(effective_cwe)
            if rule_id not in rule_indexes:
                rule_indexes[rule_id] = len(rules)
                rule_tags = [
                    value
                    for value in (*cwe_sarif_tags(effective_cwe), finding.get("kind"))
                    if value
                ]
                rule = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": finding.get("rule_title") or finding.get("message", rule_id)
                    },
                    "properties": {"tags": rule_tags},
                }
                if help_uri:
                    rule["helpUri"] = help_uri
                if help_text:
                    rule["help"] = format_rule_help(
                        help_text,
                        title=finding.get("rule_title") or finding.get("message", rule_id),
                        cwe=effective_cwe,
                        help_uri=help_uri,
                    )
                rules.append(rule)

            locations = []
            primary_span = finding.get("primary_location")
            primary_snippet = (
                _single_source_line(
                    primary_span.get("uri", ""), int(primary_span.get("start_line") or 0)
                )
                if isinstance(primary_span, dict)
                else ""
            )
            primary = location_from_span(
                primary_span,
                snippet=primary_snippet or None,
                logical_name=finding.get("procedure") or None,
            )
            if primary is not None:
                locations.append(primary)

            thread_flow_locations = []
            for step in finding.get("code_flow", []):
                step_span = step.get("location")
                step_snippet = (
                    _single_source_line(
                        step_span.get("uri", ""), int(step_span.get("start_line") or 0)
                    )
                    if isinstance(step_span, dict)
                    else ""
                )
                location = location_from_span(
                    step_span,
                    snippet=step_snippet or None,
                    logical_name=step.get("procedure") or None,
                )
                if location is None:
                    continue
                location["message"] = {"text": step.get("message", step.get("kind", "flow"))}
                location["properties"] = {
                    "kind": step.get("kind"),
                    "nodeId": step.get("node_id"),
                    "procedureId": step.get("procedure_id"),
                }
                thread_flow_locations.append(
                    {
                        "location": location,
                        "nestingLevel": int(step.get("nesting_level") or 0),
                        "importance": step_importance(step.get("kind")),
                    }
                )

            ifds_props: Dict[str, Any] = {
                "confidence": finding.get("confidence"),
                "analysisStatus": result.get("status", "complete"),
                **(finding.get("properties") or {}),
            }
            if finding.get("procedure"):
                ifds_props["procedure"] = finding["procedure"]
            if effective_cwe:
                ifds_props["cwe"] = effective_cwe
            if help_uri:
                ifds_props["cweUrl"] = help_uri
            if help_text:
                ifds_props["suggestion"] = help_text
            related = [
                r["rule_id"]
                for r in finding.get("related_rules", ())
                if isinstance(r, dict) and r.get("rule_id") and r.get("rule_id") != rule_id
            ]
            if related:
                ifds_props["relatedRules"] = related

            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": rule_indexes[rule_id],
                "level": severity_level(finding.get("severity")),
                "message": {"text": finding.get("message", rule_id)},
                "locations": locations,
                "partialFingerprints": {"pyflow/v1": finding.get("fingerprint", "")},
                "properties": ifds_props,
            }
            if thread_flow_locations:
                sarif_result["codeFlows"] = [
                    {"threadFlows": [{"locations": thread_flow_locations}]}
                ]
            sarif_results.append(sarif_result)

        invocation = {
            "executionSuccessful": result.get("status") == "complete",
            "properties": {"analysisStatus": result.get("status", "complete")},
        }
        if result.get("termination_reason"):
            invocation["toolExecutionNotifications"] = [
                {
                    "level": "warning",
                    "message": {"text": result["termination_reason"]},
                }
            ]
        return sarif_document(
            "pyflow-security-ifds", sarif_results, rules=rules, invocations=[invocation]
        )

    if engine == "cpg":
        findings = result.get("findings", [])
        # Build minimal SARIF from CPG findings
        rules: List[Dict[str, Any]] = []
        results_list: List[Dict[str, Any]] = []
        seen_rules: Dict[str, int] = {}
        for f in findings:
            rule_id = f.get("rule_id", f.get("cwe", "CPG-TAINT"))
            rule_obj = f.get("rule") if isinstance(f.get("rule"), dict) else {}
            effective_cwe = normalize_cwe(f.get("cwe")) or default_cwe_for_rule_id(rule_id)
            help_uri = rule_obj.get("help_uri") or cwe_url(effective_cwe)
            help_text = (
                f.get("suggestion")
                or rule_obj.get("help_text")
                or default_cwe_suggestion(effective_cwe)
            )
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                short_desc = rule_obj.get("short_description", "") or f.get("rule_title", "")
                rule_entry = {
                    "id": rule_id,
                    "name": rule_obj.get("name", rule_id),
                    "shortDescription": {"text": short_desc},
                }
                if help_uri:
                    rule_entry["helpUri"] = help_uri
                if help_text:
                    rule_entry["help"] = format_rule_help(
                        help_text, title=short_desc, cwe=effective_cwe, help_uri=help_uri
                    )
                if effective_cwe:
                    rule_entry["properties"] = {
                        "tags": [*cwe_sarif_tags(effective_cwe), "security", "taint"]
                    }
                rules.append(rule_entry)
            sink_uri = f.get("sink_filename") or f.get("source_filename") or artifact_uri
            sink_line = max(int(f.get("sink_line") or f.get("source_line") or 1), 1)
            cpg_props: Dict[str, Any] = {
                "confidence": f.get("confidence_level"),
                "tags": f.get("tags", []),
                "precisionReasons": f.get("precision_reasons", []),
                "analysisStatus": result.get("status", "complete"),
            }
            if f.get("procedure"):
                cpg_props["procedure"] = f["procedure"]
            if f.get("source_label"):
                cpg_props["sourceLabel"] = f["source_label"]
            if f.get("sink_label"):
                cpg_props["sinkLabel"] = f["sink_label"]
            if effective_cwe:
                cpg_props["cwe"] = effective_cwe
            if help_uri:
                cpg_props["cweUrl"] = help_uri
            if help_text:
                cpg_props["suggestion"] = help_text
            related = [
                r["rule_id"]
                for r in f.get("related_rules", ())
                if isinstance(r, dict) and r.get("rule_id") and r.get("rule_id") != rule_id
            ]
            if related:
                cpg_props["relatedRules"] = related

            result_item = {
                "ruleId": rule_id,
                "ruleIndex": seen_rules[rule_id],
                "level": (severity_level(f.get("severity"))),
                "message": {
                    "text": (
                        f"Tainted data from {f.get('source_label', '?')} "
                        f"reaches {f.get('sink_label', '?')}"
                    )
                },
                "locations": [
                    physical_location(
                        sink_uri,
                        line=sink_line,
                        column=f.get("sink_column"),
                        end_column=f.get("sink_end_column"),
                        snippet=_single_source_line(sink_uri, sink_line) or None,
                        logical_name=f.get("procedure") or None,
                    )
                ],
                "partialFingerprints": {
                    "pyflow/v1": _fingerprint(
                        rule_id,
                        sink_uri,
                        sink_line,
                        f.get("source_label"),
                        f.get("sink_label"),
                    )
                },
                "properties": cpg_props,
            }
            thread_locations = []
            for step in f.get("path_preview", []):
                line = int(step.get("line") or 0)
                if line <= 0:
                    continue
                step_uri = step.get("filename") or artifact_uri
                thread_locations.append(
                    {
                        "location": {
                            **physical_location(
                                step_uri,
                                line=line,
                                column=step.get("column"),
                                snippet=_single_source_line(step_uri, line) or None,
                                logical_name=step.get("procedure") or None,
                            ),
                            "message": {"text": step.get("label") or step.get("kind", "flow")},
                        },
                        "nestingLevel": int(step.get("nesting_level") or 0),
                        "importance": step_importance(step.get("kind")),
                    }
                )
            if thread_locations:
                result_item["codeFlows"] = [{"threadFlows": [{"locations": thread_locations}]}]
            results_list.append(result_item)
        invocation: Dict[str, Any] = {
            "executionSuccessful": result.get("status") == "complete",
            "properties": {"analysisStatus": result.get("status")},
        }
        diagnostics = result.get("diagnostics", [])
        if diagnostics:
            invocation["toolExecutionNotifications"] = [
                {
                    "level": ("warning" if diagnostic.get("affects_completeness") else "note"),
                    "message": {"text": diagnostic.get("message", "")},
                    "descriptor": {"id": diagnostic.get("code", "cpg-diagnostic")},
                    "properties": {
                        "precisionLevel": diagnostic.get("level"),
                        "function": diagnostic.get("function"),
                        "operation": diagnostic.get("operation"),
                    },
                }
                for diagnostic in diagnostics
            ]
        return sarif_document(
            "pyflow-security-cpg", results_list, rules=rules, invocations=[invocation]
        )

    # Default: generic SARIF wrapper
    return sarif_document(f"pyflow-security-{engine}", [])
