"""Result normalization and output formatting for security analyses."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from pyflow.checker.pattern.core import constants as b_constants

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


def _format_output_text(engine: str, result) -> str:
    """Format analysis results as human-readable text."""
    if engine == "ast-scanner":
        # The text formatter prints directly; we collect a summary
        issues = result.get_issue_list(b_constants.LOW, b_constants.LOW)
        if not issues:
            return "No issues found."
        lines = [f"Found {len(issues)} issue(s):\n"]
        for iss in issues:
            lines.append(f"  [{iss.test_id}] {iss.text}")
            lines.append(
                f"       Severity: {iss.severity}  Confidence: {iss.confidence}"
            )
            lines.append(f"       File: {iss.fname}:{iss.lineno}")
            lines.append("")
        return "\n".join(lines)

    if engine == "ast-dataflow":
        report = _ast_dataflow_payload(result)
        if not report["findings"]:
            return "No issues found."
        lines = [
            f"Status: {report['status']}",
            f"Found {len(report['findings'])} issue(s):\n",
        ]
        for finding in report["findings"]:
            lines.append(f"  [{finding['rule_id']}] {finding['rule_title']}")
            lines.append(
                f"       Severity: {finding['severity'].upper()}  "
                f"Confidence: {finding['confidence']}"
            )
            lines.append(f"       File: {finding['filename']}:{finding['sink_line']}")
            lines.append(
                f"       Sink: {finding['sink_name']}  "
                f"Kinds: {', '.join(finding['source_kinds'])}"
            )
            lines.append("")
        if report["diagnostics"]:
            lines.append("Diagnostics:")
            for diagnostic in report["diagnostics"]:
                lines.append(f"  [{diagnostic['code']}] {diagnostic['message']}")
        return "\n".join(lines)

    if engine == "ifds":
        report = result
        lines = [
            f"Function: {report.get('function', '<unknown>')}",
            f"Findings: {len(report.get('findings', []))}",
        ]
        stats = report.get("statistics", {})
        if stats:
            lines.append("Statistics:")
            for key, value in sorted(stats.items()):
                lines.append(f"  {key}: {value}")
        diags = report.get("diagnostics", [])
        if diags:
            lines.append("Diagnostics:")
            for diagnostic in diags:
                lines.append(f"  {diagnostic}")
        for finding in report.get("findings", []):
            if "kind" in finding:
                lines.append(
                    f"  typestate={finding.get('kind', '?')} "
                    f"protocol={finding.get('protocol', '?')} "
                    f"state={finding.get('state', '?')} "
                    f"resource={finding.get('resource_label', '?')} "
                    f"operation={finding.get('operation_name', '?')}"
                )
                continue
            args_str = ", ".join(finding.get("tainted_arguments", [])) or "<none>"
            lines.append(
                f"  sink={finding.get('sink_name', '?')} "
                f"procedure={finding.get('procedure', '?')} "
                f"args=[{args_str}]"
            )
        return "\n".join(lines)

    if engine == "cpg":
        findings = result.get("findings", [])
        if not findings:
            return f"Status: {result.get('status', 'complete')}\nNo security findings."
        lines = [
            f"Status: {result.get('status', 'complete')}",
            f"\n{len(findings)} security finding(s):\n",
        ]
        for i, f in enumerate(findings, 1):
            conf = f.get("confidence", 0)
            bar = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
            lines.append(
                f"  [{i}] {f.get('cwe', '?')} [{f.get('severity', '?')}] "
                f"confidence={conf:.0%} [{bar}]"
            )
            lines.append(
                f"      source: {f.get('source_label', '?')} "
                f"(line {f.get('source_line', 0)})"
            )
            lines.append(
                f"      sink:   {f.get('sink_label', '?')} "
                f"(line {f.get('sink_line', 0)})"
            )
            lines.append("")
        return "\n".join(lines)

    return ""


def _output_results(engine: str, result, args) -> None:
    """Write analysis results in the requested format."""
    fmt = getattr(args, "format", "text")

    # Pattern scanning and non-normalized AST-dataflow formats use checker
    # formatters.
    # which need a manager object. For ifds/cpg, use the inline formatters.
    if (
        engine == "ast-scanner"
        or (engine == "ast-dataflow" and fmt not in ("text", "json", "sarif"))
    ) and fmt in (
        "csv",
        "html",
        "screen",
        "text",
        "xml",
        "yaml",
        "json",
        "sarif",
        "custom",
    ):
        _output_via_formatter(engine, result, args, fmt)
        return

    # Fallback for ifds / cpg engines (dict-based results)
    out_file = None
    try:
        if getattr(args, "output", None):
            out_file = open(args.output, "w", encoding="utf-8")
        output = out_file or sys.stdout

        if fmt == "text":
            output.write(_format_output_text(engine, result))
            output.write("\n")
        elif fmt == "json":
            json.dump(_result_to_json(engine, result), output, indent=2)
            output.write("\n")
        elif fmt == "sarif":
            sarif_doc = _result_to_sarif(engine, result, args)
            json.dump(sarif_doc, output, indent=2)
            output.write("\n")
        else:
            # Unsupported format for dict-based engines, fall back to text
            output.write(_format_output_text(engine, result))
            output.write("\n")
    finally:
        if out_file:
            out_file.close()


def _output_via_formatter(engine: str, result, args, fmt: str) -> None:
    """Route scanner-based results through the appropriate checker formatter."""
    from pyflow.checker.pattern.core import constants as b_constants

    sev_level = getattr(args, "severity", b_constants.LOW)
    conf_level = getattr(args, "confidence", b_constants.LOW)
    lines = -1

    out_file = None
    try:
        if getattr(args, "output", None):
            out_file = open(
                args.output,
                "wb" if fmt in ("xml",) else "w",
                encoding="utf-8" if fmt != "xml" else None,
            )
        fileobj = out_file or sys.stdout

        if fmt == "json":
            from pyflow.checker.formatters import json as json_fmt

            json_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "sarif":
            from pyflow.checker.formatters import sarif as sarif_fmt

            sarif_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "text":
            from pyflow.checker.formatters import text as text_fmt

            text_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "csv":
            from pyflow.checker.formatters import csv as csv_fmt

            csv_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "html":
            from pyflow.checker.formatters import html as html_fmt

            html_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "screen":
            from pyflow.checker.formatters import screen as screen_fmt

            screen_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "xml":
            from pyflow.checker.formatters import xml as xml_fmt

            xml_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "yaml":
            from pyflow.checker.formatters import yaml as yaml_fmt

            yaml_fmt.report(result, fileobj, sev_level, conf_level, lines)
        elif fmt == "custom":
            from pyflow.checker.formatters import custom as custom_fmt

            template = getattr(args, "custom_template", None)
            custom_fmt.report(result, fileobj, sev_level, conf_level, template=template)
    finally:
        if out_file:
            out_file.close()


def _result_to_json(engine: str, result) -> Any:
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
                }
                for iss in issues
            ],
        }
    if engine == "ast-dataflow":
        return _ast_dataflow_payload(result)
    if engine == "ifds":
        return {"engine": "ifds", **result}
    if engine == "cpg":
        return result
    return {}


def _ast_dataflow_payload(manager) -> Dict[str, Any]:
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
                "source_kinds": sorted(finding.source_kinds),
                "rule_id": finding.rule_id,
                "rule_title": finding.rule_title,
                "severity": finding.severity,
                "cwe": finding.cwe,
                "suggestion": finding.suggestion,
                "confidence": finding.confidence,
                "precision_reasons": list(finding.precision_reasons),
                "trace": [
                    {
                        "operation": step.operation,
                        "location": step.location,
                        "filename": step.filename,
                        "line": step.line,
                        "detail": step.detail,
                    }
                    for step in finding.trace
                ],
            }
            for finding in analysis.findings
        ],
        "diagnostics": [
            {
                "code": diagnostic.code,
                "message": diagnostic.message,
                "affects_completeness": diagnostic.affects_completeness,
                "function": diagnostic.function,
                "level": diagnostic.level,
                "filename": diagnostic.filename,
                "line": diagnostic.line,
                "operation": diagnostic.operation,
            }
            for diagnostic in analysis.diagnostics
        ],
        "statistics": dict(analysis.statistics),
    }


def _result_to_sarif(engine: str, result, args) -> Dict[str, Any]:
    """Convert engine results to SARIF v2.1.0 format."""
    if engine == "ast-dataflow":
        report = _ast_dataflow_payload(result)
        rules: List[Dict[str, Any]] = []
        rule_indexes: Dict[str, int] = {}
        sarif_results: List[Dict[str, Any]] = []
        for finding in report["findings"]:
            rule_id = finding["rule_id"]
            if rule_id not in rule_indexes:
                rule_indexes[rule_id] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "shortDescription": {"text": finding["rule_title"]},
                        "help": {
                            "text": finding.get("suggestion") or finding["rule_title"]
                        },
                    }
                )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_indexes[rule_id],
                    "level": _sarif_level(finding.get("severity")),
                    "message": {"text": f"Tainted data reaches {finding['sink_name']}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding["filename"]},
                                "region": {"startLine": finding["sink_line"] or 1},
                            }
                        }
                    ],
                    "properties": {
                        "sourceKinds": finding["source_kinds"],
                        "confidence": finding["confidence"],
                        "precisionReasons": finding["precision_reasons"],
                        "analysisStatus": report["status"],
                    },
                    "codeFlows": (
                        [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "message": {
                                                        "text": (
                                                            step.get("detail")
                                                            or step["operation"]
                                                        )
                                                    },
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": step.get("filename")
                                                            or finding["filename"]
                                                        },
                                                        "region": {
                                                            "startLine": step.get(
                                                                "line"
                                                            )
                                                            or 1
                                                        },
                                                    },
                                                }
                                            }
                                            for step in finding.get("trace", [])
                                        ]
                                    }
                                ]
                            }
                        ]
                        if finding.get("trace")
                        else []
                    ),
                }
            )
        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pyflow-security-ast-dataflow",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": report["status"] == "complete",
                            "properties": {"analysisStatus": report["status"]},
                        }
                    ],
                    "results": sarif_results,
                }
            ],
        }

    if engine == "ifds":
        findings = result.get("findings", [])
        rules: List[Dict[str, Any]] = []
        rule_indexes: Dict[str, int] = {}
        sarif_results: List[Dict[str, Any]] = []

        def physical_location(span):
            if not span:
                return None
            region = {"startLine": max(int(span.get("start_line", 1)), 1)}
            if span.get("start_column") is not None:
                region["startColumn"] = max(int(span["start_column"]) + 1, 1)
            if span.get("end_line") is not None:
                region["endLine"] = int(span["end_line"])
            if span.get("end_column") is not None:
                region["endColumn"] = int(span["end_column"]) + 1
            return {
                "physicalLocation": {
                    "artifactLocation": {"uri": span.get("uri", "")},
                    "region": region,
                }
            }

        for finding in findings:
            rule_id = finding.get("rule_id") or "PYFLOW-IFDS"
            if rule_id not in rule_indexes:
                rule_indexes[rule_id] = len(rules)
                rule = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("message", rule_id)},
                    "properties": {
                        "tags": [
                            value
                            for value in (finding.get("cwe"), finding.get("kind"))
                            if value
                        ]
                    },
                }
                if finding.get("suggestion"):
                    rule["help"] = {"text": finding["suggestion"]}
                rules.append(rule)

            locations = []
            primary = physical_location(finding.get("primary_location"))
            if primary is not None:
                locations.append(primary)

            thread_flow_locations = []
            for index, step in enumerate(finding.get("code_flow", []), 1):
                location = physical_location(step.get("location"))
                if location is None:
                    continue
                location["message"] = {
                    "text": step.get("message", step.get("kind", "flow"))
                }
                location["properties"] = {
                    "kind": step.get("kind"),
                    "nodeId": step.get("node_id"),
                    "procedureId": step.get("procedure_id"),
                }
                location["nestingLevel"] = index - 1
                thread_flow_locations.append({"location": location})

            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": rule_indexes[rule_id],
                "level": _sarif_level(finding.get("severity")),
                "message": {"text": finding.get("message", rule_id)},
                "locations": locations,
                "partialFingerprints": {"pyflow/v1": finding.get("fingerprint", "")},
                "properties": {
                    "confidence": finding.get("confidence"),
                    "analysisStatus": result.get("status", "complete"),
                    **(finding.get("properties") or {}),
                },
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
        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "pyflow-security-ifds", "rules": rules}
                    },
                    "invocations": [invocation],
                    "results": sarif_results,
                }
            ],
        }

    if engine == "cpg":
        from pyflow.ir.cpg.taint import CPGTaintEngine

        findings = result.get("findings", [])
        artifact_uri = (
            (str(args.targets[0]) if getattr(args, "targets", None) else "")
            if hasattr(CPGTaintEngine, "deduplicate")
            else ""
        )
        # Build minimal SARIF from CPG findings
        rules: List[Dict[str, Any]] = []
        results_list: List[Dict[str, Any]] = []
        seen_rules: Dict[str, int] = {}
        for f in findings:
            rule_id = f.get("rule_id", f.get("cwe", "CPG-TAINT"))
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "name": f.get("rule", {}).get("name", rule_id),
                        "shortDescription": {
                            "text": f.get("rule", {}).get("short_description", "")
                        },
                    }
                )
            sink_line = max(int(f.get("sink_line") or 1), 1)
            result_item = {
                "ruleId": rule_id,
                "ruleIndex": seen_rules[rule_id],
                "level": (
                    "error" if f.get("severity") in ("critical", "high") else "warning"
                ),
                "message": {
                    "text": (
                        f"Tainted data from {f.get('source_label', '?')} "
                        f"reaches {f.get('sink_label', '?')}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {"startLine": sink_line},
                        }
                    }
                ],
                "properties": {
                    "confidence": f.get("confidence_level"),
                    "tags": f.get("tags", []),
                    "precisionReasons": f.get("precision_reasons", []),
                    "analysisStatus": result.get("status", "complete"),
                },
            }
            thread_locations = []
            for step in f.get("path_preview", []):
                line = int(step.get("line") or 0)
                if line <= 0:
                    continue
                thread_locations.append(
                    {
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri},
                                "region": {"startLine": line},
                            },
                            "message": {
                                "text": step.get("label") or step.get("kind", "flow")
                            },
                        }
                    }
                )
            if thread_locations:
                result_item["codeFlows"] = [
                    {"threadFlows": [{"locations": thread_locations}]}
                ]
            results_list.append(result_item)
        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "pyflow-security-cpg", "rules": rules}},
                    "invocations": [
                        {
                            "executionSuccessful": result.get("status") == "complete",
                            "properties": {"analysisStatus": result.get("status")},
                        }
                    ],
                    "results": results_list,
                }
            ],
        }

    # Default: generic SARIF wrapper
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": f"pyflow-security-{engine}"}},
                "results": [],
            }
        ],
    }


def _sarif_level(severity: str | None) -> str:
    normalized = (severity or "warning").lower()
    if normalized in {"critical", "high", "error"}:
        return "error"
    if normalized in {"low", "note", "info", "informational"}:
        return "note"
    return "warning"


# ── Analysis result serialization ───────────────────────────────────────


def _code_name(code) -> str:
    if hasattr(code, "codeName"):
        return code.codeName()
    if hasattr(code, "__name__"):
        return code.__name__
    return str(code)


def _result_status(result) -> tuple[str, str | None]:
    status = getattr(result, "status", "complete")
    return getattr(status, "value", str(status)), getattr(
        result, "termination_reason", None
    )


def _statistics_to_dict(statistics) -> dict[str, Any]:
    from dataclasses import asdict, is_dataclass

    if is_dataclass(statistics):
        return asdict(statistics)
    if hasattr(statistics, "__dict__"):
        return dict(vars(statistics))
    return dict(statistics)


def _ifds_result_to_dict(function: str, taint_result) -> Dict[str, Any]:
    """Convert an IFDS TaintAnalysisResult to a JSON-compatible dict."""
    from collections import defaultdict, deque
    from pyflow.analysis.ifds.reporting import normalized_taint_findings

    problem = getattr(taint_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = defaultdict(deque)
    if enriched:
        for finding in normalized_taint_findings(taint_result):
            normalized[
                (
                    finding.node_id,
                    tuple(finding.properties.get("tainted_arguments", ())),
                )
            ].append(finding)
    findings = []
    for finding in taint_result.findings:
        tainted_arguments = [
            local.name or "<local>" for local in finding.tainted_arguments
        ]
        if not tainted_arguments:
            tainted_arguments = list(finding.tainted_argument_labels)

        if enriched:
            node_id = adapter.supergraph.node_id(finding.sink)
            normalized_finding = (
                normalized[(node_id, tuple(tainted_arguments))].popleft().to_dict()
            )
        else:
            normalized_finding = {}
        normalized_finding.update(
            {
                "sink_name": finding.sink_name,
                "procedure": _code_name(finding.sink.procedure.code),
                "block_kind": finding.sink.kind,
                "tainted_arguments": tainted_arguments,
                "explanations": normalized_finding.get("code_flow", []),
            }
        )
        findings.append(normalized_finding)

    statistics = _statistics_to_dict(taint_result.statistics)

    status, termination_reason = _result_status(taint_result)
    return {
        "function": function,
        "analysis": "taint",
        "findings": findings,
        "statistics": statistics,
        "status": status,
        "termination_reason": termination_reason,
    }


def _typestate_result_to_dict(function: str, typestate_result) -> Dict[str, Any]:
    """Convert an IFDS TypestateAnalysisResult to a JSON-compatible dict."""
    from pyflow.analysis.ifds.reporting import normalized_typestate_findings

    problem = getattr(typestate_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = (
        {
            (
                finding.node_id,
                finding.kind,
                finding.properties.get("resource"),
                finding.properties.get("protocol"),
                finding.properties.get("state"),
            ): finding
            for finding in normalized_typestate_findings(typestate_result)
        }
        if enriched
        else {}
    )
    findings = []
    for finding in typestate_result.findings:
        if enriched:
            node_id = adapter.supergraph.node_id(finding.node)
            item = normalized[
                (
                    node_id,
                    finding.kind,
                    finding.resource_label,
                    finding.protocol,
                    finding.state,
                )
            ].to_dict()
        else:
            item = {}
        item.update(
            {
                "kind": finding.kind,
                "operation_name": finding.operation_name,
                "resource_label": finding.resource_label,
                "protocol": finding.protocol,
                "state": finding.state,
                "procedure": _code_name(finding.node.procedure.code),
                "block_kind": finding.node.kind,
            }
        )
        findings.append(item)

    statistics = _statistics_to_dict(typestate_result.statistics)

    status, termination_reason = _result_status(typestate_result)
    return {
        "function": function,
        "analysis": "typestate",
        "findings": findings,
        "statistics": statistics,
        "status": status,
        "termination_reason": termination_reason,
    }


def _nullness_result_to_dict(function: str, nullness_result) -> Dict[str, Any]:
    """Convert an IFDS nullness result to a JSON-compatible dictionary."""
    from pyflow.analysis.ifds.reporting import normalized_nullness_findings

    problem = getattr(nullness_result, "_problem", None)
    adapter = getattr(problem, "adapter", None)
    enriched = adapter is not None
    normalized = (
        {
            (
                finding.node_id,
                finding.kind,
                finding.properties.get("expression"),
            ): finding
            for finding in normalized_nullness_findings(nullness_result)
        }
        if enriched
        else {}
    )
    findings = []
    for finding in nullness_result.findings:
        if enriched:
            node_id = adapter.supergraph.node_id(finding.node)
            item = normalized[
                (node_id, finding.kind, finding.expression_label)
            ].to_dict()
        else:
            item = {}
        item.update(
            {
                "kind": finding.kind,
                "expression_label": finding.expression_label,
                "procedure": _code_name(finding.node.procedure.code),
                "block_kind": finding.node.kind,
            }
        )
        findings.append(item)
    status, termination_reason = _result_status(nullness_result)
    return {
        "function": function,
        "analysis": "nullness",
        "findings": findings,
        "statistics": _statistics_to_dict(nullness_result.statistics),
        "status": status,
        "termination_reason": termination_reason,
    }
