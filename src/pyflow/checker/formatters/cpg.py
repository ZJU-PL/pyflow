"""CPG report adapters using the shared SARIF formatter utilities.

These functions consume finding data and do not import the graph engine.
"""

import hashlib
from typing import Any, Dict
from pyflow.util.cwe import (
    cwe_ancestors,
    cwe_identifiers,
    cwe_sarif_tags,
    cwe_url,
    default_cwe_for_rule_id,
    default_cwe_suggestion,
    normalize_cwe,
)
from .report_render import _single_source_line
from .sarif import (
    format_rule_help,
    physical_location,
    sarif_document,
    severity_level,
    step_importance,
)


def rule_to_sarif(rule, severity: str) -> Dict[str, Any]:
    cwe = next((t for t in rule.tags if normalize_cwe(t)), None) or default_cwe_for_rule_id(
        rule.rule_id
    )
    help_uri = rule.help_uri or cwe_url(cwe)
    tags = list(dict.fromkeys([*rule.tags, *cwe_sarif_tags(cwe)]))
    props: Dict[str, Any] = {
        "precision": rule.precision,
        "tags": tags,
    }
    suggestion = rule.help_text or default_cwe_suggestion(cwe)
    return {
        "id": rule.rule_id,
        "name": rule.name[:80],
        "shortDescription": {"text": rule.short_description},
        "fullDescription": {"text": rule.short_description},
        "helpUri": help_uri,
        "help": format_rule_help(
            suggestion,
            title=rule.short_description,
            cwe=cwe,
            help_uri=help_uri,
        ),
        "defaultConfiguration": {"level": severity_level(severity, default="note")},
        "properties": props,
    }


def finding_to_sarif(
    finding,
    *,
    rule_index: int = 0,
    artifact_uri: str = "",
) -> Dict[str, Any]:
    """Export as a SARIF result object.

    Primary location points to the sink (falling back to the source when
    sink position is unknown), matching IFDS and AST-dataflow SARIF output.
    """
    primary_uri = (
        finding._filename(finding.sink_node)
        or finding.source_filename_override
        or finding._filename(finding.source_node)
        or artifact_uri
    )
    primary_line = finding.sink_line or finding.source_line or 1
    primary_col = finding.sink_column if finding.sink_line else finding.source_column
    primary_end_col = finding.sink_end_column if finding.sink_line else None
    effective_cwe = normalize_cwe(finding.cwe) or default_cwe_for_rule_id(finding.effective_rule_id)
    suggestion = (
        finding.suggestion
        or finding.rule_metadata.help_text
        or default_cwe_suggestion(effective_cwe)
    )
    location = physical_location(
        primary_uri,
        line=primary_line,
        column=primary_col,
        end_column=primary_end_col,
        snippet=_single_source_line(primary_uri, primary_line) or None,
        logical_name=getattr(finding, "procedure", "") or None,
    )
    fp_raw = "|".join(
        (
            str(finding.effective_rule_id),
            str(primary_uri),
            str(primary_line),
            str(finding.source_label),
            str(finding.sink_label),
        )
    )
    fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()[:24]
    properties: Dict[str, Any] = {
        "cwe": effective_cwe or finding.cwe,
        "cwes": list(cwe_identifiers(effective_cwe or finding.cwe)),
        "cwe_ancestors": list(cwe_ancestors(effective_cwe or finding.cwe)),
        "source_label": finding.source_label,
        "sink_label": finding.sink_label,
        "source_line": finding.source_line,
        "sink_line": finding.sink_line,
        "path_length": finding.path_length,
        "confidence": round(finding.confidence, 2),
        "tags": sorted(finding.tags),
        "sanitizers": sorted(finding.sanitizers),
        "precision": finding.rule_metadata.precision,
        "rule": finding.rule_metadata.to_dict(),
    }
    if getattr(finding, "procedure", ""):
        properties["procedure"] = finding.procedure
    if suggestion:
        properties["suggestion"] = suggestion
    help_uri = cwe_url(effective_cwe)
    if help_uri:
        properties["cweUrl"] = help_uri
    result: Dict[str, Any] = {
        "ruleId": finding.effective_rule_id,
        "ruleIndex": rule_index,
        "level": severity_level(finding.severity, default="note"),
        "message": {
            "text": (
                f"Tainted data from {finding.source_label} "
                f"reaches {finding.sink_label} [{effective_cwe or finding.cwe}]"
            )
        },
        "locations": [location],
        "partialFingerprints": {"pyflow/v1": fingerprint},
        "properties": properties,
    }
    path_steps = getattr(finding, "path_steps", ()) or ()
    if path_steps:
        tf_locs = []
        for step in path_steps:
            step_line = int(step.get("line") or 0)
            if step_line <= 0:
                continue
            step_uri = step.get("filename") or artifact_uri
            tf_locs.append(
                {
                    "location": {
                        **physical_location(
                            step_uri,
                            line=step_line,
                            column=step.get("column"),
                            snippet=_single_source_line(step_uri, step_line) or None,
                            logical_name=step.get("procedure") or None,
                        ),
                        "message": {
                            "text": (step.get("label") or step.get("kind") or "flow")[:120]
                        },
                    },
                    "nestingLevel": int(step.get("nesting_level") or 0),
                    "importance": step_importance(step.get("kind")),
                }
            )
        if tf_locs:
            result["codeFlows"] = [{"threadFlows": [{"locations": tf_locs}]}]
    elif finding.path_nodes:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    **physical_location(
                                        finding._filename(n) or artifact_uri,
                                        line=getattr(n.ast_node, "lineno", 0) or 1,
                                        column=getattr(n.ast_node, "col_offset", None),
                                    ),
                                    "message": {"text": (n.label or n.kind)[:120]},
                                }
                            }
                            for n in finding.path_nodes
                        ]
                    }
                ]
            }
        ]
    return result


def findings_to_sarif(findings, *, tool_name="pyflow-cpg", artifact_uri=""):
    findings = list(findings)
    rules_by_id = {}
    for finding in findings:
        rules_by_id.setdefault(
            finding.effective_rule_id, rule_to_sarif(finding.rule_metadata, finding.severity)
        )
    rules = sorted(rules_by_id.values(), key=lambda rule: rule["id"])
    indexes = {rule["id"]: index for index, rule in enumerate(rules)}
    return sarif_document(
        tool_name,
        [
            finding_to_sarif(
                finding, rule_index=indexes[finding.effective_rule_id], artifact_uri=artifact_uri
            )
            for finding in findings
        ],
        rules=rules,
        artifacts=[{"location": {"uri": artifact_uri}}] if artifact_uri else [],
    )
