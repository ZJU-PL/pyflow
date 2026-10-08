"""CPG report adapters using the shared SARIF formatter utilities.

These functions consume finding data and do not import the graph engine.
"""

from typing import Any, Dict
from pyflow.util.cwe import cwe_ancestors, cwe_identifiers
from .sarif import physical_location, severity_level, sarif_document


def rule_to_sarif(rule, severity: str) -> Dict[str, Any]:
    props: Dict[str, Any] = {
        "precision": rule.precision,
        "tags": list(rule.tags),
    }
    return {
        "id": rule.rule_id,
        "name": rule.name[:80],
        "shortDescription": {"text": rule.short_description},
        "fullDescription": {"text": rule.short_description},
        "helpUri": rule.help_uri,
        "help": {"text": rule.help_text or rule.short_description},
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

    Parameters
    ----------
    rule_index:
        Zero-based index into the SARIF ``rules`` array.
    """
    location = physical_location(artifact_uri, line=finding.source_line or 1)
    result: Dict[str, Any] = {
        "ruleId": finding.effective_rule_id,
        "ruleIndex": rule_index,
        "level": severity_level(finding.severity, default="note"),
        "message": {
            "text": (
                f"Tainted data from {finding.source_label} "
                f"reaches {finding.sink_label} [{finding.cwe}]"
            )
        },
        "locations": [location],
        "properties": {
            "cwe": finding.cwe,
            "cwes": list(cwe_identifiers(finding.cwe)),
            "cwe_ancestors": list(cwe_ancestors(finding.cwe)),
            "source_label": finding.source_label,
            "sink_label": finding.sink_label,
            "sink_line": finding.sink_line,
            "path_length": finding.path_length,
            "confidence": round(finding.confidence, 2),
            "tags": sorted(finding.tags),
            "sanitizers": sorted(finding.sanitizers),
            "precision": finding.rule_metadata.precision,
            "rule": finding.rule_metadata.to_dict(),
        },
    }
    if finding.path_nodes:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    **physical_location(
                                        artifact_uri, line=getattr(n.ast_node, "lineno", 0) or 1
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
