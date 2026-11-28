"""CPG SARIF adapters delegating directly to the canonical report model & SARIF renderer."""

from __future__ import annotations

from typing import Any, Dict

from .report_model import build_security_report
from .sarif import render_sarif


def rule_to_sarif(rule, severity: str) -> Dict[str, Any]:
    doc = build_security_report(
        "cpg",
        {
            "status": "complete",
            "findings": [
                {
                    "rule_id": rule.rule_id,
                    "rule_title": rule.short_description or rule.name,
                    "severity": severity,
                    "suggestion": rule.help_text,
                    "tags": list(rule.tags),
                    "rule": rule.to_dict(),
                }
            ],
        },
    )
    return render_sarif(doc)["runs"][0]["tool"]["driver"]["rules"][0]


def finding_to_sarif(
    finding,
    *,
    rule_index: int = 0,
    artifact_uri: str = "",
) -> Dict[str, Any]:
    """Export one CPG :class:`TaintFinding` via the canonical SARIF renderer."""
    doc = build_security_report("cpg", {"status": "complete", "findings": [finding.to_dict()]})
    result = render_sarif(doc, artifact_uri=artifact_uri)["runs"][0]["results"][0]
    result["ruleIndex"] = rule_index
    return result


def findings_to_sarif(findings, *, tool_name="pyflow-cpg", artifact_uri=""):
    """Export CPG :class:`TaintFinding` objects as a full SARIF v2.1.0 document."""
    doc = build_security_report(
        "cpg",
        {"status": "complete", "findings": [finding.to_dict() for finding in findings]},
    )
    return render_sarif(doc, tool_name=tool_name, artifact_uri=artifact_uri)
