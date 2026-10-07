"""Finding deduplication and JSON/SARIF reporting."""

from __future__ import annotations
from typing import Any, Dict, List, Set, Tuple
from .model import TaintFinding


class _TaintReportingMixin:
    """Internal mixin composed by CPGTaintEngine."""

    @staticmethod
    def deduplicate(findings: List[TaintFinding]) -> List[TaintFinding]:
        """Collapse similar findings by ``(cwe, source_line, sink_line)``.

        For each group of duplicates, keeps the finding with the longest
        path (most evidence) and merges tags/sanitizers from all members.
        """
        groups: Dict[Tuple[str, int, int], List[TaintFinding]] = {}
        for f in findings:
            key = f.dedup_key
            groups.setdefault(key, []).append(f)

        result: List[TaintFinding] = []
        for group in groups.values():
            if len(group) == 1:
                result.append(group[0])
                continue
            best = max(group, key=lambda f: f.path_length)
            all_tags: Set[str] = set()
            all_sans: Set[str] = set()
            for f in group:
                all_tags.update(f.tags)
                all_sans.update(f.sanitizers)
            best.tags = frozenset(all_tags)
            best.sanitizers = frozenset(all_sans)
            result.append(best)
        return sorted(result, key=lambda f: f.confidence, reverse=True)

    @staticmethod
    def to_json(findings: List[TaintFinding]) -> str:
        """Serialize findings to a JSON string."""
        import json

        return json.dumps([f.to_dict() for f in findings], indent=2)

    @staticmethod
    def to_sarif(
        findings: List[TaintFinding],
        *,
        tool_name: str = "pyflow-cpg",
        artifact_uri: str = "",
    ) -> Dict[str, Any]:
        """Build a SARIF v2.1.0 document from taint findings.

        Returns a JSON-serializable dict.
        """
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            rule_id = f.effective_rule_id
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = f.rule_metadata.to_sarif_rule(f.severity)
        rules = sorted(rules_by_id.values(), key=lambda r: r["id"])
        rule_to_idx = {rule["id"]: i for i, rule in enumerate(rules)}

        return {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/"
                "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "rules": rules,
                        }
                    },
                    "artifacts": (
                        [{"location": {"uri": artifact_uri}}] if artifact_uri else []
                    ),
                    "results": [
                        f.to_sarif(
                            rule_index=rule_to_idx.get(f.effective_rule_id, 0),
                            artifact_uri=artifact_uri,
                        )
                        for f in findings
                    ],
                }
            ],
        }
