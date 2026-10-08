"""Engine-specific finding deduplication."""

from __future__ import annotations
from typing import Dict, List, Set, Tuple
from .model import TaintFinding


class _TaintFindingsMixin:
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
