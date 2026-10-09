"""Fold audited rule overlaps at an exact source node, retaining evidence."""

from copy import copy

# CWE alone is too broad to prove equivalence. Only fold vetted rules whose
# messages describe the same condition, and keep unrelated findings separate.
_FAMILIES = {
    "app_run_debug": "flask-debug-mode",
    "flask_debug_in_production": "flask-debug-mode",
    "flask_debug_mode_traceback": "flask-debug-mode",
}
_SEVERITY = {"UNDEFINED": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_CONFIDENCE = {"UNDEFINED": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def fold_overlapping_issues(issues):
    groups = {}
    for index, issue in enumerate(issues):
        family = _FAMILIES.get(issue.test)
        key = (
            (
                family,
                issue.fname,
                issue.lineno,
                issue.col_offset,
                issue.end_col_offset,
                tuple(issue.linerange),
            )
            if family and issue.lineno is not None and issue.col_offset >= 0
            else ("unique", index)
        )
        groups.setdefault(key, []).append(issue)
    result = []
    for members in groups.values():
        if len(members) == 1:
            result.append(members[0])
            continue
        primary = min(
            members,
            key=lambda item: (
                -_SEVERITY[item.severity],
                -_CONFIDENCE[item.confidence],
                item.test_id,
                item.test,
            ),
        )
        primary = copy(primary)
        primary.vulnerability_family = _FAMILIES[primary.test]
        primary.related_rules = [
            {
                "rule_id": item.test_id,
                "rule_name": item.test,
                "severity": item.severity,
                "confidence": item.confidence,
                "message": item.text,
            }
            for item in sorted(members, key=lambda item: (item.test_id, item.test))
        ]
        result.append(primary)
    return result
