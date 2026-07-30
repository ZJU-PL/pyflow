"""Detection-oriented metrics over normalized analyzer findings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

from .mapping import cwes_from


COMPLETED_STATUSES = {"complete", "partial"}


def compute_metrics(
    runs: Iterable[Mapping[str, Any]], *, label_pointer: str = "/cwe"
) -> dict[str, Any]:
    details = [_score_run(run, label_pointer) for run in runs]
    by_engine: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for detail in details:
        by_engine[str(detail["engine"])].append(detail)
        for cwe in detail["expected_cwes"]:
            by_cwe[cwe].append(detail)
    return {
        "schema_version": 1,
        "metric_semantics": {
            "completed_statuses": sorted(COMPLETED_STATUSES),
            "detected": "at least one finding CWE intersects the expected CWE label",
            "recall_all": ("detected labeled samples / all labeled samples"),
            "recall_completed": (
                "detected completed labeled samples / completed labeled samples"
            ),
            "precision": (
                "not computed because negative/ground-truth locations may be absent"
            ),
        },
        "label_pointer": label_pointer,
        "overall": _aggregate(details),
        "by_engine": {
            key: _aggregate(values) for key, values in sorted(by_engine.items())
        },
        "by_cwe": {key: _aggregate(values) for key, values in sorted(by_cwe.items())},
        "runs": details,
    }


def _score_run(run: Mapping[str, Any], label_pointer: str) -> dict[str, Any]:
    expected = cwes_from(_json_pointer(run.get("labels", {}), label_pointer))
    findings = run.get("findings", [])
    finding_cwes = [
        cwes_from(finding.get("cwes"))
        for finding in findings
        if isinstance(finding, dict)
    ]
    matches = sum(bool(expected & values) for values in finding_cwes)
    completed = run.get("run_status") in COMPLETED_STATUSES and not run.get(
        "normalization_error"
    )
    return {
        "sample_id": run.get("sample_id"),
        "engine": run.get("engine"),
        "run_status": run.get("run_status"),
        "completed": completed,
        "expected_cwes": sorted(expected),
        "evaluable": bool(expected),
        "warning_count": len(finding_cwes),
        "mapped_warning_count": sum(bool(values) for values in finding_cwes),
        "matched_finding_count": matches,
        "detected": bool(expected) and matches > 0,
        "normalization_error": run.get("normalization_error"),
    }


def _aggregate(details: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(details)
    labeled = [row for row in rows if row["evaluable"]]
    completed = [row for row in rows if row["completed"]]
    completed_labeled = [row for row in labeled if row["completed"]]
    detected = sum(bool(row["detected"]) for row in labeled)
    detected_completed = sum(bool(row["detected"]) for row in completed_labeled)
    warnings = sum(int(row["warning_count"]) for row in rows)
    return {
        "run_count": len(rows),
        "completed_run_count": len(completed),
        "incomplete_run_count": len(rows) - len(completed),
        "labeled_run_count": len(labeled),
        "completed_labeled_run_count": len(completed_labeled),
        "warning_count": warnings,
        "mapped_warning_count": sum(int(row["mapped_warning_count"]) for row in rows),
        "detected_run_count": detected,
        "recall_all": _ratio(detected, len(labeled)),
        "recall_completed": _ratio(detected_completed, len(completed_labeled)),
        "warnings_per_completed_run": _ratio(warnings, len(completed)),
    }


def _json_pointer(value: object, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("label pointer must be empty or start with '/'")
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None
