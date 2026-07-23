"""Finding baselines, expiring exceptions, and package-name policy checks."""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from packaging.utils import canonicalize_name

from .input_safety import load_json_file
from .models import SupplyChainFinding, SupplyChainScan


@dataclass(frozen=True)
class FindingPolicy:
    exceptions: tuple[dict[str, Any], ...] = ()
    baseline_ids: frozenset[str] = frozenset()


def load_finding_policy(path: Path) -> FindingPolicy:
    data = load_json_file(path)
    if not isinstance(data, dict):
        raise ValueError("finding policy must be a JSON object")
    exceptions = data.get("exceptions", ()) or ()
    if not isinstance(exceptions, list) or not all(
        isinstance(item, dict) for item in exceptions
    ):
        raise ValueError("policy exceptions must be an array of objects")
    for item in exceptions:
        if not str(item.get("reason", "")).strip():
            raise ValueError("every policy exception requires a reason")
        if not str(item.get("expires", "")).strip():
            raise ValueError("every policy exception requires an expiry date")
        expiry = _parse_expiry(item.get("expires"))
        if expiry == dt.date.min:
            raise ValueError("policy exception expiry must use YYYY-MM-DD")
    baseline = data.get("baseline", ()) or ()
    if not isinstance(baseline, list):
        raise ValueError("policy baseline must be an array of finding IDs")
    return FindingPolicy(
        exceptions=tuple(exceptions),
        baseline_ids=frozenset(str(item) for item in baseline),
    )


def load_baseline(path: Path) -> frozenset[str]:
    data = load_json_file(path)
    values = data.get("finding_ids", ()) if isinstance(data, dict) else data
    if not isinstance(values, list):
        raise ValueError("baseline must be an array or contain a finding_ids array")
    return frozenset(str(item) for item in values)


def write_baseline(path: Path, findings: Iterable[SupplyChainFinding]) -> None:
    identifiers = sorted({finding.to_dict()["id"] for finding in findings})
    document = {
        "schema": "pyflow-supply-chain-baseline-v1",
        "finding_ids": identifiers,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def apply_finding_policy(
    findings: Iterable[SupplyChainFinding],
    policy: FindingPolicy,
    *,
    today: dt.date | None = None,
) -> tuple[tuple[SupplyChainFinding, ...], tuple[SupplyChainFinding, ...]]:
    active_date = today or dt.datetime.now(dt.timezone.utc).date()
    kept: list[SupplyChainFinding] = []
    suppressed: list[SupplyChainFinding] = []
    expired_reported: set[int] = set()
    for finding in findings:
        finding_id = str(finding.to_dict()["id"])
        if finding_id in policy.baseline_ids:
            suppressed.append(finding)
            continue
        matched = False
        for index, exception in enumerate(policy.exceptions):
            if not _exception_matches(exception, finding, finding_id):
                continue
            expires = _parse_expiry(exception.get("expires"))
            if expires is not None and expires < active_date:
                if index not in expired_reported:
                    kept.append(
                        SupplyChainFinding(
                            kind="policy-exception-expired",
                            message="A supply-chain policy exception has expired",
                            location=str(exception.get("location") or finding.location),
                            severity="MEDIUM",
                            details={
                                "expires": expires.isoformat(),
                                "reason": str(exception.get("reason", "")),
                            },
                        )
                    )
                    expired_reported.add(index)
                continue
            suppressed.append(finding)
            matched = True
            break
        if not matched:
            kept.append(finding)
    return tuple(kept), tuple(suppressed)


def audit_package_names(
    scan: SupplyChainScan,
    protected_names: Iterable[str],
    *,
    maximum_distance: int = 1,
) -> tuple[SupplyChainFinding, ...]:
    protected = {canonicalize_name(name) for name in protected_names if name}
    findings: list[SupplyChainFinding] = []
    for component in scan.components:
        name = canonicalize_name(str(component.get("name", "")))
        if not name or name in protected:
            continue
        closest = min(
            (
                (_edit_distance(name, candidate, maximum_distance), candidate)
                for candidate in protected
            ),
            default=(maximum_distance + 1, ""),
        )
        if closest[0] <= maximum_distance:
            findings.append(
                SupplyChainFinding(
                    kind="possible-typosquatting",
                    message="Dependency name is unusually similar to a protected package",
                    location=str(component.get("purl") or name),
                    severity="HIGH",
                    details={"component": name, "protected": closest[1]},
                )
            )
    return tuple(findings)


def _exception_matches(
    exception: Mapping[str, Any], finding: SupplyChainFinding, finding_id: str
) -> bool:
    selectors = {
        "id": finding_id,
        "kind": finding.kind,
        "location": finding.location,
        "severity": finding.severity,
        "vulnerability": str(finding.details.get("vulnerability", "")),
        "component": str(finding.details.get("component", "")),
    }
    present = False
    for key, actual in selectors.items():
        expected = exception.get(key)
        if expected is None:
            continue
        present = True
        if not fnmatch.fnmatch(actual, str(expected)):
            return False
    return present


def _parse_expiry(value: Any) -> dt.date | None:
    if value in {None, ""}:
        return None
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        return dt.date.min


def _edit_distance(left: str, right: str, limit: int) -> int:
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous_previous: list[int] | None = None
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        row_min = left_index
        for right_index, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_char != right_char),
                )
            )
            if (
                previous_previous is not None
                and left_index > 1
                and right_index > 1
                and left_char == right[right_index - 2]
                and left[left_index - 2] == right_char
            ):
                current[-1] = min(current[-1], previous_previous[right_index - 2] + 1)
            row_min = min(row_min, current[-1])
        if row_min > limit:
            return limit + 1
        previous_previous, previous = previous, current
    return previous[-1]
