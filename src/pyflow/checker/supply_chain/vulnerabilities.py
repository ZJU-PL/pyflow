"""Offline vulnerability matching for local Python dependency inventories.

The matcher consumes OSV records from local JSON, JSONL, or directory exports.
It deliberately performs no network access so CI results can be reproduced and
the caller controls database freshness and trust.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Iterable, Iterator

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import SupplyChainFinding, SupplyChainScan


MAX_VULNERABILITY_DATABASE_FILE_SIZE = 512 * 1024 * 1024


def audit_vulnerabilities(
    scan: SupplyChainScan,
    databases: Iterable[str | os.PathLike[str]],
) -> tuple[SupplyChainFinding, ...]:
    """Match exact-version PyPI components against local OSV records."""

    findings: list[SupplyChainFinding] = []
    records: dict[str, dict[str, Any]] = {}
    for database in databases:
        path = Path(database)
        for record, source in _load_osv_records(path, findings):
            identifier = str(record.get("id", "")).strip()
            if not identifier:
                findings.append(
                    SupplyChainFinding(
                        kind="invalid-vulnerability-record",
                        message="OSV record does not declare an id",
                        location=str(source),
                        severity="LOW",
                    )
                )
                continue
            if record.get("withdrawn"):
                continue
            previous = records.get(identifier)
            if previous is None or str(record.get("modified", "")) > str(
                previous.get("modified", "")
            ):
                records[identifier] = record

    matched: set[tuple[str, str]] = set()
    unresolved: set[str] = set()
    for component in scan.components:
        name = canonicalize_name(str(component.get("name", "")))
        version_text = str(component.get("version", ""))
        purl = str(component.get("purl") or f"pkg:pypi/{name}")
        if not name:
            continue
        if not version_text:
            if purl not in unresolved:
                findings.append(
                    SupplyChainFinding(
                        kind="vulnerability-scan-unresolved-version",
                        message="Known-vulnerability matching requires an exact version",
                        location=purl,
                        severity="LOW",
                        details={"component": name},
                    )
                )
                unresolved.add(purl)
            continue

        for identifier, record in records.items():
            if (identifier, purl) in matched:
                continue
            affected_entries = record.get("affected", ()) or ()
            for affected in affected_entries:
                if not isinstance(affected, dict):
                    continue
                package = affected.get("package", {}) or {}
                ecosystem = str(package.get("ecosystem", "")).casefold()
                package_name = canonicalize_name(str(package.get("name", "")))
                if ecosystem not in {"pypi", "python"} or package_name != name:
                    continue
                if not _affected_version(version_text, affected):
                    continue
                findings.append(_vulnerability_finding(record, affected, component))
                matched.add((identifier, purl))
                break

    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.location,
                -_severity_rank(finding.severity),
                finding.kind,
                finding.message,
            ),
        )
    )


def _load_osv_records(
    path: Path,
    findings: list[SupplyChainFinding],
) -> Iterator[tuple[dict[str, Any], Path]]:
    if not path.exists():
        findings.append(
            SupplyChainFinding(
                kind="missing-vulnerability-database",
                message="Vulnerability database path does not exist",
                location=str(path),
                severity="HIGH",
            )
        )
        return
    if path.is_dir():
        try:
            children = sorted(
                child
                for child in path.rglob("*")
                if child.suffix.casefold() in {".json", ".jsonl", ".ndjson"}
            )
        except OSError as exc:
            findings.append(_database_read_error(path, exc))
            return
        for child in children:
            yield from _load_osv_records(child, findings)
        return
    if not path.is_file():
        findings.append(
            SupplyChainFinding(
                kind="invalid-vulnerability-database",
                message="Vulnerability database is not a regular file or directory",
                location=str(path),
                severity="HIGH",
            )
        )
        return
    try:
        size = path.stat().st_size
    except OSError as exc:
        findings.append(_database_read_error(path, exc))
        return
    if size > MAX_VULNERABILITY_DATABASE_FILE_SIZE:
        findings.append(
            SupplyChainFinding(
                kind="vulnerability-database-size-limit",
                message="Vulnerability database file exceeds the safety limit",
                location=str(path),
                severity="HIGH",
                details={
                    "size": size,
                    "limit": MAX_VULNERABILITY_DATABASE_FILE_SIZE,
                },
            )
        )
        return

    if path.suffix.casefold() in {".jsonl", ".ndjson"}:
        yield from _load_json_lines(path, findings)
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        findings.append(_database_read_error(path, exc))
        return
    except json.JSONDecodeError as exc:
        findings.append(
            SupplyChainFinding(
                kind="invalid-vulnerability-database",
                message="Vulnerability database is not valid JSON",
                location=str(path),
                severity="HIGH",
                details={"error": str(exc)},
            )
        )
        return

    if isinstance(data, dict) and data.get("id"):
        yield data, path
    elif isinstance(data, dict) and isinstance(data.get("vulns"), list):
        for record in data["vulns"]:
            if isinstance(record, dict):
                yield record, path
    elif isinstance(data, list):
        for record in data:
            if isinstance(record, dict):
                yield record, path
    else:
        findings.append(
            SupplyChainFinding(
                kind="invalid-vulnerability-database",
                message="JSON does not contain OSV records",
                location=str(path),
                severity="HIGH",
            )
        )


def _load_json_lines(
    path: Path,
    findings: list[SupplyChainFinding],
) -> Iterator[tuple[dict[str, Any], Path]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    findings.append(
                        SupplyChainFinding(
                            kind="invalid-vulnerability-record",
                            message="Could not parse OSV JSONL record",
                            location=str(path),
                            severity="LOW",
                            details={"line": line_no, "error": str(exc)},
                        )
                    )
                    continue
                if isinstance(record, dict):
                    yield record, path
    except OSError as exc:
        findings.append(_database_read_error(path, exc))


def _database_read_error(path: Path, exc: OSError) -> SupplyChainFinding:
    return SupplyChainFinding(
        kind="vulnerability-database-read-error",
        message="Could not read local vulnerability database",
        location=str(path),
        severity="HIGH",
        details={"error": str(exc)},
    )


def _affected_version(version_text: str, affected: dict[str, Any]) -> bool:
    explicit_versions = affected.get("versions", ()) or ()
    if any(
        _versions_equal(version_text, str(candidate)) for candidate in explicit_versions
    ):
        return True
    for range_data in affected.get("ranges", ()) or ():
        if not isinstance(range_data, dict):
            continue
        range_type = str(range_data.get("type", "")).upper()
        if range_type not in {"ECOSYSTEM", "SEMVER"}:
            continue
        if _events_match(version_text, range_data.get("events", ()) or ()):
            return True
    return False


def _events_match(version_text: str, events: Iterable[Any]) -> bool:
    vulnerable = False
    comparable = _parse_version(version_text)
    if comparable is None:
        return False
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event["introduced"])
            vulnerable = introduced == "0" or _version_at_least(comparable, introduced)
        elif "fixed" in event and _version_at_least(comparable, str(event["fixed"])):
            vulnerable = False
        elif "last_affected" in event:
            upper = _parse_version(str(event["last_affected"]))
            if upper is not None and comparable > upper:
                vulnerable = False
        elif "limit" in event and _version_at_least(comparable, str(event["limit"])):
            vulnerable = False
    return vulnerable


def _versions_equal(left: str, right: str) -> bool:
    parsed_left = _parse_version(left)
    parsed_right = _parse_version(right)
    if parsed_left is None or parsed_right is None:
        return left == right
    return parsed_left == parsed_right


def _version_at_least(version: Version, lower_text: str) -> bool:
    lower = _parse_version(lower_text)
    return lower is not None and version >= lower


def _parse_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _vulnerability_finding(
    record: dict[str, Any],
    affected: dict[str, Any],
    component: dict[str, Any],
) -> SupplyChainFinding:
    identifier = str(record.get("id", "UNKNOWN"))
    fixed_versions = sorted(
        {
            str(event["fixed"])
            for range_data in affected.get("ranges", ()) or ()
            if isinstance(range_data, dict)
            for event in range_data.get("events", ()) or ()
            if isinstance(event, dict) and event.get("fixed")
        }
    )
    details: dict[str, Any] = {
        "vulnerability": identifier,
        "component": component.get("name"),
        "version": component.get("version"),
        "aliases": sorted(str(alias) for alias in record.get("aliases", ()) or ()),
    }
    if fixed_versions:
        details["fixed_versions"] = fixed_versions
    if record.get("published"):
        details["published"] = record["published"]
    if record.get("modified"):
        details["modified"] = record["modified"]
    references = [
        str(reference.get("url"))
        for reference in record.get("references", ()) or ()
        if isinstance(reference, dict) and reference.get("url")
    ]
    if references:
        details["references"] = references[:10]

    summary = str(record.get("summary") or record.get("details") or identifier)
    if len(summary) > 240:
        summary = summary[:237].rstrip() + "..."
    return SupplyChainFinding(
        kind="known-vulnerability",
        message=f"{identifier}: {summary}",
        location=str(component.get("purl") or component.get("name", "")),
        severity=_osv_severity(record, affected),
        details=details,
    )


def _osv_severity(record: dict[str, Any], affected: dict[str, Any]) -> str:
    for container in (
        record.get("database_specific", {}) or {},
        affected.get("database_specific", {}) or {},
        affected.get("ecosystem_specific", {}) or {},
    ):
        value = str(container.get("severity", "")).upper()
        if value in {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}:
            return "MEDIUM" if value == "MODERATE" else value

    scores = []
    for severity in record.get("severity", ()) or ():
        if not isinstance(severity, dict):
            continue
        raw_score = severity.get("score")
        if raw_score is not None:
            try:
                scores.append(float(raw_score))
                continue
            except (TypeError, ValueError):
                pass
        if isinstance(raw_score, str):
            calculated = _cvss_v3_score(raw_score)
            if calculated is not None:
                scores.append(calculated)
    if not scores:
        return "HIGH"
    score = max(scores)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _cvss_v3_score(vector: str) -> float | None:
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None
    scope_changed = metrics["S"] == "C"
    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    pr_weights = (
        {"N": 0.85, "L": 0.68, "H": 0.5}
        if scope_changed
        else {"N": 0.85, "L": 0.62, "H": 0.27}
    )
    try:
        impact_base = 1 - (
            (1 - weights["CIA"][metrics["C"]])
            * (1 - weights["CIA"][metrics["I"]])
            * (1 - weights["CIA"][metrics["A"]])
        )
        if scope_changed:
            impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
        else:
            impact = 6.42 * impact_base
        if impact <= 0:
            return 0.0
        exploitability = (
            8.22
            * weights["AV"][metrics["AV"]]
            * weights["AC"][metrics["AC"]]
            * pr_weights[metrics["PR"]]
            * weights["UI"][metrics["UI"]]
        )
    except KeyError:
        return None
    total = (
        min(1.08 * (impact + exploitability), 10)
        if scope_changed
        else min(impact + exploitability, 10)
    )
    return math.ceil(total * 10) / 10


def _severity_rank(value: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)
