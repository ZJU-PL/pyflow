"""Offline vulnerability matching for local Python dependency inventories.

The matcher consumes OSV records from local JSON, JSONL, or directory exports.
It deliberately performs no network access so CI results can be reproduced and
the caller controls database freshness and trust.
"""

from __future__ import annotations

import json
import hashlib
import math
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import SupplyChainFinding, SupplyChainScan
from .vex import load_vex, vex_status_for


MAX_VULNERABILITY_DATABASE_FILE_SIZE = 512 * 1024 * 1024
MAX_VULNERABILITY_JSON_FILE_SIZE = 64 * 1024 * 1024
MAX_VULNERABILITY_DATABASE_FILES = 100_000
MAX_VULNERABILITY_RECORD_SIZE = 10 * 1024 * 1024


def audit_vulnerabilities(
    scan: SupplyChainScan,
    databases: Iterable[str | os.PathLike[str]],
    *,
    max_database_age_days: float | None = None,
    require_hashes: bool = False,
    vex_documents: Iterable[str | os.PathLike[str]] = (),
    reachable_refs: frozenset[str] | None = None,
    trusted_hashes: Mapping[str, str] | None = None,
) -> tuple[SupplyChainFinding, ...]:
    """Match exact-version PyPI components against local OSV records."""

    if max_database_age_days is not None and (
        not math.isfinite(max_database_age_days) or max_database_age_days < 0
    ):
        raise ValueError("max_database_age_days must be finite and non-negative")
    findings: list[SupplyChainFinding] = []
    vex_statuses = load_vex(vex_documents, findings)
    records: dict[str, dict[str, Any]] = {}
    for database in databases:
        path = Path(database)
        _audit_database_source(
            path,
            findings,
            max_age_days=max_database_age_days,
            require_hash=require_hashes,
            trusted_hashes=trusted_hashes or {},
        )
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

    records_by_package: dict[str, list[tuple[str, dict[str, Any], dict[str, Any]]]] = (
        defaultdict(list)
    )
    for identifier, record in records.items():
        for affected in record.get("affected", ()) or ():
            if not isinstance(affected, dict):
                continue
            package = affected.get("package", {}) or {}
            ecosystem = str(package.get("ecosystem", "")).casefold()
            package_name = canonicalize_name(str(package.get("name", "")))
            if ecosystem in {"pypi", "python"} and package_name:
                records_by_package[package_name].append((identifier, record, affected))

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

        for identifier, record, affected in records_by_package.get(name, ()):
            if (identifier, purl) in matched:
                continue
            if not _affected_version(version_text, affected):
                continue
            vex = vex_status_for(vex_statuses, identifier, purl, name)
            if vex and vex.get("status") in {
                "not-affected",
                "resolved",
                "fixed",
                "false-positive",
            }:
                if not str(vex.get("justification", "")).strip():
                    findings.append(
                        SupplyChainFinding(
                            kind="vex-missing-justification",
                            message=(
                                f"{identifier} has a suppressing VEX status without "
                                "a justification"
                            ),
                            location=purl,
                            severity="MEDIUM",
                            details={
                                "vulnerability": identifier,
                                "component": name,
                                "status": vex.get("status"),
                            },
                        )
                    )
                else:
                    findings.append(
                        SupplyChainFinding(
                            kind="vulnerability-suppressed-by-vex",
                            message=(
                                f"{identifier} is suppressed by an applicable "
                                "VEX statement"
                            ),
                            location=purl,
                            severity="LOW",
                            details={
                                "vulnerability": identifier,
                                "component": name,
                                "status": vex.get("status"),
                                "justification": vex.get("justification", ""),
                            },
                        )
                    )
                    matched.add((identifier, purl))
                    continue
            reachability = None
            if reachable_refs is not None:
                reachability = "observed" if purl in reachable_refs else "not-observed"
            findings.append(
                _vulnerability_finding(
                    record, affected, component, reachability=reachability
                )
            )
            matched.add((identifier, purl))

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
    if path.is_symlink():
        findings.append(
            SupplyChainFinding(
                kind="vulnerability-database-symlink",
                message="Vulnerability database symlinks are not followed",
                location=str(path),
                severity="HIGH",
            )
        )
        return
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
            children: list[Path] = []
            for child in path.rglob("*"):
                if child.is_symlink() or child.suffix.casefold() not in {
                    ".json",
                    ".jsonl",
                    ".ndjson",
                }:
                    continue
                children.append(child)
                if len(children) > MAX_VULNERABILITY_DATABASE_FILES:
                    findings.append(
                        SupplyChainFinding(
                            kind="vulnerability-database-file-limit",
                            message="Vulnerability database exceeds the file-count limit",
                            location=str(path),
                            severity="HIGH",
                            details={"limit": MAX_VULNERABILITY_DATABASE_FILES},
                        )
                    )
                    return
            children.sort()
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
    is_json_lines = path.suffix.casefold() in {".jsonl", ".ndjson"}
    size_limit = (
        MAX_VULNERABILITY_DATABASE_FILE_SIZE
        if is_json_lines
        else MAX_VULNERABILITY_JSON_FILE_SIZE
    )
    if size > size_limit:
        findings.append(
            SupplyChainFinding(
                kind="vulnerability-database-size-limit",
                message="Vulnerability database file exceeds the safety limit",
                location=str(path),
                severity="HIGH",
                details={
                    "size": size,
                    "limit": size_limit,
                },
            )
        )
        return

    if is_json_lines:
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
            line_no = 0
            while True:
                line = handle.readline(MAX_VULNERABILITY_RECORD_SIZE + 1)
                if not line:
                    break
                line_no += 1
                if len(line) > MAX_VULNERABILITY_RECORD_SIZE:
                    findings.append(
                        SupplyChainFinding(
                            kind="vulnerability-record-size-limit",
                            message="OSV JSONL record exceeds the safety limit",
                            location=str(path),
                            severity="HIGH",
                            details={
                                "line": line_no,
                                "limit": MAX_VULNERABILITY_RECORD_SIZE,
                            },
                        )
                    )
                    while line and not line.endswith("\n"):
                        line = handle.readline(MAX_VULNERABILITY_RECORD_SIZE + 1)
                    continue
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
            # A future introduced event starts another interval; it must not
            # erase a match from an earlier still-open interval.
            if introduced == "0" or _version_at_least(comparable, introduced):
                vulnerable = True
        elif "fixed" in event and _version_at_least(comparable, str(event["fixed"])):
            vulnerable = False
        elif "last_affected" in event:
            upper = _parse_version(str(event["last_affected"]))
            if upper is not None and comparable > upper:
                vulnerable = False
        elif "limit" in event and _version_at_least(comparable, str(event["limit"])):
            vulnerable = False
    return vulnerable


def _audit_database_source(
    path: Path,
    findings: list[SupplyChainFinding],
    *,
    max_age_days: float | None,
    require_hash: bool,
    trusted_hashes: Mapping[str, str],
) -> None:
    """Audit freshness and optional SHA-256 sidecars for local OSV data."""

    if not path.exists():
        return
    files: list[Path]
    if path.is_dir():
        try:
            files = []
            for child in path.rglob("*"):
                if (
                    child.is_file()
                    and not child.is_symlink()
                    and child.suffix.casefold() in {".json", ".jsonl", ".ndjson"}
                ):
                    files.append(child)
                    if len(files) > MAX_VULNERABILITY_DATABASE_FILES:
                        return
        except OSError:
            return
    else:
        files = [path]

    if max_age_days is not None:
        threshold = time.time() - max_age_days * 86400
        stale: list[str] = []
        for source in files:
            try:
                if source.stat().st_mtime < threshold:
                    stale.append(str(source))
            except OSError:
                continue
        if stale:
            findings.append(
                SupplyChainFinding(
                    kind="stale-vulnerability-database",
                    message="Local vulnerability data exceeds the configured maximum age",
                    location=str(path),
                    severity="HIGH",
                    details={"max_age_days": max_age_days, "stale_files": stale[:20]},
                )
            )

    for source in files:
        trusted = _trusted_digest_for(source, trusted_hashes)
        if trusted is not None:
            try:
                actual = _sha256_file(source)
            except OSError as exc:
                findings.append(_database_read_error(source, exc))
                continue
            if not _is_sha256(trusted) or actual != trusted:
                findings.append(
                    SupplyChainFinding(
                        kind="vulnerability-database-trusted-digest-mismatch",
                        message="Vulnerability database does not match its trusted SHA-256 digest",
                        location=str(source),
                        severity="CRITICAL",
                        details={"expected": trusted, "actual": actual},
                    )
                )
            continue
        sidecar = Path(str(source) + ".sha256")
        if not sidecar.is_file():
            if require_hash:
                findings.append(
                    SupplyChainFinding(
                        kind="vulnerability-database-missing-checksum",
                        message="Vulnerability database has no SHA-256 sidecar",
                        location=str(source),
                        severity="HIGH",
                    )
                )
            continue
        try:
            expected = sidecar.read_text(encoding="utf-8").split()[0].lower()
            actual = _sha256_file(source)
        except OSError as exc:
            findings.append(_database_read_error(sidecar, exc))
            continue
        except IndexError:
            findings.append(
                SupplyChainFinding(
                    kind="invalid-vulnerability-database-checksum",
                    message="Vulnerability database checksum sidecar is empty",
                    location=str(sidecar),
                    severity="HIGH",
                )
            )
            continue
        if not _is_sha256(expected) or actual != expected:
            findings.append(
                SupplyChainFinding(
                    kind="vulnerability-database-checksum-mismatch",
                    message="Vulnerability database SHA-256 verification failed",
                    location=str(source),
                    severity="CRITICAL",
                    details={"expected": expected, "actual": actual},
                )
            )


def _trusted_digest_for(path: Path, trusted_hashes: Mapping[str, str]) -> str | None:
    candidates = (str(path), str(path.resolve(strict=False)), path.name)
    for candidate in candidates:
        value = trusted_hashes.get(candidate)
        if value is not None:
            return str(value).strip().lower()
    return None


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _versions_equal(left: str, right: str) -> bool:
    parsed_left = _parse_version(left)
    parsed_right = _parse_version(right)
    if parsed_left is None or parsed_right is None:
        return left == right
    return bool(parsed_left == parsed_right)


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
    *,
    reachability: str | None = None,
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
    if reachability is not None:
        details["reachability"] = reachability
        details["reachability_is_conclusive"] = False
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
