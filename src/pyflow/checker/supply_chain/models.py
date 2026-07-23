"""Shared data models for supply-chain scanning and policy checks."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any


MIB = 1024 * 1024
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class ScanLimits:
    """Resource budgets applied while scanning untrusted local inputs."""

    max_manifest_size: int = 10 * MIB
    max_archive_size: int = 5_000 * MIB
    max_archive_members: int = 10_000
    max_archive_member_size: int = 100 * MIB
    max_archive_uncompressed_size: int = 1_000 * MIB
    max_compression_ratio: float = 200.0
    max_archive_depth: int = 3
    max_scan_entries: int = 200_000


@dataclass(frozen=True)
class SupplyChainFinding:
    """A local supply-chain risk or metadata anomaly."""

    kind: str
    message: str
    location: str
    severity: str = "MEDIUM"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fingerprint_input = json.dumps(
            [
                self.kind,
                _fingerprint_location(self.location),
                _fingerprint_value(self.details),
            ],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return {
            "id": hashlib.sha256(fingerprint_input).hexdigest()[:20],
            "kind": self.kind,
            "message": self.message,
            "location": self.location,
            "severity": self.severity,
            "details": self.details,
        }


def _fingerprint_location(location: str) -> str:
    """Make workspace-local finding IDs stable across CI checkout paths."""

    outer, separator, member = location.partition("!/")
    try:
        relative = (
            Path(outer)
            .resolve(strict=False)
            .relative_to(Path.cwd().resolve(strict=False))
        )
    except (OSError, ValueError):
        return location
    normalized = relative.as_posix()
    return f"{normalized}!/{member}" if separator else normalized


def _fingerprint_value(value: Any) -> Any:
    volatile = {"error", "published", "modified", "references", "stale_files"}
    if isinstance(value, dict):
        return {
            key: _fingerprint_value(item)
            for key, item in sorted(value.items())
            if key not in volatile
        }
    if isinstance(value, (list, tuple)):
        return [_fingerprint_value(item) for item in value]
    if isinstance(value, str):
        return _fingerprint_location(value)
    return value


@dataclass(frozen=True)
class SupplyChainScan:
    """Components and findings discovered from local supply-chain inputs."""

    components: tuple[dict[str, Any], ...]
    findings: tuple[SupplyChainFinding, ...]
    dependencies: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


def validate_limits(limits: ScanLimits) -> None:
    integer_limits = {
        "max_manifest_size": limits.max_manifest_size,
        "max_archive_size": limits.max_archive_size,
        "max_archive_members": limits.max_archive_members,
        "max_archive_member_size": limits.max_archive_member_size,
        "max_archive_uncompressed_size": limits.max_archive_uncompressed_size,
        "max_archive_depth": limits.max_archive_depth,
        "max_scan_entries": limits.max_scan_entries,
    }
    invalid = [name for name, value in integer_limits.items() if value < 0]
    if (
        not math.isfinite(limits.max_compression_ratio)
        or limits.max_compression_ratio <= 0
    ):
        invalid.append("max_compression_ratio")
    if invalid:
        raise ValueError(f"Scan limits must be non-negative: {', '.join(invalid)}")
