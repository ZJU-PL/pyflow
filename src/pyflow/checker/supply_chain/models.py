"""Shared data models for supply-chain scanning and policy checks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


MIB = 1024 * 1024
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class ScanLimits:
    """Resource budgets applied while scanning untrusted local inputs."""

    max_manifest_size: int = 10 * MIB
    max_archive_members: int = 10_000
    max_archive_member_size: int = 100 * MIB
    max_archive_uncompressed_size: int = 1_000 * MIB
    max_compression_ratio: float = 200.0
    max_archive_depth: int = 3


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
            [self.kind, self.location, self.details],
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


@dataclass(frozen=True)
class SupplyChainScan:
    """Components and findings discovered from local supply-chain inputs."""

    components: tuple[dict[str, Any], ...]
    findings: tuple[SupplyChainFinding, ...]
    dependencies: tuple[dict[str, Any], ...] = ()


def validate_limits(limits: ScanLimits) -> None:
    integer_limits = {
        "max_manifest_size": limits.max_manifest_size,
        "max_archive_members": limits.max_archive_members,
        "max_archive_member_size": limits.max_archive_member_size,
        "max_archive_uncompressed_size": limits.max_archive_uncompressed_size,
        "max_archive_depth": limits.max_archive_depth,
    }
    invalid = [name for name, value in integer_limits.items() if value < 0]
    if limits.max_compression_ratio <= 0:
        invalid.append("max_compression_ratio")
    if invalid:
        raise ValueError(f"Scan limits must be non-negative: {', '.join(invalid)}")
