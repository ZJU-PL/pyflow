"""Small shared helpers for safe local supply-chain input handling."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .models import ScanLimits, SupplyChainFinding


def read_error(path: Path, exc: OSError) -> SupplyChainFinding:
    return SupplyChainFinding(
        kind="file-read-error",
        message="Could not inspect local supply-chain input",
        location=str(path),
        severity="MEDIUM",
        details={"error": str(exc)},
    )


def read_text(
    path: Path,
    findings: list[SupplyChainFinding],
    limits: ScanLimits,
    description: str,
) -> str | None:
    try:
        size = path.stat().st_size
        if size > limits.max_manifest_size:
            findings.append(
                SupplyChainFinding(
                    kind="manifest-size-limit",
                    message=f"{description.capitalize()} exceeds the configured size limit",
                    location=str(path),
                    severity="HIGH",
                    details={"size": size, "limit": limits.max_manifest_size},
                )
            )
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        findings.append(read_error(path, exc))
        return None


def redacted_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.username is None and parsed.password is None:
        return value
    hostname = parsed.hostname or ""
    if parsed.port:
        hostname += f":{parsed.port}"
    return parsed._replace(netloc=hostname).geturl()


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
