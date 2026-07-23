"""Small shared helpers for safe local supply-chain input handling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from .models import ScanLimits, SupplyChainFinding


MAX_POLICY_FILE_SIZE = 10 * 1024 * 1024


def load_json_file(path: Path, *, max_size: int = MAX_POLICY_FILE_SIZE) -> Any:
    """Load a bounded UTF-8 JSON control file."""

    size = path.stat().st_size
    if size > max_size:
        raise ValueError(f"JSON file exceeds the {max_size}-byte safety limit")
    with path.open("rb") as handle:
        raw = handle.read(max_size + 1)
    if len(raw) > max_size:
        raise ValueError(f"JSON file exceeds the {max_size}-byte safety limit")
    return json.loads(raw.decode("utf-8"))


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
        with path.open("rb") as handle:
            raw = handle.read(limits.max_manifest_size + 1)
        if len(raw) > limits.max_manifest_size:
            findings.append(
                SupplyChainFinding(
                    kind="manifest-size-limit",
                    message=(
                        f"{description.capitalize()} grew beyond the configured "
                        "size limit while being read"
                    ),
                    location=str(path),
                    severity="HIGH",
                    details={
                        "size": len(raw),
                        "limit": limits.max_manifest_size,
                    },
                )
            )
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError as exc:
        findings.append(read_error(path, exc))
        return None


def redacted_url(value: str) -> str:
    parsed = urlparse(value)
    hostname = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        hostname = parsed.hostname or ""
        if parsed.port:
            hostname += f":{parsed.port}"
    sensitive = {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "key",
        "password",
        "secret",
        "signature",
        "sig",
        "token",
    }
    query = urlencode(
        [
            (key, "<redacted>" if key.casefold() in sensitive else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    return parsed._replace(netloc=hostname, query=query).geturl()


def contains_credentials(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.username is not None or parsed.password is not None:
        return True
    sensitive = {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "key",
        "password",
        "secret",
        "signature",
        "sig",
        "token",
    }
    return any(
        key.casefold() in sensitive
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True)
    )


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
