"""Small shared helpers for safe local supply-chain input handling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse

from .models import ScanLimits, SupplyChainFinding

MAX_POLICY_FILE_SIZE = 10 * 1024 * 1024

_SENSITIVE_URL_KEYS = frozenset(
    {
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
)

# Login names that identify a public VCS transport rather than a secret.
_PUBLIC_VCS_USERNAMES = frozenset({"git", "hg", "svn", "anonymous", "ftp"})


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
        # utf-8-sig transparently strips a BOM while accepting normal UTF-8.
        return raw.decode("utf-8-sig", errors="replace")
    except OSError as exc:
        findings.append(read_error(path, exc))
        return None


def redacted_url(value: str) -> str:
    parsed = urlparse(value)
    hostname = parsed.netloc
    if _userinfo_is_secret(parsed):
        hostname = parsed.hostname or ""
        if parsed.port:
            hostname += f":{parsed.port}"
    query = urlencode(
        [
            (key, "<redacted>" if key.casefold() in _SENSITIVE_URL_KEYS else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    return parsed._replace(
        netloc=hostname,
        query=query,
        fragment=_redact_fragment(parsed.fragment),
    ).geturl()


def contains_credentials(value: str) -> bool:
    parsed = urlparse(value)
    if _userinfo_is_secret(parsed):
        return True
    if any(
        key.casefold() in _SENSITIVE_URL_KEYS
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True)
    ):
        return True
    return _fragment_has_credentials(parsed.fragment)


def _userinfo_is_secret(parsed: Any) -> bool:
    """Return whether URL userinfo carries a secret.

    ``git+ssh://git@github.com/...`` is a public transport login, not a
    credential.  A password, or a token supplied as the username of an HTTP(S)
    URL, is still treated as sensitive.
    """

    if parsed.password is not None:
        return True
    username = parsed.username
    if username is None:
        return False
    if unquote(username).casefold() in _PUBLIC_VCS_USERNAMES:
        return False
    scheme = parsed.scheme.casefold()
    for prefix in ("git+", "hg+", "svn+", "bzr+"):
        scheme = scheme.removeprefix(prefix)
    return scheme in {"http", "https", "ftp", "ftps"}


def _fragment_has_credentials(fragment: str) -> bool:
    return any(
        key.casefold() in _SENSITIVE_URL_KEYS
        for key, _value in parse_qsl(fragment, keep_blank_values=True)
    )


def _redact_fragment(fragment: str) -> str:
    if not fragment:
        return fragment
    parts: list[str] = []
    for part in fragment.split("&"):
        key, separator, _value = part.partition("=")
        if separator and key.casefold() in _SENSITIVE_URL_KEYS:
            parts.append(f"{key}=<redacted>")
        else:
            parts.append(part)
    return "&".join(parts)


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
