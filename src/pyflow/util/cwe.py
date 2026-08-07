"""Small, explicit CWE taxonomy helpers used by security reporting."""

from __future__ import annotations

import re


_CWE_PATTERN = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)

# These are direct MITRE CWE parent relationships used by PyFlow's current
# injection rules. Keep this table deliberately explicit: related weaknesses
# must not be treated as ancestors merely to improve benchmark matching.
_CWE_PARENTS: dict[str, tuple[str, ...]] = {
    "CWE-78": ("CWE-77",),
    "CWE-95": ("CWE-94",),
}


def normalize_cwe(value: object) -> str | None:
    """Return a canonical ``CWE-<number>`` identifier when valid."""
    if isinstance(value, dict):
        value = value.get("id")
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    if not isinstance(value, str):
        return None
    match = _CWE_PATTERN.fullmatch(value.strip())
    return f"CWE-{int(match.group(1))}" if match else None


def cwe_ancestors(value: object) -> tuple[str, ...]:
    """Return known CWE ancestors, nearest parent first."""
    primary = normalize_cwe(value)
    if primary is None:
        return ()
    ancestors: list[str] = []
    pending = list(_CWE_PARENTS.get(primary, ()))
    seen = {primary}
    while pending:
        candidate = pending.pop(0)
        if candidate in seen:
            continue
        seen.add(candidate)
        ancestors.append(candidate)
        pending.extend(_CWE_PARENTS.get(candidate, ()))
    return tuple(ancestors)


def cwe_identifiers(value: object) -> tuple[str, ...]:
    """Return the primary CWE followed by its known ancestors."""
    primary = normalize_cwe(value)
    return (primary, *cwe_ancestors(primary)) if primary else ()
