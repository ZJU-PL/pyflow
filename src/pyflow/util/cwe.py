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


# Default actionable remediation guidance keyed by canonical CWE identifier.
# Used as a fallback whenever a rule pack or engine does not supply a more
# specific suggestion.
_CWE_DEFAULT_SUGGESTIONS: dict[str, str] = {
    "CWE-22": (
        "Resolve and canonicalize user-supplied paths (e.g. Path.resolve()) and verify "
        "the resulting path stays within an allowlisted base directory."
    ),
    "CWE-77": (
        "Avoid invoking shell interpreters with untrusted data; pass explicit argument "
        "lists (shell=False) and validate inputs against an allowlist."
    ),
    "CWE-78": (
        "Pass argument lists to subprocess.run(..., shell=False) instead of shell strings, "
        "and validate or allowlist any user-controlled command arguments."
    ),
    "CWE-79": (
        "Escape untrusted values for the target HTML/JS/URL context and rely on "
        "auto-escaping templates rather than building raw HTML strings."
    ),
    "CWE-89": (
        "Use parameterized queries or ORM bindings (e.g. cursor.execute(sql, (param,))) "
        "instead of concatenating or formatting untrusted input into SQL."
    ),
    "CWE-90": (
        "Escape untrusted values using an LDAP filter/DN escaping helper before "
        "constructing directory queries."
    ),
    "CWE-94": (
        "Avoid dynamically executing or compiling untrusted input; replace dynamic code "
        "evaluation with safe, explicit dispatch or data parsing."
    ),
    "CWE-95": (
        "Remove eval()/exec() on untrusted data; use ast.literal_eval(), json.loads(), "
        "or an explicit allowlist of operations instead."
    ),
    "CWE-117": (
        "Sanitize newlines and control characters in untrusted values before writing "
        "them to logs, or use structured logging."
    ),
    "CWE-134": (
        "Use constant format strings and pass untrusted values as positional/keyword "
        "arguments rather than formatting user-controlled templates."
    ),
    "CWE-200": (
        "Avoid exposing sensitive data or internal details in responses, logs, or error "
        "messages; filter fields before serialization."
    ),
    "CWE-295": (
        "Keep TLS certificate verification enabled (verify=True) and use the system "
        "trust store or an explicitly pinned CA bundle."
    ),
    "CWE-327": (
        "Replace broken or weak cryptographic primitives (e.g. MD5, SHA-1, DES, RC4) "
        "with modern algorithms such as SHA-256/SHA-3, AES-GCM, or ChaCha20-Poly1305."
    ),
    "CWE-404": (
        "Ensure resources are released on all exit paths (including exceptions), "
        "preferably by managing them with a 'with' context manager."
    ),
    "CWE-470": (
        "Validate dynamically imported module/attribute names against a strict "
        "allowlist before invoking importlib, getattr(), or setattr()."
    ),
    "CWE-476": (
        "Check that the value is not None (e.g. 'if x is not None:') or supply a safe "
        "non-None default before dereferencing it."
    ),
    "CWE-502": (
        "Never deserialize untrusted data with pickle, yaml.load(), or marshal; use "
        "safe data formats like JSON or yaml.safe_load()."
    ),
    "CWE-601": (
        "Validate redirect targets against an allowlist of trusted relative paths or "
        "hostnames before redirecting."
    ),
    "CWE-611": (
        "Disable external entity resolution and DTD processing, or use defusedxml when "
        "parsing untrusted XML."
    ),
    "CWE-667": (
        "Release acquired locks in a finally block or manage them with a 'with' " "context manager."
    ),
    "CWE-672": (
        "Keep all resource operations inside the open lifetime (e.g. inside a 'with' "
        "block) and do not use a resource after closing it."
    ),
    "CWE-675": (
        "Ensure each resource is closed only once, or delegate lifecycle cleanup to a "
        "'with' context manager."
    ),
    "CWE-798": (
        "Move hardcoded credentials and secrets out of source code into environment "
        "variables or a dedicated secrets manager."
    ),
    "CWE-918": (
        "Validate outbound URLs against an allowlist of schemes and hostnames, and "
        "block private/link-local/metadata IP ranges."
    ),
    "CWE-943": (
        "Validate and type-check untrusted inputs before constructing NoSQL query "
        "objects so attacker-controlled operators cannot be injected."
    ),
    "CWE-1321": (
        "Block writes to dunder/prototype attributes (e.g. __class__, __globals__, "
        "__init__) and validate attribute/key paths against an allowlist."
    ),
    "CWE-1336": (
        "Do not pass untrusted input as a template source; render static template files "
        "with untrusted data bound strictly as template context variables."
    ),
}


_RULE_SUFFIX_TO_CWE: tuple[tuple[str, str], ...] = (
    ("-UNSAFE_DESERIALIZATION", "CWE-502"),
    ("-EXECDESERIALIZATIONSINK", "CWE-502"),
    ("-DESERIALIZATION", "CWE-502"),
    ("-CLASS-POLLUTION", "CWE-1321"),
    ("-CLASS_POLLUTION", "CWE-1321"),
    ("-CODE_INJECTION", "CWE-95"),
    ("-PATH_TRAVERSAL", "CWE-22"),
    ("-OPEN_REDIRECT", "CWE-601"),
    ("-FORMATSTRING", "CWE-134"),
    ("-EXECIMPORTSINK", "CWE-470"),
    ("-EXECARGSINK", "CWE-78"),
    ("-EXECENVSINK", "CWE-78"),
    ("-REFLECTION", "CWE-470"),
    ("-WEAK_CRYPTO", "CWE-327"),
    ("-REDIRECT", "CWE-601"),
    ("-TEMPLATE", "CWE-1336"),
    ("-LOGGING", "CWE-117"),
    ("-COMMAND", "CWE-78"),
    ("-NULLNESS", "CWE-476"),
    ("-CRYPTO", "CWE-327"),
    ("-NOSQL", "CWE-943"),
    ("-SSRF", "CWE-918"),
    ("-SSTI", "CWE-1336"),
    ("-LDAP", "CWE-90"),
    ("-FILE", "CWE-22"),
    ("-PATH", "CWE-22"),
    ("-EVAL", "CWE-95"),
    ("-SQLI", "CWE-89"),
    ("-XSS", "CWE-79"),
    ("-SQL", "CWE-89"),
    ("-RCE", "CWE-78"),
    ("-XXE", "CWE-611"),
    ("-XML", "CWE-611"),
    ("-TLS", "CWE-295"),
    ("-CERT", "CWE-295"),
)


def default_cwe_for_rule_id(rule_id: str | None) -> str | None:
    """Infer a canonical CWE from a PyFlow rule identifier when the rule omits ``cwe``."""
    if not isinstance(rule_id, str) or not rule_id.strip():
        return None
    direct = normalize_cwe(rule_id)
    if direct:
        return direct
    upper = rule_id.strip().upper()
    for suffix, cwe in _RULE_SUFFIX_TO_CWE:
        if upper.endswith(suffix):
            return cwe
    return None


def default_cwe_suggestion(value: object) -> str:
    """Return a concise default remediation suggestion for *value* (CWE id), or ``""``."""
    for candidate in cwe_identifiers(value):
        suggestion = _CWE_DEFAULT_SUGGESTIONS.get(candidate)
        if suggestion:
            return suggestion
    return ""


def cwe_url(value: object) -> str:
    """Return the canonical MITRE CWE documentation URL for *value*, or ``""``."""
    norm = normalize_cwe(value)
    if not norm or not norm.startswith("CWE-"):
        return ""
    number = norm.split("-", 1)[1]
    return f"https://cwe.mitre.org/data/definitions/{number}.html" if number.isdigit() else ""


def cwe_sarif_tags(value: object) -> tuple[str, ...]:
    """Return SARIF rule tags for *value*, including GitHub Code Scanning's ``external/cwe/...`` tag."""
    norm = normalize_cwe(value)
    if not norm:
        return ()
    return (norm, f"external/cwe/{norm.lower()}")


def cwe_identifiers(value: object) -> tuple[str, ...]:
    """Return the primary CWE followed by its known ancestors."""
    primary = normalize_cwe(value)
    return (primary, *cwe_ancestors(primary)) if primary else ()
