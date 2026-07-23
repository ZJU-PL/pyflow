"""License metadata normalization and allowlist policy checks."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from .models import SupplyChainFinding, SupplyChainScan


DEFAULT_ALLOWED_LICENSES: frozenset[str] = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Python-2.0",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "Unlicense",
        "CC0-1.0",
        "ISC",
        "Zlib",
        "PSF-2.0",
        "PostgreSQL",
    }
)

_SPDX_OPERATORS = frozenset({"AND", "OR", "WITH"})
DEFAULT_ALLOWED_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "Classpath-exception-2.0",
        "GCC-exception-3.1",
        "LLVM-exception",
        "Autoconf-exception-3.0",
    }
)


class _LicenseExpressionError(ValueError):
    pass


class _LicenseExpressionParser:
    """Small SPDX-expression parser used for policy evaluation.

    ``packaging`` can canonicalize SPDX expressions in recent releases, but
    PyFlow supports Python environments with older packaging versions too.  A
    local parser keeps policy semantics correct without introducing a hard
    dependency solely for boolean expression evaluation.
    """

    _token_re = re.compile(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*")

    def __init__(self, expression: str) -> None:
        self.tokens: list[str] = self._token_re.findall(expression)
        compact = re.sub(r"\s+", "", expression)
        if "".join(self.tokens) != compact:
            raise _LicenseExpressionError("expression contains invalid characters")
        self.index = 0

    def parse(self) -> tuple[Any, ...]:
        if not self.tokens:
            raise _LicenseExpressionError("expression is empty")
        result = self._parse_or()
        if self.index != len(self.tokens):
            raise _LicenseExpressionError(
                f"unexpected token {self.tokens[self.index]!r}"
            )
        return result

    def _parse_or(self) -> tuple[Any, ...]:
        result = self._parse_and()
        while self._accept("OR"):
            result = ("OR", result, self._parse_and())
        return result

    def _parse_and(self) -> tuple[Any, ...]:
        result = self._parse_with()
        while self._accept("AND"):
            result = ("AND", result, self._parse_with())
        return result

    def _parse_with(self) -> tuple[Any, ...]:
        result = self._parse_primary()
        if self._accept("WITH"):
            if result[0] != "LICENSE":
                raise _LicenseExpressionError(
                    "WITH must follow a single license identifier"
                )
            exception = self._identifier()
            result = ("WITH", result, exception)
        return result

    def _parse_primary(self) -> tuple[Any, ...]:
        if self._accept("("):
            result = self._parse_or()
            if not self._accept(")"):
                raise _LicenseExpressionError("missing closing parenthesis")
            return result
        return ("LICENSE", self._identifier())

    def _identifier(self) -> str:
        if self.index >= len(self.tokens):
            raise _LicenseExpressionError("expected a license identifier")
        token = self.tokens[self.index]
        if token.upper() in _SPDX_OPERATORS or token in {"(", ")"}:
            raise _LicenseExpressionError(f"expected identifier, found {token!r}")
        self.index += 1
        return token

    def _accept(self, token: str) -> bool:
        if self.index >= len(self.tokens):
            return False
        current = self.tokens[self.index]
        matches: bool = (
            current == token if token in {"(", ")"} else current.upper() == token
        )
        if matches:
            self.index += 1
        return matches


def audit_license_policy(
    scan: SupplyChainScan,
    *,
    allowed_licenses: Iterable[str] | None = None,
    allowed_exceptions: Iterable[str] | None = None,
) -> tuple[SupplyChainFinding, ...]:
    """Check components against an SPDX-aware license allowlist.

    OR expressions pass when at least one choice is acceptable, AND
    expressions require every term, and WITH expressions require both the
    base license and an allowed exception.
    """

    allowed = (
        frozenset(allowed_licenses)
        if allowed_licenses is not None
        else DEFAULT_ALLOWED_LICENSES
    )
    exceptions = frozenset(
        DEFAULT_ALLOWED_EXCEPTIONS if allowed_exceptions is None else allowed_exceptions
    )
    findings: list[SupplyChainFinding] = []

    for component in scan.components:
        name = component.get("name", "")
        purl = component.get("purl", name)
        licenses = component.get("licenses", [])
        if not licenses:
            findings.append(
                SupplyChainFinding(
                    kind="license-not-declared",
                    message=f"Component {name} has no declared license",
                    location=purl,
                    severity="LOW",
                )
            )
            continue

        choices_allowed: list[bool] = []
        rejected: set[str] = set()
        for license_choice in licenses:
            expression = license_choice.get("expression")
            if expression:
                expression_text = str(expression)
                try:
                    parsed = _LicenseExpressionParser(expression_text).parse()
                except _LicenseExpressionError as exc:
                    findings.append(
                        SupplyChainFinding(
                            kind="invalid-license-expression",
                            message=f"Component {name} has an invalid SPDX expression",
                            location=purl,
                            severity="MEDIUM",
                            details={"expression": expression_text, "error": str(exc)},
                        )
                    )
                    continue
                accepted, denied = _evaluate_license_expression(
                    parsed, allowed, exceptions
                )
                choices_allowed.append(accepted)
                rejected.update(denied)
                continue
            inner = license_choice.get("license", {})
            identifier = inner.get("id") or inner.get("name")
            if identifier:
                identifier_text = str(identifier)
                accepted = identifier_text in allowed
                choices_allowed.append(accepted)
                if not accepted:
                    rejected.add(identifier_text)

        # Multiple license-choice objects are alternatives in CycloneDX.  Do
        # not reject a component when at least one declared choice is allowed.
        if choices_allowed and not any(choices_allowed):
            findings.append(
                SupplyChainFinding(
                    kind="license-not-allowed",
                    message=f"No declared license choice for {name} is allowed",
                    location=purl,
                    severity="MEDIUM",
                    details={
                        "licenses": sorted(rejected),
                        "component": name,
                    },
                )
            )

    return tuple(findings)


def licenses_from_metadata(data: Any) -> list[dict[str, Any]]:
    expression = data.get("License-Expression")
    if expression:
        return [{"expression": str(expression).strip()}]

    licenses: list[dict[str, Any]] = []
    if license_text := data.get("License"):
        licenses.append(license_entry(license_text))
    for classifier in data.get_all("Classifier", []) or []:
        if classifier.startswith("License ::"):
            classifier_text = classifier.strip()
            mapped = _TROVE_LICENSES.get(classifier_text)
            licenses.append(
                license_entry(mapped or classifier.rsplit("::", 1)[-1].strip())
            )
    unique: dict[str, dict[str, Any]] = {}
    for item in licenses:
        key = json.dumps(item, sort_keys=True)
        unique[key] = item
    return list(unique.values())


def license_entry(value: str) -> dict[str, dict[str, str]]:
    value = _LICENSE_ALIASES.get(value.strip().casefold(), value.strip())
    if value and " " not in value and len(value) <= 64:
        return {"license": {"id": value}}
    return {"license": {"name": value}}


def _evaluate_license_expression(
    node: tuple[Any, ...],
    allowed: frozenset[str],
    allowed_exceptions: frozenset[str],
) -> tuple[bool, set[str]]:
    operation = node[0]
    if operation == "LICENSE":
        identifier = str(node[1])
        return identifier in allowed, set() if identifier in allowed else {identifier}
    if operation == "WITH":
        base_allowed, rejected = _evaluate_license_expression(
            node[1], allowed, allowed_exceptions
        )
        exception = str(node[2])
        exception_allowed = exception in allowed_exceptions
        if not exception_allowed:
            rejected.add(exception)
        return base_allowed and exception_allowed, rejected
    left_allowed, left_rejected = _evaluate_license_expression(
        node[1], allowed, allowed_exceptions
    )
    right_allowed, right_rejected = _evaluate_license_expression(
        node[2], allowed, allowed_exceptions
    )
    if operation == "AND":
        return left_allowed and right_allowed, left_rejected | right_rejected
    if operation == "OR":
        if left_allowed or right_allowed:
            return True, set()
        return False, left_rejected | right_rejected
    raise _LicenseExpressionError(f"unknown expression operation {operation!r}")


_TROVE_LICENSES = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
}

_LICENSE_ALIASES = {
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "isc license": "ISC",
    "mit license": "MIT",
    "mozilla public license 2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
}
