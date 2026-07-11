"""
Shadow-scan differential pattern for IFDS failure attribution.

Runs a lightweight regex-only scan alongside the full IFDS analysis and
diffs the results to attribute every FN/FP to a specific analyzer gap.

Categories:
  - ``both_hit``    — both engines found it (high confidence)
  - ``ifds_only``   — only IFDS found it (potential FP from false flow)
  - ``shadow_only`` — only shadow found it (potential FN from broken flow)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

SHADOW_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "CWE-78",
        "critical",
        "shell injection",
        re.compile(
            r"shell\s*=\s*True|subprocess\.(?:run|call|Popen|check_output)",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-89",
        "critical",
        "SQL injection",
        re.compile(
            r"(?:execute|cursor)\.\s*(?:execute|executemany)\s*\([^\n]*?(?:\+|%|\.format|f[\"'])",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-95",
        "critical",
        "eval/exec",
        re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(", re.IGNORECASE),
    ),
    (
        "CWE-79",
        "high",
        "XSS",
        re.compile(
            r"render_template\s*\([^\n]*request\.|innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-918",
        "high",
        "SSRF",
        re.compile(
            r"requests\.(?:get|post|put|delete|head|request)\s*\(\s*\w+|fetch\s*\(\s*\w+|urllib\.request\.urlopen\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-22",
        "high",
        "path traversal",
        re.compile(
            r"os\.path\.join\s*\(|open\s*\([^\n]*?(?:request\.|req\.|filename|path|\.\./)",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-601",
        "medium",
        "open redirect",
        re.compile(
            r"(?:redirect|flask\.redirect)\s*\([^\n]*(?:request\.|req\.|\?)",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-502",
        "critical",
        "unsafe deserialization",
        re.compile(
            r"pickle\.(?:loads|load)\s*\(|yaml\.load\s*\(\s*(?!.*SafeLoader)|marshal\.loads\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-798",
        "high",
        "hardcoded secret",
        re.compile(
            r"(?:password|secret|api_key|token|auth_key)\s*=\s*[\"'][^\n]{6,}",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-327",
        "high",
        "weak crypto",
        re.compile(
            r"hashlib\.(?:md5|sha1)\s*\(|\"md5\"|\"sha1\"|MD5\s*\(\s*\"",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-611",
        "high",
        "XML external entity",
        re.compile(
            r"xml\.etree\.ElementTree\.(?:parse|iterparse)\s*\(|lxml\.etree\.parse\s*\(|minidom\.parse\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-1333",
        "medium",
        "ReDoS",
        re.compile(
            r"re\.compile\s*\(\s*[\"'][^\"']*(?:\([^)]*[+*][^)]*\)|\[[^\]]+\][+*][^\"']+|\(\.\*.)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class ShadowMatch:
    """A single shadow-pattern match in source code."""

    cwe: str
    severity: str
    label: str
    line: int
    pattern: str
    snippet: str


@dataclass(frozen=True)
class DiffEntry:
    """Attribution result for a single finding diff between IFDS and shadow."""

    cwe: str
    rule_id: str
    line: int
    category: str
    attribution: str
    flow_break_at: str
    heuristic_trigger: str


@dataclass(frozen=True)
class ShadowScanReport:
    """Full diff report between IFDS and shadow scans."""

    file_path: str
    language: str
    total_real: int
    total_shadow: int
    both_hit: tuple[DiffEntry, ...]
    ifds_only: tuple[DiffEntry, ...]
    shadow_only: tuple[DiffEntry, ...]

    @property
    def total_diffs(self) -> int:
        """Number of findings where the two engines disagreed."""
        return len(self.ifds_only) + len(self.shadow_only)


def _line_of_offset(code: str, offset: int) -> int:
    return code[:offset].count("\n") + 1


def _extract_snippet(code: str, start: int, end: int) -> str:
    snippet_start = max(0, start - 20)
    snippet_end = min(len(code), end + 40)
    return code[snippet_start:snippet_end].replace("\n", " ").strip()[:120]


def run_shadow_scan(
    code: str, language: str = "python"
) -> list[ShadowMatch]:
    """Run pattern-only shadow scan over source code.

    Returns a list of :class:`ShadowMatch` instances deduplicated by
    ``(cwe, line)``.
    """
    matches: list[ShadowMatch] = []
    seen: set[tuple[str, int]] = set()

    for cwe, severity, label, pattern in SHADOW_PATTERNS:
        for match in pattern.finditer(code):
            line = _line_of_offset(code, match.start())
            key = (cwe, line)
            if key in seen:
                continue
            seen.add(key)

            snippet = _extract_snippet(code, match.start(), match.end())

            matches.append(
                ShadowMatch(
                    cwe=cwe,
                    severity=severity,
                    label=label,
                    line=line,
                    pattern=pattern.pattern[:120],
                    snippet=snippet,
                )
            )

    return matches


def _build_ifds_map(ifds_findings: list[Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = defaultdict(list)
    for f in ifds_findings:
        cwe = (getattr(f, "cwe", "") or "").strip().upper()
        line = getattr(f, "line", 0) or 0
        if not cwe.startswith("CWE-"):
            continue
        key = f"{cwe}:{line}"
        grouped[key].append(f)
    return grouped


def _build_shadow_map(
    shadow_matches: list[ShadowMatch],
) -> dict[str, ShadowMatch]:
    return {f"{m.cwe}:{m.line}": m for m in shadow_matches}


def _attribute_ifds_only(cwe: str, finding: Any) -> str:
    return (
        f"IFDS-only finding ({cwe}) not matched by shadow patterns. "
        f"Shadow scan's simple regex cannot track interprocedural dataflow. "
        f"Review this finding for false-positive potential, especially if the flow "
        f"crosses multiple files or framework boundaries."
    )


def _attribute_shadow_only(match: ShadowMatch, cwe: str) -> str:
    return (
        f"Shadow pattern '{match.label}' matched at line {match.line} but the "
        f"IFDS engine did not produce a finding for {cwe}. Likely causes: "
        f"(1) taint flow broke at a function call boundary, "
        f"(2) sanitizer suppressed this path, "
        f"(3) source not recognised as user-controllable input, "
        f"(4) sink not in the IFDS sink catalog."
    )


def diff_scans(
    ifds_findings: list[Any],
    shadow_matches: list[ShadowMatch],
    *,
    file_path: str = "",
    language: str = "",
) -> ShadowScanReport:
    """Diff IFDS findings against shadow-pattern matches with attribution.

    IFDS findings are expected to have at minimum ``cwe`` and ``line``
    attributes.  Matching key is ``f"{cwe}:{line}"``.
    """
    real_map = _build_ifds_map(ifds_findings)
    shadow_map = _build_shadow_map(shadow_matches)

    all_keys = set(real_map.keys()) | set(shadow_map.keys())

    both_hit: list[DiffEntry] = []
    ifds_only: list[DiffEntry] = []
    shadow_only: list[DiffEntry] = []

    for key in sorted(all_keys):
        cwe, line_str = key.split(":") if ":" in key else ("", "0")
        line = int(line_str)

        real_hits = real_map.get(key, [])
        shadow_hit = shadow_map.get(key)

        if real_hits and shadow_hit:
            rule_id = getattr(real_hits[0], "rule_id", "") or ""
            both_hit.append(
                DiffEntry(
                    cwe=cwe,
                    rule_id=rule_id,
                    line=line,
                    category="both_hit",
                    attribution="Both engines detected this pattern — high confidence.",
                    flow_break_at="",
                    heuristic_trigger="",
                )
            )
        elif real_hits and not shadow_hit:
            rule_id = getattr(real_hits[0], "rule_id", "") or ""
            heuristic = getattr(real_hits[0], "analysis_kind", "") or ""
            ifds_only.append(
                DiffEntry(
                    cwe=cwe,
                    rule_id=rule_id,
                    line=line,
                    category="ifds_only",
                    attribution=_attribute_ifds_only(cwe, real_hits[0]),
                    flow_break_at="",
                    heuristic_trigger=heuristic,
                )
            )
        elif shadow_hit and not real_hits:
            shadow_only.append(
                DiffEntry(
                    cwe=cwe,
                    rule_id="",
                    line=line,
                    category="shadow_only",
                    attribution=_attribute_shadow_only(shadow_hit, cwe),
                    flow_break_at=(
                        f"Shadow hit at line {shadow_hit.line}: {shadow_hit.snippet}. "
                        f"Investigate whether this is a true source->sink flow "
                        f"that IFDS should track."
                    ),
                    heuristic_trigger="",
                )
            )

    return ShadowScanReport(
        file_path=file_path,
        language=language,
        total_real=len(ifds_findings),
        total_shadow=len(shadow_matches),
        both_hit=tuple(both_hit),
        ifds_only=tuple(ifds_only),
        shadow_only=tuple(shadow_only),
    )


def generate_shadow_report(
    code: str,
    ifds_findings: list[Any],
    *,
    file_path: str = "",
    language: str = "python",
) -> ShadowScanReport:
    """Run shadow scan and diff against IFDS findings — convenience API."""
    shadow_matches = run_shadow_scan(code, language)
    return diff_scans(
        ifds_findings, shadow_matches, file_path=file_path, language=language
    )
