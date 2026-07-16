"""Finding quality helpers for security reports.

The helpers in this module are intentionally independent of the pattern and
semantic checker runners.  Callers can apply them at CLI/reporting boundaries
without changing how analyses produce issues.
"""

from __future__ import annotations

import ast
import hashlib
import json
import linecache
import re
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .pattern.core import constants


_SUPPRESSION_RE = re.compile(
    r"#\s*pyflow\s*:\s*ignore\s*(?P<ids>[^-\n#]*)(?:--(?P<reason>.*))?",
    re.IGNORECASE,
)
_RULE_ID_RE = re.compile(r"[A-Z][A-Z0-9_-]*\d+[A-Z0-9_-]*|B\d+", re.ASCII)
_BASELINE_VERSION = 1
_AUTH_GUARD_RE = re.compile(
    r"is_authenticated|login_required|permission_required|has_permission|"
    r"require_auth|current_user|request\.user",
    re.IGNORECASE,
)
_VALIDATION_GUARD_RE = re.compile(
    r"isinstance|\.isdigit|\.isalnum|allowed_|validate|startswith|commonpath|"
    r"is_relative_to",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SuppressionDirective:
    """A parsed inline suppression directive."""

    line: int
    rule_ids: frozenset[str]
    reason: str = ""

    @property
    def suppresses_all(self) -> bool:
        return not self.rule_ids


class BareSuppressionWarning(UserWarning):
    """Emitted when a broad suppression omits a rule ID."""


@dataclass(frozen=True)
class GuardInfo:
    """A lightweight security guard and the lines it protects."""

    kind: str
    line: int
    protects_lines: frozenset[int]


def parse_suppressions(
    source: str,
    *,
    file_path: str = "<unknown>",
    warn_bare: bool = True,
) -> dict[int, SuppressionDirective]:
    """Parse ``# pyflow: ignore`` comments by 1-based line number.

    Empty ``rule_ids`` means a bare suppression that suppresses every rule on
    that line.  Bare suppressions are accepted for compatibility with quick
    triage, but callers can keep ``warn_bare`` enabled to make them visible.
    """

    directives: dict[int, SuppressionDirective] = {}
    for line_number, line in enumerate(source.splitlines(), start=1):
        match = _SUPPRESSION_RE.search(line)
        if match is None:
            continue

        ids_text = (match.group("ids") or "").strip()
        reason = (match.group("reason") or "").strip()
        rule_ids = frozenset(_RULE_ID_RE.findall(ids_text))
        if not rule_ids and warn_bare:
            warnings.warn(
                f"{file_path}:{line_number}: bare `# pyflow: ignore` suppresses "
                "all rules on this line; prefer `# pyflow: ignore RULE-ID`.",
                BareSuppressionWarning,
                stacklevel=2,
            )
        directives[line_number] = SuppressionDirective(
            line=line_number,
            rule_ids=rule_ids,
            reason=reason,
        )
    return directives


def is_suppressed(issue: object, suppressions: dict[int, SuppressionDirective]) -> bool:
    """Return whether *issue* is covered by parsed suppressions."""

    line = int(getattr(issue, "lineno", 0) or 0)
    directive = suppressions.get(line)
    if directive is None:
        return False
    if directive.suppresses_all:
        return True
    issue_ids = {
        str(getattr(issue, "test_id", "") or ""),
        str(getattr(issue, "test", "") or ""),
    }
    return bool(issue_ids & set(directive.rule_ids))


def _issue_file(issue: object) -> str:
    return str(getattr(issue, "fname", "") or "")


def _issue_line(issue: object) -> int:
    return int(getattr(issue, "lineno", 0) or 0)


def _issue_rule_id(issue: object) -> str:
    return str(getattr(issue, "test_id", "") or getattr(issue, "test", "") or "")


def _source_line(issue: object) -> str:
    fname = _issue_file(issue)
    line = _issue_line(issue)
    if fname and line:
        text = linecache.getline(fname, line)
        if text:
            return text.strip()
    return str(getattr(issue, "text", "") or "")


def issue_fingerprint(issue: object) -> str:
    """Return a stable BLAKE2b fingerprint for an issue."""

    source_hash = hashlib.blake2b(
        _source_line(issue).encode("utf-8"),
        digest_size=20,
    ).hexdigest()
    key = "\x00".join(
        [
            _issue_rule_id(issue),
            _issue_file(issue),
            str(_issue_line(issue)),
            source_hash,
        ]
    )
    return hashlib.blake2b(key.encode("utf-8"), digest_size=20).hexdigest()


class BaselineStore:
    """Persistent set of issue fingerprints used to suppress known findings."""

    def __init__(self, fingerprints: dict[str, dict] | None = None) -> None:
        self._fingerprints = fingerprints or {}

    @classmethod
    def generate(cls, issues: Iterable[object]) -> "BaselineStore":
        records: dict[str, dict] = {}
        for issue in issues:
            fingerprint = issue_fingerprint(issue)
            records[fingerprint] = {
                "rule_id": _issue_rule_id(issue),
                "file": _issue_file(issue),
                "line": _issue_line(issue),
                "text": str(getattr(issue, "text", "") or ""),
            }
        return cls(records)

    @classmethod
    def load(cls, path: Path) -> "BaselineStore":
        if not path.is_file():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return cls()
        if data.get("pyflow_baseline_version") != _BASELINE_VERSION:
            return cls()
        findings = data.get("findings", {})
        return cls(findings if isinstance(findings, dict) else {})

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pyflow_baseline_version": _BASELINE_VERSION,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "findings": self._fingerprints,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def contains(self, issue: object) -> bool:
        return issue_fingerprint(issue) in self._fingerprints

    def filter_new(self, issues: Iterable[object]) -> list[object]:
        return [issue for issue in issues if not self.contains(issue)]

    def __len__(self) -> int:
        return len(self._fingerprints)


def score_confidence(issue: object, *, has_taint_trace: bool | None = None) -> float:
    """Compute a normalized confidence score for a checker issue."""

    base = {
        constants.HIGH: 0.88,
        constants.MEDIUM: 0.66,
        constants.LOW: 0.42,
        constants.UNDEFINED: 0.35,
    }.get(str(getattr(issue, "confidence", constants.UNDEFINED)), 0.35)

    severity_bonus = {
        constants.HIGH: 0.08,
        constants.MEDIUM: 0.04,
        constants.LOW: 0.0,
        constants.UNDEFINED: -0.05,
    }.get(str(getattr(issue, "severity", constants.UNDEFINED)), 0.0)

    if has_taint_trace is True:
        base += 0.08
    elif has_taint_trace is False and _is_injection_or_auth_issue(issue):
        base -= 0.18

    return round(max(0.0, min(1.0, base + severity_bonus)), 2)


def confidence_level(score: float) -> str:
    """Convert a normalized confidence score to PyFlow's confidence levels."""

    if score >= 0.8:
        return constants.HIGH
    if score >= 0.55:
        return constants.MEDIUM
    return constants.LOW


def apply_taint_aware_demotion(
    issue: object,
    *,
    has_taint_trace: bool,
    structural: bool = True,
) -> object:
    """Demote broad injection/auth findings that lack semantic evidence.

    The function mutates and returns *issue*, matching the existing checker
    issue style.
    """

    if has_taint_trace or not _is_injection_or_auth_issue(issue):
        return issue
    if (
        not structural
        or getattr(issue, "severity", constants.UNDEFINED) == constants.HIGH
    ):
        issue.severity = constants.MEDIUM
    issue.confidence = confidence_level(
        score_confidence(issue, has_taint_trace=False)
    )
    return issue


def find_security_guards(source: str) -> tuple[GuardInfo, ...]:
    """Extract simple auth/validation guards from Python source."""

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ()

    guards: list[GuardInfo] = []

    class Visitor(ast.NodeVisitor):
        def visit_If(self, node: ast.If) -> None:
            test_text = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            kind = _guard_kind(test_text)
            if kind is not None:
                protects = _node_line_range(node.body)
                if protects:
                    guards.append(
                        GuardInfo(
                            kind=kind,
                            line=node.lineno,
                            protects_lines=frozenset(protects),
                        )
                    )
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for decorator in node.decorator_list:
                deco_text = ast.unparse(decorator) if hasattr(ast, "unparse") else ""
                kind = _guard_kind(deco_text)
                if kind is not None:
                    protects = set(range(node.lineno, _end_lineno(node) + 1))
                    guards.append(
                        GuardInfo(
                            kind=kind,
                            line=getattr(decorator, "lineno", node.lineno),
                            protects_lines=frozenset(protects),
                        )
                    )
            self.generic_visit(node)

    Visitor().visit(tree)
    return tuple(guards)


def is_guarded(
    issue: object,
    guards: Iterable[GuardInfo],
    *,
    guard_kinds: Iterable[str] | None = None,
) -> bool:
    """Return whether *issue* is on a line protected by a security guard."""

    line = _issue_line(issue)
    allowed = set(guard_kinds) if guard_kinds is not None else None
    return any(
        line in guard.protects_lines
        and (allowed is None or guard.kind in allowed)
        for guard in guards
    )


def apply_guard_aware_demotion(
    issue: object,
    guards: Iterable[GuardInfo],
    *,
    guard_kinds: Iterable[str] | None = None,
) -> object:
    """Demote an issue when a nearby structural guard protects its line."""

    if not is_guarded(issue, guards, guard_kinds=guard_kinds):
        return issue
    if getattr(issue, "severity", constants.UNDEFINED) == constants.HIGH:
        issue.severity = constants.MEDIUM
    issue.confidence = constants.LOW
    return issue


def _guard_kind(text: str) -> str | None:
    if _AUTH_GUARD_RE.search(text):
        return "auth_check"
    if _VALIDATION_GUARD_RE.search(text):
        return "input_validation"
    return None


def _node_line_range(nodes: Iterable[ast.AST]) -> set[int]:
    lines: set[int] = set()
    for node in nodes:
        start = getattr(node, "lineno", 0) or 0
        end = _end_lineno(node)
        if start and end:
            lines.update(range(start, end + 1))
    return lines


def _end_lineno(node: ast.AST) -> int:
    return int(getattr(node, "end_lineno", None) or getattr(node, "lineno", 0) or 0)


def _is_injection_or_auth_issue(issue: object) -> bool:
    cwe = getattr(getattr(issue, "cwe", None), "id", 0)
    return cwe in {22, 77, 78, 79, 89, 90, 94, 95, 306, 639, 862, 918}
