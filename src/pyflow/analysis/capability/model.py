"""Public result model for defensive Python capability analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CapabilityOperation(str, Enum):
    CALL = "call"
    READ = "read"
    WRITE = "write"


class CapabilityReportKind(str, Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    RUNTIME_GUARDED = "runtime_guarded"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, order=True)
class SourceLocation:
    filename: str
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.filename,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass(frozen=True)
class CapabilityFinding:
    location: SourceLocation
    capability: str
    category: str
    operation: CapabilityOperation
    access_path: str
    report_kind: CapabilityReportKind
    reason: str
    context: str = ""
    trace: tuple[str, ...] = ()
    escape_kind: str = ""
    boundary: str = ""

    def key(self) -> tuple[Any, ...]:
        return (
            self.location,
            self.capability,
            self.operation,
            self.access_path,
            self.report_kind,
            self.reason,
            self.escape_kind,
            self.boundary,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "capability": self.capability,
            "category": self.category,
            "operation": self.operation.value,
            "access_path": self.access_path,
            "report_kind": self.report_kind.value,
            "reason": self.reason,
            "context": self.context,
            "trace": list(self.trace),
            "escape_kind": self.escape_kind,
            "boundary": self.boundary,
        }


@dataclass(frozen=True)
class CapabilityDiagnostic:
    kind: str
    message: str
    location: SourceLocation | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind, "message": self.message}
        if self.location is not None:
            result["location"] = self.location.to_dict()
        return result


@dataclass
class CapabilityAnalysisResult:
    findings: list[CapabilityFinding] = field(default_factory=list)
    diagnostics: list[CapabilityDiagnostic] = field(default_factory=list)
    status: str = "complete"
    statistics: dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> "CapabilityAnalysisResult":
        unique = {finding.key(): finding for finding in self.findings}
        self.findings = sorted(
            unique.values(),
            key=lambda finding: (
                finding.location.filename,
                finding.location.line,
                finding.location.column,
                finding.capability,
                finding.report_kind.value,
            ),
        )
        if any(d.kind in {"unsupported", "unknown", "budget"} for d in self.diagnostics):
            self.status = "partial"
        self.statistics = {
            "findings": len(self.findings),
            "direct": sum(f.report_kind is CapabilityReportKind.DIRECT for f in self.findings),
            "indirect": sum(f.report_kind is CapabilityReportKind.INDIRECT for f in self.findings),
            "runtime_guarded": sum(
                f.report_kind is CapabilityReportKind.RUNTIME_GUARDED for f in self.findings
            ),
            "diagnostics": len(self.diagnostics),
        }
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "statistics": dict(self.statistics),
            "findings": [finding.to_dict() for finding in self.findings],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


__all__ = [
    "CapabilityAnalysisResult",
    "CapabilityDiagnostic",
    "CapabilityFinding",
    "CapabilityOperation",
    "CapabilityReportKind",
    "SourceLocation",
]
