"""Structured diagnostics for IFDS analysis setup and execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DiagnosticSeverity = Literal["info", "warning", "error"]
DiagnosticPhase = Literal["extract", "pipeline", "cfg", "callgraph", "solver"]


@dataclass(frozen=True)
class IFDSDiagnostic:
    """Non-fatal diagnostic emitted while preparing or running IFDS analyses."""

    severity: DiagnosticSeverity
    phase: DiagnosticPhase
    message: str
    exception_type: str | None = None
    subject: str | None = None
    code: str = "IFDS000"
    recoverable: bool = True
    affects_completeness: bool = False

    def __str__(self) -> str:
        return self.message

    def __contains__(self, text: object) -> bool:
        return isinstance(text, str) and text in self.message
