"""Explicit soundness-envelope metadata for imprecise operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PrecisionLevel(str, Enum):
    PRECISE = "precise"
    CONSERVATIVE = "conservative"
    ASSUMED = "assumed"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, order=True)
class AnalysisUncertainty:
    """A site where the analysis crossed a documented precision boundary."""

    code: str
    message: str
    level: PrecisionLevel
    function: str | None = None
    filename: str | None = None
    line: int | None = None
    operation: str | None = None

    @property
    def affects_completeness(self) -> bool:
        return self.level in {PrecisionLevel.ASSUMED, PrecisionLevel.UNSUPPORTED}
