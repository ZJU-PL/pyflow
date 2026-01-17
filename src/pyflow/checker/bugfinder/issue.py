"""Issue types for the analysis-backed bug finder."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class IssueTrace:
    """Lightweight trace payload."""

    summary: str
    detail: Optional[str] = None


@dataclass(frozen=True)
class BugInstance:
    """Single reported bug instance."""

    rule: str
    message: str
    severity: Severity
    function: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    traces: List[IssueTrace] = field(default_factory=list)
