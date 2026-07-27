"""Data models shared by AST dataflow taint components."""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Set, Tuple


@dataclass(frozen=True)
class ASTDataflowTaintDiagnostic:
    """One precision or completeness diagnostic produced by the detector."""

    message: str
    code: str
    affects_completeness: bool = False
    function: str | None = None


@dataclass(frozen=True)
class ASTDataflowTaintFinding:
    """Typed source-to-sink result produced by AST dataflow analysis."""

    function: str
    filename: str
    sink_name: str
    sink_line: int | None
    source_kinds: FrozenSet[str]
    rule_id: str
    rule_title: str
    severity: str
    cwe: str | None = None
    suggestion: str | None = None
    confidence: str = "HIGH"
    precision_reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ASTDataflowTaintResult:
    """Findings plus explicit completion and observability information."""

    findings: Tuple[ASTDataflowTaintFinding, ...]
    status: str = "complete"
    diagnostics: Tuple[ASTDataflowTaintDiagnostic, ...] = ()
    statistics: Dict[str, int] = field(default_factory=dict)


@dataclass
class FunctionSummary:
    """Summary of taint analysis for a function."""

    name: str
    has_source: bool = False
    returns_tainted: bool = False
    returns_tainted_unconditional: bool = False
    params_to_sink: Set[str] = field(default_factory=set)
    param_taint_outputs: Set[str] = field(default_factory=set)
    param_key_writes: Dict[str, Set[str]] = field(default_factory=dict)
    param_key_taint_writes: Dict[str, Set[str]] = field(default_factory=dict)
    sinks: Set[str] = field(default_factory=set)
    tainted_sinks: Set[str] = field(default_factory=set)
    tainted_sink_lines: Dict[str, Set[int]] = field(default_factory=dict)
    tainted_sink: bool = False
    returns_value: bool = True
    return_param_deps: Set[str] = field(default_factory=set)
