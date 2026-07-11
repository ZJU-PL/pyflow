"""
Shared result models for query APIs.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class IpaFunctionSummary:
    """Container for IPA summaries per analyzed context."""

    name: str
    signature: object
    summary: object


@dataclass
class AliasInfo:
    """Information about variable aliases within a function."""

    variable: str
    aliases: Set[str] = field(default_factory=set)
    is_aliased: bool = False
    ref_count: int = 0
    is_escaped: bool = False
    is_singleton: bool = False
    strong_update_possible: bool = False


@dataclass
class PointsToInfo:
    """Information about points-to relationships for a variable."""

    variable: str
    points_to: Set[str] = field(default_factory=set)
    may_be_null: bool = True
    ref_count: int = 0
    is_escaped: bool = False
    is_singleton: bool = False
    strong_update_possible: bool = False


@dataclass
class ReachingDef:
    """A reaching definition for a variable use."""

    variable: str
    def_location: Any = None
    def_value: Optional[str] = None
    is_call: bool = False


@dataclass
class TaintFlowReport:
    """Interprocedural taint report returned by the IFDS engine."""

    function: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, int] = field(default_factory=dict)


@dataclass
class LocalizationCandidate:
    """A candidate location for a bug or feature."""

    function_name: str
    confidence: float
    reason: str
    related_functions: List[str]
    data_dependencies: List[str]
    evidence: Optional["LocalizationEvidence"] = None


@dataclass
class LocalizationEvidence:
    """Structured evidence used to rank and explain localization candidates."""

    distance: Optional[int] = None
    shortest_path: List[str] = field(default_factory=list)
    variable_match: bool = False
    reaching_defs: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    points_to: List[str] = field(default_factory=list)
    upstream_callers: List[str] = field(default_factory=list)
    downstream_callees: List[str] = field(default_factory=list)

    @property
    def dependency_hits(self) -> int:
        return len(set(self.reaching_defs) | set(self.aliases) | set(self.points_to))


@dataclass
class ProgramSlice:
    """A program slice relevant to a variable or statement."""

    target_function: str
    target_variable: Optional[str]
    backward_slice: List[str]
    forward_slice: List[str]


@dataclass
class VariableFlowTrace:
    """Structured trace output for one variable within a function."""

    variable: str
    origin_function: str
    definitions: List[str] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    upstream_functions: List[str] = field(default_factory=list)
    downstream_functions: List[str] = field(default_factory=list)
    candidate_locations: List[str] = field(default_factory=list)
    dependency_summary: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variable": self.variable,
            "origin_function": self.origin_function,
            "definitions": self.definitions,
            "uses": self.uses,
            "interprocedural_flow": self.downstream_functions,
            "upstream_functions": self.upstream_functions,
            "downstream_functions": self.downstream_functions,
            "candidate_locations": self.candidate_locations,
            "dependency_summary": self.dependency_summary,
        }


@dataclass
class ChangeImpactReport:
    """Structured change-impact summary for a function."""

    changed_function: str
    direct_callers: List[str] = field(default_factory=list)
    transitive_callers: List[str] = field(default_factory=list)
    direct_callees: List[str] = field(default_factory=list)
    transitive_callees: List[str] = field(default_factory=list)
    test_targets: List[str] = field(default_factory=list)
    impact_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "changed_function": self.changed_function,
            "directly_affected": self.direct_callers,
            "transitively_affected": self.transitive_callers,
            "direct_dependencies": self.direct_callees,
            "transitive_dependencies": self.transitive_callees,
            "test_targets": self.test_targets,
            "impact_score": self.impact_score,
        }


@dataclass
class FunctionTestProfile:
    """Profile of a function for test generation."""

    name: str
    signature: Optional[str]
    parameters: List[str]
    return_type: Optional[str]
    calls: List[str]
    called_by: List[str]
    has_branches: bool
    has_loops: bool
    complexity: int
    external_dependencies: List[str]


@dataclass
class TestScenario:
    """A test scenario derived from control flow analysis."""

    scenario_id: str
    path_description: str
    conditions: List[str]
    expected_calls: List[str]
