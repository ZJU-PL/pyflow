"""
Query interfaces for PyFlow.

This package provides query services for accessing analysis results:
- Call graph queries: callers, callees, paths
- Control flow queries: CFG, SSA, CDG
- Data flow queries: reaching defs, aliases, points-to
- Task-specific queries: localization, test generation
- Semantic query service: unified facade for all queries
"""

from .call_graph import CallGraphQueries
from .capabilities import (
    MCPServerMode,
    DEFAULT_MODE,
    get_server_mode_description,
    resolve_capabilities,
)
from .context import QueryContext
from .control_flow import ControlFlowQueries
from .data_flow import (
    AliasInfo,
    DataFlowQueries,
    IpaFunctionSummary,
    PointsToInfo,
    ReachingDef,
    TaintFlowReport,
)
from .engine import GraphQueryEngine
from .localization import LocalizationCandidate, LocalizationQueries, ProgramSlice
from .service import SemanticQueryService
from .test_generation import (
    FunctionTestProfile,
    TestGenerationQueries,
    TestScenario,
)

__all__ = [
    # Core
    "QueryContext",
    "GraphQueryEngine",
    "MCPServerMode",
    "DEFAULT_MODE",
    "get_server_mode_description",
    "resolve_capabilities",
    # Service
    "SemanticQueryService",
    # Graph queries
    "CallGraphQueries",
    "ControlFlowQueries",
    "DataFlowQueries",
    "IpaFunctionSummary",
    # Data flow types
    "AliasInfo",
    "PointsToInfo",
    "ReachingDef",
    "TaintFlowReport",
    # Task queries
    "LocalizationQueries",
    "LocalizationCandidate",
    "ProgramSlice",
    "TestGenerationQueries",
    "FunctionTestProfile",
    "TestScenario",
]
