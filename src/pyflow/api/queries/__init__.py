"""
Query interfaces for PyFlow.

This package provides composable query domains for accessing analysis results:
- Call graph queries: callers, callees, paths
- Control flow queries: CFG, SSA, CDG
- Data flow queries: reaching defs, aliases, points-to
- Task-specific queries: localization, test generation
- Query components: a protocol-neutral composition root for a snapshot
"""

from .call_graph import CallGraphQueries
from .components import QueryComponents, create_query_components
from .context import QueryContext
from .control_flow import ControlFlowQueries
from ._models import (
    AliasInfo,
    FunctionTestProfile,
    IpaFunctionSummary,
    LocalizationCandidate,
    PointsToInfo,
    ProgramSlice,
    ReachingDef,
    TaintFlowReport,
    TestScenario,
)
from .data_flow import DataFlowQueries
from .engine import GraphQueryEngine
from .localization import LocalizationQueries
from .test_generation import TestGenerationQueries
from .type_info import TypeInfoQueries

__all__ = [
    # Core
    "QueryContext",
    "GraphQueryEngine",
    "QueryComponents",
    "create_query_components",
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
    "TypeInfoQueries",
]
