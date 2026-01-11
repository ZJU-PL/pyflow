"""
Query interfaces for PyFlow.

This package exposes programmatic access to semantic facts and graph
structures (CFG, SSA, CDG, callgraph) for coding agents and tooling.
"""

from .service import SemanticQueryService
from .summary_queries import FunctionSummary
from .server_mode import DEFAULT_MODE, MCPServerMode, resolve_capabilities

__all__ = [
    "SemanticQueryService",
    "FunctionSummary",
    "MCPServerMode",
    "DEFAULT_MODE",
    "resolve_capabilities",
]
