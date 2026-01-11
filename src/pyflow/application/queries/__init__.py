"""
Query interfaces for PyFlow.

The package now groups the queries that coding agents need (call graph
insights vs. semantic facts) while still exposing the low-level graph and
analysis helpers.
"""

from .service import SemanticQueryService
from .data_flow_queries import IpaFunctionSummary
from .server_mode import DEFAULT_MODE, MCPServerMode, resolve_capabilities

__all__ = [
    "SemanticQueryService",
    "IpaFunctionSummary",
    "MCPServerMode",
    "DEFAULT_MODE",
    "resolve_capabilities",
]
