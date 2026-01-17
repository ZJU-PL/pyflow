"""
Query interfaces for PyFlow.

The package now groups the queries that coding agents need (call graph
insights vs. semantic facts) while still exposing the low-level graph and
analysis helpers.
"""

from .core import MCPServerMode, DEFAULT_MODE, resolve_capabilities
from .graphs import IpaFunctionSummary
from .service import SemanticQueryService

__all__ = [
    "SemanticQueryService",
    "IpaFunctionSummary",
    "MCPServerMode",
    "DEFAULT_MODE",
    "resolve_capabilities",
]
