"""
Query interfaces for PyFlow.

This package exposes programmatic access to semantic facts and graph
structures (CFG, SSA, CDG, callgraph) for coding agents and tooling.
"""

from .service import SemanticQueryService
from .summaries import FunctionSummary

__all__ = ["SemanticQueryService", "FunctionSummary"]
