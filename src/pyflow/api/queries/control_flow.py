"""
Control-flow query helpers for PyFlow.

These queries expose CFG/SSA/CDG insights via the GraphQueryEngine without
forcing consumers to depend on the engine directly.
"""

from typing import Any, Dict, Union

from .context import QueryContext
from .engine import GraphQueryEngine


class ControlFlowQueries:
    """Wraps the graph engine to provide CFG/SSA/CDG helpers."""

    def __init__(self, context: QueryContext, graph_engine: GraphQueryEngine):
        self.context = context
        self.graph_engine = graph_engine

    def get_cfg(self, function: Union[str, object]):
        """Return the raw CFG for the requested function."""
        return self.graph_engine.get_cfg(function)

    def get_cfg_structure(self, function: Union[str, object]) -> Dict[str, Any]:
        """Return a serialized view of the CFG suitable for JSON output."""
        return self.graph_engine.get_cfg_structure(function)

    def get_ssa(self, function: Union[str, object]):
        """Return the SSA graph for the requested function."""
        return self.graph_engine.get_ssa(function)

    def get_cdg(self, function: Union[str, object]):
        """Return the CDG for the requested function."""
        return self.graph_engine.get_cdg(function)