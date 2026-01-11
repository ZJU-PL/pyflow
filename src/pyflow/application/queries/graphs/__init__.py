"""
Low-level graph query interfaces.

These modules provide direct access to graph structures (call graph, CFG, SSA, 
CDG, data flow) for users who need fine-grained control.
"""

from .call_graph_queries import CallGraphQueries
from .control_flow_queries import ControlFlowQueries
from .data_flow_queries import DataFlowQueries, IpaFunctionSummary

__all__ = [
    "CallGraphQueries",
    "ControlFlowQueries",
    "DataFlowQueries",
    "IpaFunctionSummary",
]
