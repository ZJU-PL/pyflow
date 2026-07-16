"""Constraint-based call graph analysis package.

Primary entry points:
- `extract_call_graph_constraint` for call graph extraction.
- `extract_call_site_edge_index_constraint` for direct call-site edges.
- `extract_value_flow_graph_constraint` for debug value-flow inspection.
"""

from .api import (
    analyze_file_constraint,
    extract_call_site_edge_index_constraint,
    extract_call_graph_constraint,
    extract_value_flow_graph_constraint,
)
from .engine import ConstraintCallGraphBuilder
from .model import AnalysisOptions, ConstraintCallSite

__all__ = [
    "extract_call_graph_constraint",
    "extract_call_site_edge_index_constraint",
    "analyze_file_constraint",
    "extract_value_flow_graph_constraint",
    "ConstraintCallGraphBuilder",
    "ConstraintCallSite",
    "AnalysisOptions",
]
