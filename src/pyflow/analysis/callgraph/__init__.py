"""
Call graph extraction for Python code.

This package provides call graph analysis with multiple algorithm options:
- ast_based: Fast, lightweight AST-based analysis
- pycg: More sophisticated analysis using PyCG (if available)
- pycg_mir: Native PyCG-style assignment analysis over the seven-instruction MIR
- constraint_based: Value-flow solver with optional context-sensitive mode

The module is organized into focused components:
- Core CallGraph class in callgraph module
- Analysis algorithms in ast_based, pycg_based, pycg_mir, and constraint_based
- Output formats in formats module
"""

# Prefer the more precise constraint-based implementation when available.
# If it's missing (e.g. in lightweight installs), fall back to the PyCG-backed
# implementation, which relies on the external `pycg` package. As a final
# fallback, use the minimal AST-based implementation so basic functionality
# still works even without optional dependencies.
try:
    from .constraint_based import (
        extract_call_graph_constraint as extract_call_graph,
        analyze_file_constraint as analyze_file,
    )
except ModuleNotFoundError:
    try:
        from .pycg_based import (
            extract_call_graph_pycg as extract_call_graph,
            analyze_file_pycg as analyze_file,
        )
    except (ModuleNotFoundError, ImportError):
        from .ast_based import extract_call_graph, analyze_file

from .pycg_based import extract_call_graph_pycg, analyze_file_pycg
from .constraint_based import (
    extract_call_graph_constraint,
    extract_call_site_edge_index_constraint,
    analyze_file_constraint,
    extract_value_flow_graph_constraint,
)
from .formats import generate_text_output, generate_dot_output, generate_json_output
from .callgraph import CallGraph, CallGraphError


def __getattr__(name):
    # Keep the independent MIR pipeline lazy for clients that only use an
    # existing analyzer. This also avoids a frontend/analysis import cycle.
    if name in {"extract_call_graph_pycg_mir", "analyze_file_pycg_mir"}:
        from . import pycg_mir

        value = getattr(pycg_mir, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "extract_call_graph",
    "analyze_file",
    "extract_call_graph_constraint",
    "extract_call_site_edge_index_constraint",
    "analyze_file_constraint",
    "extract_value_flow_graph_constraint",
    "extract_call_graph_pycg",
    "analyze_file_pycg",
    "extract_call_graph_pycg_mir",
    "analyze_file_pycg_mir",
    "CallGraph",
    "CallGraphError",
    "generate_text_output",
    "generate_dot_output",
    "generate_json_output",
]
