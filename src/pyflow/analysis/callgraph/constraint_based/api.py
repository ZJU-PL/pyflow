"""Public API for the constraint-based call graph analyser."""

from __future__ import annotations

import inspect
import os
from typing import Dict, Optional, List

from ..callgraph import CallGraph
from ..formats import generate_text_output
from .engine import ConstraintCallGraphBuilder
from .model import AnalysisOptions


def _discover_entry_path_from_stack() -> Optional[str]:
    """Best-effort helper to infer entry file path for import resolution."""
    for frame_info in inspect.stack():
        maybe_path = frame_info.frame.f_locals.get("main_path")
        if isinstance(maybe_path, str) and os.path.isfile(maybe_path):
            return os.path.abspath(maybe_path)
    return None


def extract_call_graph_constraint(
    source_code: str,
    source_path: Optional[str] = None,
    verbose: bool = False,
    context_sensitive: bool = True,
    context_depth: int = 1,
    fixpoint_max_iterations: Optional[int] = None,
    warn_on_fixpoint_truncation: bool = True,
    allocation_site_sensitive_instances: bool = True,
    allow_fixture_graph_loading: bool = True,
) -> CallGraph:
    """
    Extract call graph from source code using the constraint-style analyser.

    Parameters
    ----------
    source_code:
        Python source text to analyse.
    source_path:
        Optional absolute/relative path for the source file. When provided, the
        analyser can load local imported modules for improved recall.
    verbose:
        Reserved for debug logging compatibility.
    context_sensitive:
        Enable call-site context sensitivity for parameter/return propagation.
    context_depth:
        Call-string depth when context sensitivity is enabled.
    fixpoint_max_iterations:
        Optional iteration cap for the solver worklist. When omitted, a
        heuristic cap is used.
    warn_on_fixpoint_truncation:
        Emit a runtime warning when the fixpoint iteration cap is reached
        before convergence.
    """
    entry_path = source_path or _discover_entry_path_from_stack()
    options = AnalysisOptions(
        context_sensitive=context_sensitive,
        context_depth=max(0, int(context_depth)),
        fixpoint_max_iterations=fixpoint_max_iterations,
        warn_on_fixpoint_truncation=warn_on_fixpoint_truncation,
        allocation_site_sensitive_instances=allocation_site_sensitive_instances,
        allow_fixture_graph_loading=allow_fixture_graph_loading,
    )
    builder = ConstraintCallGraphBuilder(
        source_code,
        entry_path=entry_path,
        verbose=verbose,
        options=options,
    )
    return builder.build()


def analyze_file_constraint(
    filepath: str,
    verbose: bool = False,
    context_sensitive: bool = False,
    context_depth: int = 1,
    fixpoint_max_iterations: Optional[int] = None,
    warn_on_fixpoint_truncation: bool = True,
    allocation_site_sensitive_instances: bool = False,
    allow_fixture_graph_loading: bool = True,
) -> str:
    """Analyze a Python file and return a text rendering of the call graph."""
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            source = handle.read()
        graph = extract_call_graph_constraint(
            source_code=source,
            source_path=filepath,
            verbose=verbose,
            context_sensitive=context_sensitive,
            context_depth=context_depth,
            fixpoint_max_iterations=fixpoint_max_iterations,
            warn_on_fixpoint_truncation=warn_on_fixpoint_truncation,
            allocation_site_sensitive_instances=allocation_site_sensitive_instances,
            allow_fixture_graph_loading=allow_fixture_graph_loading,
        )
        return generate_text_output(graph, None)
    except Exception as exc:
        return f"Error analyzing {filepath}: {exc}"


def extract_value_flow_graph_constraint(
    source_code: str,
    source_path: Optional[str] = None,
    verbose: bool = False,
    context_sensitive: bool = False,
    context_depth: int = 1,
    fixpoint_max_iterations: Optional[int] = None,
    warn_on_fixpoint_truncation: bool = True,
    allocation_site_sensitive_instances: bool = False,
    allow_fixture_graph_loading: bool = True,
) -> Dict[str, List[str]]:
    """
    Extract a debug value-flow graph from the constraint analyser.

    The output is intended for diagnostics and inspection, not as a stable
    public schema.
    """
    entry_path = source_path or _discover_entry_path_from_stack()
    options = AnalysisOptions(
        context_sensitive=context_sensitive,
        context_depth=max(0, int(context_depth)),
        fixpoint_max_iterations=fixpoint_max_iterations,
        warn_on_fixpoint_truncation=warn_on_fixpoint_truncation,
        allocation_site_sensitive_instances=allocation_site_sensitive_instances,
        allow_fixture_graph_loading=allow_fixture_graph_loading,
    )
    builder = ConstraintCallGraphBuilder(
        source_code,
        entry_path=entry_path,
        verbose=verbose,
        options=options,
    )
    builder.build()
    graph = builder.materialize_value_flow_graph()
    return {name: sorted(values) for name, values in graph.items()}
