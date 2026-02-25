"""Public API for the constraint-based call graph analyser."""

from __future__ import annotations

import inspect
import os
from typing import Optional

from ..callgraph import CallGraph
from ..formats import generate_text_output
from .engine import ConstraintCallGraphBuilder
from .model import AnalysisOptions


def _discover_entry_path_from_stack() -> Optional[str]:
    for frame_info in inspect.stack():
        maybe_path = frame_info.frame.f_locals.get("main_path")
        if isinstance(maybe_path, str) and os.path.isfile(maybe_path):
            return os.path.abspath(maybe_path)
    return None


def extract_call_graph_constraint(
    source_code: str,
    source_path: Optional[str] = None,
    verbose: bool = False,
    context_sensitive: bool = False,
    context_depth: int = 1,
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
    """
    entry_path = source_path or _discover_entry_path_from_stack()
    options = AnalysisOptions(
        context_sensitive=context_sensitive,
        context_depth=max(0, int(context_depth)),
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
) -> str:
    """Analyze a Python file and return a text rendering of the call graph."""
    try:
        with open(filepath, "r") as handle:
            source = handle.read()
        graph = extract_call_graph_constraint(
            source_code=source,
            source_path=filepath,
            verbose=verbose,
            context_sensitive=context_sensitive,
            context_depth=context_depth,
        )
        return generate_text_output(graph, None)
    except Exception as exc:
        return f"Error analyzing {filepath}: {exc}"
