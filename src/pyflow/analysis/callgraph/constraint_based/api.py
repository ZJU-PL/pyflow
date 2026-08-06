"""Public API for the constraint-based call graph analyser."""

from __future__ import annotations

import inspect
import os
from typing import Dict, List, Mapping, Optional

from ..callgraph import CallGraph
from ..formats import generate_text_output
from .engine import ConstraintCallGraphBuilder
from .model import AnalysisOptions, CallSiteEdgeIndex


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
    context_sensitive: bool = False,
    context_depth: int = 1,
    fixpoint_max_iterations: Optional[int] = None,
    warn_on_fixpoint_truncation: bool = True,
    allocation_site_sensitive_instances: bool = True,
    use_type_hints: bool = True,
    refine_type_guards: bool = True,
    allow_fixture_graph_loading: bool = True,
    max_values_per_binding: int = 128,
    max_contexts_per_scope: int = 64,
    requeue_policy: str = "priority",
    emit_solver_stats: bool = False,
    strict_precision_mode: bool = False,
    skip_stdlib_modules: bool = True,
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
        use_type_hints=use_type_hints,
        refine_type_guards=refine_type_guards,
        allow_fixture_graph_loading=allow_fixture_graph_loading,
        max_values_per_binding=max(1, int(max_values_per_binding)),
        max_contexts_per_scope=max(1, int(max_contexts_per_scope)),
        requeue_policy="fifo" if requeue_policy == "fifo" else "priority",
        emit_solver_stats=emit_solver_stats,
        strict_precision_mode=strict_precision_mode,
        skip_stdlib_modules=skip_stdlib_modules,
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
    use_type_hints: bool = True,
    refine_type_guards: bool = True,
    allow_fixture_graph_loading: bool = True,
    max_values_per_binding: int = 128,
    max_contexts_per_scope: int = 64,
    requeue_policy: str = "priority",
    emit_solver_stats: bool = False,
    strict_precision_mode: bool = False,
    skip_stdlib_modules: bool = True,
) -> str:
    """Analyze a Python file and return a text rendering of the call graph."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
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
            use_type_hints=use_type_hints,
            refine_type_guards=refine_type_guards,
            allow_fixture_graph_loading=allow_fixture_graph_loading,
            max_values_per_binding=max_values_per_binding,
            max_contexts_per_scope=max_contexts_per_scope,
            requeue_policy=requeue_policy,
            emit_solver_stats=emit_solver_stats,
            strict_precision_mode=strict_precision_mode,
            skip_stdlib_modules=skip_stdlib_modules,
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
    use_type_hints: bool = True,
    refine_type_guards: bool = True,
    allow_fixture_graph_loading: bool = True,
    max_values_per_binding: int = 128,
    max_contexts_per_scope: int = 64,
    requeue_policy: str = "priority",
    emit_solver_stats: bool = False,
    strict_precision_mode: bool = False,
    skip_stdlib_modules: bool = True,
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
        use_type_hints=use_type_hints,
        refine_type_guards=refine_type_guards,
        allow_fixture_graph_loading=allow_fixture_graph_loading,
        max_values_per_binding=max(1, int(max_values_per_binding)),
        max_contexts_per_scope=max(1, int(max_contexts_per_scope)),
        requeue_policy="fifo" if requeue_policy == "fifo" else "priority",
        emit_solver_stats=emit_solver_stats,
        strict_precision_mode=strict_precision_mode,
        skip_stdlib_modules=skip_stdlib_modules,
    )
    builder = ConstraintCallGraphBuilder(
        source_code,
        entry_path=entry_path,
        verbose=verbose,
        options=options,
    )
    builder.build()
    graph = builder.materialize_value_flow_graph()
    out = {name: sorted(values) for name, values in graph.items()}
    if emit_solver_stats:
        out["__solver_stats__"] = [
            f"{key}={value}"
            for key, value in sorted(builder.solver_stats.__dict__.items())
        ]
    return out


def extract_call_site_edge_index_constraint(
    source_code: str,
    source_path: Optional[str] = None,
    verbose: bool = False,
    context_sensitive: bool = False,
    context_depth: int = 1,
    fixpoint_max_iterations: Optional[int] = None,
    warn_on_fixpoint_truncation: bool = True,
    allocation_site_sensitive_instances: bool = True,
    use_type_hints: bool = True,
    refine_type_guards: bool = True,
    allow_fixture_graph_loading: bool = False,
    max_values_per_binding: int = 128,
    max_contexts_per_scope: int = 64,
    requeue_policy: str = "priority",
    emit_solver_stats: bool = False,
    strict_precision_mode: bool = False,
    skip_stdlib_modules: bool = True,
    skip_external_modules: bool = False,
    analyze_reachable_only: bool = False,
    seed_entry_file_scopes: bool = False,
    additional_sources: Optional[Mapping[str, str]] = None,
) -> CallSiteEdgeIndex:
    """Extract direct call-site edges from the constraint analyser."""
    entry_path = source_path or _discover_entry_path_from_stack()
    options = AnalysisOptions(
        context_sensitive=context_sensitive,
        context_depth=max(0, int(context_depth)),
        fixpoint_max_iterations=fixpoint_max_iterations,
        warn_on_fixpoint_truncation=warn_on_fixpoint_truncation,
        allocation_site_sensitive_instances=allocation_site_sensitive_instances,
        use_type_hints=use_type_hints,
        refine_type_guards=refine_type_guards,
        allow_fixture_graph_loading=allow_fixture_graph_loading,
        max_values_per_binding=max(1, int(max_values_per_binding)),
        max_contexts_per_scope=max(1, int(max_contexts_per_scope)),
        requeue_policy="fifo" if requeue_policy == "fifo" else "priority",
        emit_solver_stats=emit_solver_stats,
        strict_precision_mode=strict_precision_mode,
        skip_stdlib_modules=skip_stdlib_modules,
        skip_external_modules=skip_external_modules,
        analyze_reachable_only=analyze_reachable_only,
        seed_entry_file_scopes=seed_entry_file_scopes,
    )
    builder = ConstraintCallGraphBuilder(
        source_code,
        entry_path=entry_path,
        verbose=verbose,
        options=options,
        additional_sources=additional_sources,
    )
    builder.build()
    return builder.call_site_edge_index()
