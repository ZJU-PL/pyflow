"""File and program entry points for IFDS security checks."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

from pyflow.analysis.entrypoints import EntryPointDefaults, EntryPointMode, EntryPointOptions
from pyflow.api.ifds import (
    PreparedIFDSProgram,
    _entry_nodes_from_program,
    load_analysis_session,
)
from pyflow.analysis.ifds.core.solver import SolverOptions
from pyflow.analysis.ifds.modeling.calls import CallModelRegistry

from .taint import TaintAnalysisResult, TaintConfiguration, UnknownCallPolicy, analyze_taint


def run_taint_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str | None = None,
    entry_file: str | Path | None = None,
    call_models=None,
    rules=(),
    collection_mutator_names: Iterable[str] | None = None,
    collection_accessor_names: Iterable[str] | None = None,
    unknown_call_policy: UnknownCallPolicy = "drop",
    conservative_unresolved_call_side_effects: bool = False,
    entry_point_options: EntryPointOptions | None = None,
    entry_point_defaults: EntryPointDefaults | None = None,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
    shadow_scan: bool = False,
    solver_options: SolverOptions | None = None,
    callgraph_max_iterations: int = 256,
) -> tuple[PreparedIFDSProgram, TaintAnalysisResult, list | None]:
    """Load files and run taint analysis from a function or module entry.

    When *shadow_scan* is ``True``, returns a third element: a list of
    :class:`~pyflow.checker.ifds.shadow_scan.ShadowMatch` from a
    lightweight regex-only scan run alongside the IFDS analysis.  This
    provides an independent signal for failure attribution.
    """
    session = load_analysis_session(
        python_files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_exceptional_edges=include_exceptional_edges,
        root_function=function,
        entry_file=entry_file,
        callgraph_max_iterations=callgraph_max_iterations,
    )
    resolved_entry_options = entry_point_options
    if resolved_entry_options is None and entry_point_defaults is not None:
        if entry_file is not None:
            fallback = EntryPointOptions(
                mode=EntryPointMode.FILE_PUBLIC,
                files=(str(entry_file),),
                taint_parameters=True,
            )
        elif function is not None:
            fallback = EntryPointOptions(mode=EntryPointMode.DECLARED_ONLY)
        else:
            fallback = EntryPointOptions(mode=EntryPointMode.DECLARED_ONLY)
        resolved_entry_options = entry_point_defaults.resolve(fallback)

    result = analyze_taint(
        session.adapter,
        TaintConfiguration(
            call_models=(call_models if call_models is not None else CallModelRegistry()),
            rules=tuple(rules),
            collection_mutator_names=(
                frozenset(collection_mutator_names)
                if collection_mutator_names is not None
                else TaintConfiguration().collection_mutator_names
            ),
            collection_accessor_names=(
                frozenset(collection_accessor_names)
                if collection_accessor_names is not None
                else TaintConfiguration().collection_accessor_names
            ),
            unknown_call_policy=unknown_call_policy,
            conservative_unresolved_call_side_effects=(conservative_unresolved_call_side_effects),
            entry_point_options=(
                resolved_entry_options
                or EntryPointOptions(
                    mode=(
                        EntryPointMode.FILE_PUBLIC
                        if entry_file is not None
                        else EntryPointMode.DECLARED_ONLY
                    ),
                    files=((str(entry_file),) if entry_file is not None else ()),
                    taint_parameters=entry_file is not None,
                )
            ),
        ),
        entry_nodes=_entry_nodes_from_program(
            session,
            function_name=function,
            entry_file=entry_file,
            entry_point_options=resolved_entry_options,
        ),
        **({"solver_options": solver_options} if solver_options is not None else {}),
    )

    if not shadow_scan:
        return session, result, None

    from .shadow_scan import run_shadow_scan as _run_shadow_scan

    shadow_matches: list = []
    for f in python_files:
        code = Path(f).read_text(encoding="utf-8", errors="replace")
        shadow_matches.extend(_run_shadow_scan(code))
    return session, result, shadow_matches
