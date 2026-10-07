"""Program/file entry points for class-pollution analysis."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Sequence

from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions
from pyflow.analysis.ifds.api import (
    AnalysisSession,
    _entry_nodes_from_program,
    load_analysis_session,
)
from pyflow.analysis.ifds.core.solver import SolverOptions

from .analysis import (
    ClassPollutionAnalysisResult,
    ClassPollutionConfiguration,
    analyze_class_pollution,
)


def run_class_pollution_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str | None = None,
    entry_file: str | Path | None = None,
    configuration: ClassPollutionConfiguration | None = None,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
    solver_options: SolverOptions | None = None,
    callgraph_max_iterations: int = 256,
) -> tuple[AnalysisSession, ClassPollutionAnalysisResult]:
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
    config = configuration or ClassPollutionConfiguration()
    options = config.entry_point_options
    if entry_file is not None:
        options = EntryPointOptions(
            mode=EntryPointMode.FILE_PUBLIC,
            files=(str(entry_file),),
            include_synthetic_modules=options.include_synthetic_modules,
        )
    config = replace(config, entry_point_options=options)
    result = analyze_class_pollution(
        session.adapter,
        config,
        entry_nodes=_entry_nodes_from_program(
            session,
            function_name=function,
            entry_file=entry_file,
            entry_point_options=options,
        ),
        **({"solver_options": solver_options} if solver_options is not None else {}),
    )
    return session, result


__all__ = ["run_class_pollution_analysis"]
