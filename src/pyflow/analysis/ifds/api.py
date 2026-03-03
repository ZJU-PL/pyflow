"""Practical API entry points for IFDS-backed analyses."""

from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
from types import SimpleNamespace
from typing import Iterable, Sequence

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.frontend.programextractor import Extractor, create_interface_from_paths, extractProgram
from pyflow.util.application.console import Console

from .cfg_adapter import CFGSupergraphAdapter, build_supergraph_from_cfgs
from .taint import TaintAnalysisResult, TaintConfiguration, analyze_taint


@dataclass(frozen=True)
class AnalysisSession:
    """Loaded program plus IFDS-ready CFG supergraph."""

    compiler: CompilerContext
    program: Program
    adapter: CFGSupergraphAdapter


def _path_args(verbose: bool, dependency_strategy: str, search_paths):
    return SimpleNamespace(
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
    )


def load_analysis_session(
    python_files: Sequence[str | Path],
    *,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
) -> AnalysisSession:
    """Load source files into a PyFlow program and build CFGs for all live code."""
    files = [Path(path) for path in python_files]
    compiler = CompilerContext(Console(out=None if verbose else io.StringIO(), verbose=verbose))
    program = Program()

    args = _path_args(verbose, dependency_strategy, search_paths)
    program.interface, all_source_code = create_interface_from_paths(files, args)
    compiler.extractor = Extractor(compiler, verbose=verbose, source_code=all_source_code)
    extractProgram(compiler, program)

    queries = program.get_queries(compiler)
    cfgs = [queries.get_cfg(code) for code in program.liveCode]
    adapter = build_supergraph_from_cfgs(cfgs)
    return AnalysisSession(compiler, program, adapter)


def run_taint_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str,
    source_names: Iterable[str],
    sink_names: Iterable[str],
    sanitizer_names: Iterable[str] = (),
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
) -> tuple[AnalysisSession, TaintAnalysisResult]:
    """Load files, resolve a function, and run the shipped taint analysis."""
    session = load_analysis_session(
        python_files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
    )
    queries = session.program.get_queries(session.compiler)
    cfg = queries.graph_engine.get_cfg(function)
    result = analyze_taint(
        session.adapter,
        TaintConfiguration(
            source_names=frozenset(source_names),
            sink_names=frozenset(sink_names),
            sanitizer_names=frozenset(sanitizer_names),
        ),
        entry_nodes=[session.adapter.supergraph.entry_of(cfg)],
    )
    return session, result
