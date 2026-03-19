"""Practical API entry points for IFDS-backed analyses."""

from __future__ import annotations

from contextlib import nullcontext, redirect_stdout
from dataclasses import dataclass
import io
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Iterable, Sequence

from pyflow.application.context import CompilerContext
from pyflow.application.pipeline import Pipeline
from pyflow.application.program import Program
from pyflow.frontend.programextractor import Extractor, create_interface_from_paths, extractProgram
from pyflow.util.application.console import Console

from .cfg_adapter import CFGSupergraphAdapter, build_supergraph_from_cfgs
from .clients.nullness import NullnessAnalysisResult, analyze_nullness
from .clients.taint import TaintAnalysisResult, TaintConfiguration, analyze_taint
from .clients.typestate import (
    TypestateAnalysisResult,
    TypestateConfiguration,
    analyze_typestate,
)
from .preparation import prepare_program_for_ifds


@dataclass(frozen=True)
class AnalysisSession:
    """Loaded program plus IFDS-ready CFG supergraph and non-fatal preparation notes."""

    compiler: CompilerContext
    program: Program
    adapter: CFGSupergraphAdapter
    diagnostics: tuple[str, ...] = ()


def _path_args(verbose: bool, dependency_strategy: str, search_paths):
    return SimpleNamespace(
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_main_entry_points=True,
    )


def _entry_nodes_from_program(
    session: AnalysisSession,
    *,
    fallback_function: str | None = None,
):
    queries = session.program.get_queries(session.compiler)
    if fallback_function is not None:
        target_code = queries.context.resolve_function(fallback_function)
        candidate_codes = [target_code]
        target_source = _source_filename_from_code(target_code)
        if target_source is not None:
            for code in getattr(session.program, "liveCode", ()):
                if code is target_code:
                    continue
                if not _is_synthetic_module_code(code):
                    continue
                if _source_filename_from_code(code) == target_source:
                    candidate_codes.append(code)

        entry_nodes = []
        seen = set()
        for code in candidate_codes:
            try:
                cfg = queries.graph_engine.get_cfg(code)
            except Exception:
                continue
            node = session.adapter.supergraph.entry_of(cfg)
            if node not in seen:
                seen.add(node)
                entry_nodes.append(node)
        if entry_nodes:
            return tuple(entry_nodes)

    entry_nodes = []
    seen = set()
    for entry_point in getattr(session.program, "entryPoints", ()):
        code = getattr(entry_point, "code", None)
        if code is None:
            continue
        try:
            cfg = queries.graph_engine.get_cfg(code)
        except Exception:
            continue
        node = session.adapter.supergraph.entry_of(cfg)
        if node not in seen:
            seen.add(node)
            entry_nodes.append(node)

    if entry_nodes:
        return tuple(entry_nodes)

    raise ValueError("Unable to derive IFDS entry nodes from program entry points.")


def _source_filename_from_code(code) -> str | None:
    annotation = getattr(code, "annotation", None)
    origin = getattr(annotation, "origin", ()) or ()
    for item in origin:
        if not isinstance(item, str):
            continue
        if not (item.startswith("source(") and item.endswith(")")):
            continue
        payload = item[len("source(") : -1]
        filename, _sep, _lineno = payload.rpartition(":")
        if filename:
            return os.path.realpath(filename)
    return None


def _code_display_name(code) -> str:
    if code is None:
        return "<unknown>"
    code_name = getattr(code, "codeName", None)
    if callable(code_name):
        try:
            name = code_name()
        except Exception:
            name = None
        if isinstance(name, str):
            return name
    return repr(code)


def _is_synthetic_module_code(code) -> bool:
    annotation = getattr(code, "annotation", None)
    origin = getattr(annotation, "origin", ()) or ()
    return any(
        isinstance(item, str) and item.startswith("synthetic_module(")
        for item in origin
    )


def _restrict_program_entry_points(
    compiler: CompilerContext,
    program: Program,
    function_name: str,
) -> None:
    queries = program.get_queries(compiler)
    target_code = _resolve_requested_entry_code(program, queries, function_name)
    target_source = _source_filename_from_code(target_code)
    entry_points = []
    target_module_present = False
    for ep in getattr(program.interface, "entryPoint", ()):
        code = getattr(ep, "code", None)
        if code is None:
            continue
        if not _is_synthetic_module_code(code):
            entry_points.append(ep)
            continue
        if target_source is not None and _source_filename_from_code(code) == target_source:
            entry_points.append(ep)
            target_module_present = True

    from pyflow.api.entrypoints import nullWrapper

    if target_source is not None and not target_module_present:
        for code in getattr(program, "liveCode", ()):
            if not _is_synthetic_module_code(code):
                continue
            if _source_filename_from_code(code) != target_source:
                continue
            ep = program.interface.createEntryPoint(
                code,
                nullWrapper,
                (),
                [],
                nullWrapper,
                nullWrapper,
                None,
            )
            entry_points.append(ep)
            break

    program.interface.entryPoint = entry_points
    program.entryPoints = entry_points


def _resolve_requested_entry_code(program: Program, queries, function_name: str):
    interface_matches = []
    seen = set()
    for ep in getattr(program.interface, "entryPoint", ()):
        code = getattr(ep, "code", None)
        if code is None or id(code) in seen:
            continue
        if function_name in queries.context.code_aliases(code):
            interface_matches.append(code)
            seen.add(id(code))

    if len(interface_matches) == 1:
        return interface_matches[0]
    if len(interface_matches) > 1:
        raise ValueError(
            f"Function name '{function_name}' is ambiguous among interface entry points."
        )
    return queries.context.resolve_function(function_name)


def load_analysis_session(
    python_files: Sequence[str | Path],
    *,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
    root_function: str | None = None,
) -> AnalysisSession:
    """Load source files into a PyFlow program and build CFGs for all live code."""
    files = [Path(path) for path in python_files]
    compiler = CompilerContext(Console(out=None if verbose else io.StringIO(), verbose=verbose))
    program = Program()

    args = _path_args(verbose, dependency_strategy, search_paths)
    stdout = nullcontext() if verbose else redirect_stdout(io.StringIO())
    preserved_codes = ()
    with stdout:
        program.interface, all_source_code = create_interface_from_paths(files, args)
        compiler.extractor = Extractor(compiler, verbose=verbose, source_code=all_source_code)
        extractProgram(compiler, program)
        if root_function is not None:
            queries = program.get_queries(compiler)
            target_code = _resolve_requested_entry_code(program, queries, root_function)
            target_source = _source_filename_from_code(target_code)
            preserved_codes = tuple(
                code
                for code in program.liveCode
                if _is_synthetic_module_code(code)
                and target_source is not None
                and _source_filename_from_code(code) == target_source
            )
        if root_function is not None:
            _restrict_program_entry_points(compiler, program, root_function)
        prepared = prepare_program_for_ifds(
            compiler,
            program,
            get_cfg=lambda code: program.get_queries(compiler).get_cfg(code),
            describe_code=_code_display_name,
            run_pipeline=lambda: Pipeline(use_pass_manager=True).run_custom_pipeline(
                compiler, program, ["ipa", "cpa"]
            ),
            supplemental_live_codes=preserved_codes,
        )
    adapter = build_supergraph_from_cfgs(
        prepared.cfgs, include_exceptional_edges=include_exceptional_edges
    )
    return AnalysisSession(
        compiler,
        program,
        adapter,
        diagnostics=prepared.diagnostics,
    )


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
    include_exceptional_edges: bool = True,
) -> tuple[AnalysisSession, TaintAnalysisResult]:
    """Load files, resolve a function, and run the shipped taint analysis."""
    session = load_analysis_session(
        python_files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_exceptional_edges=include_exceptional_edges,
        root_function=function,
    )
    queries = session.program.get_queries(session.compiler)
    result = analyze_taint(
        session.adapter,
        TaintConfiguration(
            source_names=frozenset(source_names),
            sink_names=frozenset(sink_names),
            sanitizer_names=frozenset(sanitizer_names),
        ),
        entry_nodes=_entry_nodes_from_program(session, fallback_function=function),
    )
    return session, result


def run_nullness_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
) -> tuple[AnalysisSession, NullnessAnalysisResult]:
    """Load files, resolve a function, and run the shipped nullness analysis."""
    session = load_analysis_session(
        python_files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_exceptional_edges=include_exceptional_edges,
        root_function=function,
    )
    result = analyze_nullness(
        session.adapter,
        entry_nodes=_entry_nodes_from_program(session, fallback_function=function),
    )
    return session, result


def run_typestate_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str,
    open_names: Iterable[str] = ("open",),
    close_names: Iterable[str] = ("close",),
    use_names: Iterable[str] = ("read", "write", "send", "recv"),
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
) -> tuple[AnalysisSession, TypestateAnalysisResult]:
    """Load files, resolve a function, and run the shipped typestate analysis."""
    session = load_analysis_session(
        python_files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_exceptional_edges=include_exceptional_edges,
        root_function=function,
    )
    result = analyze_typestate(
        session.adapter,
        TypestateConfiguration(
            open_names=frozenset(open_names),
            close_names=frozenset(close_names),
            use_names=frozenset(use_names),
        ),
        entry_nodes=_entry_nodes_from_program(session, fallback_function=function),
    )
    return session, result
