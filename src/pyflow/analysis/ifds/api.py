"""Practical API entry points for IFDS-backed analyses."""

from __future__ import annotations

from contextlib import nullcontext, redirect_stdout
from dataclasses import dataclass
import io
import os
from pathlib import Path
from typing import Iterable, Sequence

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.analysis.callgraph.publication import publish_constraint_callgraph_facts
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.util.application.console import Console

from .frontend.cfg_adapter import (
    CFGSupergraphAdapter,
    build_supergraph_from_cfgs,
)
from .analyses.nullness import (
    NullnessAnalysisResult,
    NullnessConfiguration,
    analyze_nullness,
)
from .modeling.registry import load_registry
from .modeling.calls import CallModelRegistry
from .analyses.taint import TaintAnalysisResult, TaintConfiguration, analyze_taint
from .analyses.typestate import (
    TypestateAnalysisResult,
    TypestateConfiguration,
    analyze_typestate,
)
from .diagnostics import IFDSDiagnostic
from .frontend.preparation import prepare_program_for_ifds
from .core.solver import SolverOptions


@dataclass(frozen=True)
class AnalysisSession:
    """Loaded program plus IFDS-ready CFG supergraph and non-fatal preparation notes."""

    compiler: CompilerContext
    program: Program
    adapter: CFGSupergraphAdapter
    diagnostics: tuple[IFDSDiagnostic, ...] = ()

    @property
    def diagnostic_messages(self) -> tuple[str, ...]:
        """Human-readable diagnostic messages for compatibility and display."""
        return tuple(str(diagnostic) for diagnostic in self.diagnostics)


def _path_options(
    verbose: bool, dependency_strategy: str, search_paths
) -> InterfaceBuildOptions:
    return InterfaceBuildOptions(
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=(
            tuple(str(path) for path in search_paths)
            if search_paths is not None
            else None
        ),
        include_main_entry_points=True,
    )


def _entry_nodes_from_program(
    session: AnalysisSession,
    *,
    function_name: str | None = None,
    entry_file: str | Path | None = None,
):
    if function_name is not None and entry_file is not None:
        raise ValueError("Specify either a function name or an entry file, not both.")

    queries = session.program.get_queries(session.compiler)
    if entry_file is not None:
        target_source = os.path.realpath(entry_file)
        for code in getattr(session.program, "liveCode", ()):
            if not _is_synthetic_module_code(code):
                continue
            if _source_filename_from_code(code) != target_source:
                continue
            cfg = queries.graph_engine.get_cfg(code)
            return (session.adapter.supergraph.entry_of(cfg),)
        raise ValueError(f"Unable to find module entry CFG for '{entry_file}'.")

    if function_name is not None:
        target_code = queries.context.resolve_function(function_name)
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
    catalog = getattr(code, "ir_catalog", None)
    if catalog is None:
        return None
    origin = catalog.source_of(code, code=code)
    span = getattr(origin, "span", None)
    filename = getattr(span, "path", None)
    if not filename:
        filename = catalog.procedure(code).code_id.anchor.filename
    return os.path.realpath(filename) if filename else None


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
    catalog = getattr(code, "ir_catalog", None)
    return bool(
        catalog is not None
        and catalog.procedure(code).construct_kind == "synthetic_module"
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
        if (
            target_source is not None
            and _source_filename_from_code(code) == target_source
        ):
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


def _restrict_program_entry_points_to_file(
    program: Program,
    entry_file: str | Path,
) -> tuple[object, ...]:
    """Keep only the synthetic module root corresponding to *entry_file*."""
    target_source = os.path.realpath(entry_file)
    live_codes = tuple(getattr(program, "liveCode", ()))
    source_codes = tuple(
        code for code in live_codes if _source_filename_from_code(code) == target_source
    )
    matching_codes = tuple(
        code for code in source_codes if _is_synthetic_module_code(code)
    )
    if not matching_codes:
        raise ValueError(f"Entry file '{entry_file}' has no executable module body.")

    from pyflow.api.entrypoints import nullWrapper

    entry_points = []
    existing_by_code = {
        getattr(entry_point, "code", None): entry_point
        for entry_point in getattr(program.interface, "entryPoint", ())
    }
    for code in matching_codes:
        entry_point = existing_by_code.get(code)
        if entry_point is None:
            entry_point = program.interface.createEntryPoint(
                code,
                nullWrapper,
                (),
                [],
                nullWrapper,
                nullWrapper,
                None,
            )
        entry_points.append(entry_point)

    program.interface.entryPoint = entry_points
    program.entryPoints = entry_points
    # The constraint call graph may resolve calls into any loaded project module.
    # Keep those procedures available as CFGs, but seed only the selected module.
    return live_codes


def _resolve_requested_entry_code(program: Program, queries, function_name: str):
    interface_matches = []
    seen = set()
    for ep in getattr(program.interface, "entryPoint", ()):
        code = getattr(ep, "code", None)
        if code is None or code in seen:
            continue
        if function_name in queries.context.code_aliases(code):
            interface_matches.append(code)
            seen.add(code)

    if len(interface_matches) == 1:
        return interface_matches[0]
    if len(interface_matches) > 1:
        raise ValueError(
            f"Function name '{function_name}' is ambiguous among "
            "interface entry points."
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
    entry_file: str | Path | None = None,
) -> AnalysisSession:
    """Load source files into a PyFlow program and build CFGs for all live code."""
    if root_function is not None and entry_file is not None:
        raise ValueError("Specify either root_function or entry_file, not both.")

    files = [Path(path) for path in python_files]
    compiler = CompilerContext(
        Console(out=None if verbose else io.StringIO(), verbose=verbose)
    )
    program = Program()

    options = _path_options(verbose, dependency_strategy, search_paths)
    stdout = nullcontext() if verbose else redirect_stdout(io.StringIO())
    preserved_codes = ()
    target_source: str | None = None
    with stdout:
        program.interface, all_source_code = build_interface_from_paths(files, options)
        if entry_file is not None:
            # A file entry seeds its synthetic module body. Function/class
            # declarations inferred by the generic interface builder are
            # unrelated roots and may require invocation arguments that the
            # module-entry analysis never supplies.
            program.interface.func.clear()
            program.interface.cls.clear()
        compiler.extractor = Extractor(
            compiler,
            verbose=verbose,
            source_code=all_source_code,
            defer_semantics=True,
        )
        extract_program(compiler, program)
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
        elif entry_file is not None:
            preserved_codes = _restrict_program_entry_points_to_file(
                program, entry_file
            )
        prepared = prepare_program_for_ifds(
            compiler,
            program,
            get_cfg=lambda code: program.get_queries(compiler).graph_engine.get_cfg(
                code, commit_revision=False
            ),
            supplemental_live_codes=preserved_codes,
        )
        callgraph_entry = entry_file or target_source or (files[0] if files else None)
        publish_constraint_callgraph_facts(
            program,
            files,
            entry_path=callgraph_entry,
            analyze_reachable_only=entry_file is not None,
        )
    adapter = build_supergraph_from_cfgs(
        prepared.cfgs,
        include_exceptional_edges=include_exceptional_edges,
        catalog=prepared.catalog,
        cfgs_indexed=True,
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
    function: str | None = None,
    entry_file: str | Path | None = None,
    call_models=None,
    rules=(),
    collection_mutator_names: Iterable[str] | None = None,
    collection_accessor_names: Iterable[str] | None = None,
    conservative_unresolved_call_side_effects: bool = False,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
    shadow_scan: bool = False,
    solver_options: SolverOptions | None = None,
) -> tuple[AnalysisSession, TaintAnalysisResult, list | None]:
    """Load files and run taint analysis from a function or module entry.

    When *shadow_scan* is ``True``, returns a third element: a list of
    :class:`~pyflow.analysis.ifds.shadow_scan.ShadowMatch` from a
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
    )
    result = analyze_taint(
        session.adapter,
        TaintConfiguration(
            call_models=(
                call_models if call_models is not None else CallModelRegistry()
            ),
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
            conservative_unresolved_call_side_effects=(
                conservative_unresolved_call_side_effects
            ),
        ),
        entry_nodes=_entry_nodes_from_program(
            session, function_name=function, entry_file=entry_file
        ),
        **({"solver_options": solver_options} if solver_options is not None else {}),
    )

    if not shadow_scan:
        return session, result, None

    from .shadow_scan import run_shadow_scan as _run_shadow_scan

    shadow_matches: list = []
    for f in python_files:
        code = Path(f).read_text(encoding="utf-8")
        shadow_matches.extend(_run_shadow_scan(code))
    return session, result, shadow_matches


def run_nullness_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str | None = None,
    entry_file: str | Path | None = None,
    nullable_return_names: Iterable[str] = (),
    collection_mutator_names: Iterable[str] | None = None,
    collection_accessor_names: Iterable[str] | None = None,
    registry_frameworks: Iterable[str] = (),
    registry_paths: Iterable[str] = (),
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
    solver_options: SolverOptions | None = None,
) -> tuple[AnalysisSession, NullnessAnalysisResult]:
    """Load files and run nullness analysis from a function or module entry."""
    files = [Path(path) for path in python_files]
    session = load_analysis_session(
        files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_exceptional_edges=include_exceptional_edges,
        root_function=function,
        entry_file=entry_file,
    )
    result = analyze_nullness(
        session.adapter,
        NullnessConfiguration(
            nullable_return_names=frozenset(nullable_return_names),
            call_models=_registry_models(
                files,
                type="nullness",
                frameworks=registry_frameworks,
                custom_paths=registry_paths,
            ),
            collection_mutator_names=(
                frozenset(collection_mutator_names)
                if collection_mutator_names is not None
                else NullnessConfiguration().collection_mutator_names
            ),
            collection_accessor_names=(
                frozenset(collection_accessor_names)
                if collection_accessor_names is not None
                else NullnessConfiguration().collection_accessor_names
            ),
        ),
        entry_nodes=_entry_nodes_from_program(
            session, function_name=function, entry_file=entry_file
        ),
        **({"solver_options": solver_options} if solver_options is not None else {}),
    )
    return session, result


def run_typestate_analysis(
    python_files: Sequence[str | Path],
    *,
    function: str | None = None,
    entry_file: str | Path | None = None,
    open_names: Iterable[str] = ("open",),
    close_names: Iterable[str] = ("close",),
    use_names: Iterable[str] = ("read", "write", "send", "recv"),
    enabled_protocols: Iterable[str] = ("resource",),
    registry_frameworks: Iterable[str] = (),
    registry_paths: Iterable[str] = (),
    collection_mutator_names: Iterable[str] | None = None,
    collection_accessor_names: Iterable[str] | None = None,
    verbose: bool = False,
    dependency_strategy: str = "auto",
    search_paths: Sequence[str] | None = None,
    include_exceptional_edges: bool = True,
    solver_options: SolverOptions | None = None,
) -> tuple[AnalysisSession, TypestateAnalysisResult]:
    """Load files and run typestate analysis from a function or module entry."""
    files = [Path(path) for path in python_files]
    session = load_analysis_session(
        files,
        verbose=verbose,
        dependency_strategy=dependency_strategy,
        search_paths=search_paths,
        include_exceptional_edges=include_exceptional_edges,
        root_function=function,
        entry_file=entry_file,
    )
    result = analyze_typestate(
        session.adapter,
        TypestateConfiguration(
            open_names=frozenset(open_names),
            close_names=frozenset(close_names),
            use_names=frozenset(use_names),
            enabled_protocols=_normalize_typestate_protocols(enabled_protocols),
            call_models=_registry_models(
                files,
                type="typestate",
                frameworks=registry_frameworks,
                custom_paths=registry_paths,
            ),
            collection_mutator_names=(
                frozenset(collection_mutator_names)
                if collection_mutator_names is not None
                else TypestateConfiguration().collection_mutator_names
            ),
            collection_accessor_names=(
                frozenset(collection_accessor_names)
                if collection_accessor_names is not None
                else TypestateConfiguration().collection_accessor_names
            ),
        ),
        entry_nodes=_entry_nodes_from_program(
            session, function_name=function, entry_file=entry_file
        ),
        **({"solver_options": solver_options} if solver_options is not None else {}),
    )
    return session, result


def _registry_models(
    files: Sequence[Path],
    *,
    type: str,
    frameworks: Iterable[str],
    custom_paths: Iterable[str] = (),
):
    """Load call models from the JSON rule-pack registry, filtered by *type*.

    Activates named frameworks (auto-detects when the list is empty, falls
    back to ``"stdlib"``).  Returns a ``CallModelRegistry`` or ``None`` when
    no loadable models are configured.
    """
    frameworks = tuple(frameworks)
    custom_paths = tuple(custom_paths)
    if not frameworks and not custom_paths:
        return None

    registry = load_registry()
    if frameworks:
        registry.activate(*frameworks, type=type)
    else:
        all_detected: set[str] = set()
        for path in files:
            try:
                all_detected |= registry.detect(
                    path.read_text(encoding="utf-8").splitlines()
                )
            except OSError:
                continue
        if all_detected:
            registry.activate(*all_detected, type=type)
        else:
            registry.activate("stdlib", type=type)
    if custom_paths:
        registry.load_custom(*custom_paths)
    return registry.active_models()


def _normalize_typestate_protocols(protocols: Iterable[str]) -> frozenset[str]:
    names = frozenset(protocols)
    if "python-builtins" not in names:
        return names
    return (names - {"python-builtins"}) | frozenset(
        {"file", "socket", "lock", "transaction"}
    )
