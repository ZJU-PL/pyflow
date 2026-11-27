"""Publish constraint-callgraph results through the shared IR fact store."""

from __future__ import annotations

from pyflow.frontend.source import read_python_source

import ast as py_stdlib_ast
from collections import defaultdict
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterable, Mapping

from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import CallTarget, Capabilities, ContextualKey, FactResult
from pyflow.language.python import ast
from pyflow.language.source_compat import normalize_legacy_python_syntax

from .constraint_based import AnalysisOptions, ConstraintCallGraphBuilder


@dataclass(frozen=True)
class ConstraintCallgraphAnalysis:
    """Partial-or-complete source call graph plus convergence metadata."""

    edges: Mapping[object, frozenset[str]]
    iterations: int
    truncated: bool


def _scope_matches(code, scope: str) -> bool:
    name = code.codeName()
    return scope == name or scope.endswith(f".{name}")


def _target_codes(catalog, name: str):
    candidate_names = {name}
    if name.startswith("main."):
        candidate_names.add(name[len("main.") :])
    short_names = {candidate.rsplit(".", 1)[-1] for candidate in candidate_names}
    matches = []
    for procedure in catalog.procedures():
        code = catalog.code(procedure.code_id)
        if (
            procedure.code_id.qualname in candidate_names
            or any(
                procedure.code_id.qualname.endswith(f".{candidate}")
                for candidate in candidate_names
            )
            or code.codeName() in candidate_names
            or code.codeName() in short_names
        ):
            matches.append(code)
    return tuple(matches)


def _source_filename(catalog, code) -> str | None:
    try:
        origin = catalog.source_of(code, code=code)
    except KeyError:
        origin = None
    span = getattr(origin, "span", None)
    filename = getattr(span, "path", None)
    if not filename:
        filename = catalog.procedure(code).code_id.anchor.filename
    return os.path.realpath(filename) if filename else None


def _source_location(catalog, code, operation) -> tuple[int, int] | None:
    try:
        origin = catalog.source_of(operation, code=code)
    except KeyError:
        return None
    span = getattr(origin, "span", None)
    start_line = getattr(span, "start_line", None)
    start_column = getattr(span, "start_column", None)
    if start_line is None or start_column is None:
        return None
    return (int(start_line), int(start_column))


def _is_interpreter_helper_call(operation) -> bool:
    if not isinstance(operation, ast.Call):
        return False
    expr = getattr(operation, "expr", None)
    if not isinstance(expr, ast.Existing):
        return False
    obj = getattr(expr, "object", None)
    pyobj = getattr(obj, "pyobj", None)
    name = getattr(pyobj, "__name__", None) or str(obj)
    return "interpreter" in str(name)


def _matching_caller_scopes(
    procedure, code, candidate_scopes: Iterable[str], is_module: bool
) -> set[str]:
    matched = {
        scope
        for scope in candidate_scopes
        if _scope_matches(code, scope) or (is_module and scope == "main")
    }
    if is_module or len(matched) <= 1:
        return matched
    # Disambiguate same-named methods vs module-level functions in the same file
    # (e.g. ``mod.foo`` vs ``mod.Class.foo``) using the IR procedure's qualname.
    qual_parts = [
        part
        for part in procedure.code_id.qualname.split(".")
        if part and part not in {"<module>", "<locals>"}
    ]
    if len(qual_parts) >= 2:
        # Prefer scopes sharing the immediate enclosing qualifier (class or outer function).
        tail2 = ".".join(qual_parts[-2:])
        narrowed = {scope for scope in matched if scope == tail2 or scope.endswith(f".{tail2}")}
        if narrowed:
            return narrowed
    return matched


def extract_constraint_callgraph_edges(
    paths: Iterable[str | Path],
    *,
    entry_path: str | Path | None = None,
    analyze_reachable_only: bool = False,
    max_iterations: int = 256,
    follow_imports: bool = True,
):
    """Compute source-level constraint edges without mutating the IR catalog."""
    return analyze_constraint_callgraph_edges(
        paths,
        entry_path=entry_path,
        analyze_reachable_only=analyze_reachable_only,
        max_iterations=max_iterations,
        follow_imports=follow_imports,
    ).edges


def analyze_constraint_callgraph_edges(
    paths: Iterable[str | Path],
    *,
    entry_path: str | Path | None = None,
    analyze_reachable_only: bool = False,
    max_iterations: int = 256,
    follow_imports: bool = True,
) -> ConstraintCallgraphAnalysis:
    """Compute constraint edges and expose whether the bounded pass converged."""
    source_paths = tuple(Path(path).resolve() for path in paths)
    if not source_paths and entry_path is None:
        return ConstraintCallgraphAnalysis({}, 0, False)

    def _try_parse_source(path: Path) -> str | None:
        try:
            text = normalize_legacy_python_syntax(read_python_source(path))
            py_stdlib_ast.parse(text, filename=str(path))
            return text
        except (OSError, UnicodeError, SyntaxError, ValueError):
            return None

    parsed_sources: dict[Path, str] = {}
    for path in source_paths:
        text = _try_parse_source(path)
        if text is not None:
            parsed_sources[path] = text

    if entry_path is None:
        analysis_entry = next(iter(parsed_sources), None)
    else:
        resolved_entry = Path(entry_path).resolve()
        if resolved_entry not in parsed_sources:
            text = _try_parse_source(resolved_entry)
            if text is not None:
                parsed_sources[resolved_entry] = text
        analysis_entry = (
            resolved_entry if resolved_entry in parsed_sources else next(iter(parsed_sources), None)
        )

    if analysis_entry is None:
        return ConstraintCallgraphAnalysis({}, 0, False)

    source = parsed_sources[analysis_entry]
    additional_sources = {
        str(path): text for path, text in parsed_sources.items() if path != analysis_entry
    }
    builder = ConstraintCallGraphBuilder(
        source,
        entry_path=str(analysis_entry),
        options=AnalysisOptions(
            context_sensitive=False,
            # Publishing an entry-rooted graph is a preparatory precision pass,
            # not the IFDS fixpoint itself. Bound the scope states so a large
            # vendored tree cannot consume the whole project timeout first.
            fixpoint_max_iterations=max(1, int(max_iterations)),
            allow_fixture_graph_loading=False,
            skip_external_modules=True,
            follow_imports=follow_imports,
            analyze_reachable_only=analyze_reachable_only,
            seed_entry_file_scopes=analyze_reachable_only,
        ),
        additional_sources=additional_sources,
    )
    builder.build()
    return ConstraintCallgraphAnalysis(
        edges=builder.call_site_edge_index(),
        iterations=builder.fixpoint_iterations,
        truncated=builder.fixpoint_truncated,
    )


def target_codes_for_constraint_edges(catalog, edge_index) -> frozenset[object]:
    """Resolve all target names in an edge index to loaded IR code objects."""
    return frozenset(
        target
        for targets in edge_index.values()
        for target_name in targets
        for target in _target_codes(catalog, target_name)
    )


def publish_constraint_callgraph_facts(
    program,
    paths: Iterable[str | Path],
    *,
    entry_path: str | Path | None = None,
    analyze_reachable_only: bool = False,
    edge_index: Mapping[object, Iterable[str]] | None = None,
) -> int:
    """Publish a complete, context-conservative call-target snapshot."""
    catalog = program.ir
    edges = defaultdict(set)
    edges_by_location = defaultdict(set)
    module_edges = defaultdict(set)
    scopes_by_source = defaultdict(set)
    source_paths = tuple(Path(path).resolve() for path in paths)
    if entry_path is None:
        if not source_paths:
            return 0
        analysis_entry = source_paths[0]
    else:
        analysis_entry = Path(entry_path).resolve()
    computed_edges = (
        edge_index
        if edge_index is not None
        else extract_constraint_callgraph_edges(
            source_paths,
            entry_path=analysis_entry,
            analyze_reachable_only=analyze_reachable_only,
        )
    )
    for site, targets in computed_edges.items():
        site_source = os.path.realpath(site.source_path or analysis_entry)
        scopes_by_source[site_source].add(site.caller_scope)
        edges[(site_source, site.caller_scope, site.ordinal)].update(targets)
        if site.line > 0 and site.column >= 0:
            edges_by_location[(site_source, site.caller_scope, site.line, site.column)].update(
                targets
            )
        if site.is_module_scope:
            module_edges[(site_source, site.line)].update(targets)

    contexts_by_code = {}
    for procedure in catalog.procedures():
        result = catalog.facts.query(Capabilities.CONTEXTS, procedure.code_id)
        contexts_by_code[procedure.code_id] = tuple(sorted(result.values))

    published = {}
    published_codes = {}
    call_types = (ast.Call, ast.DirectCall, ast.MethodCall)
    for procedure in catalog.procedures():
        code = catalog.code(procedure.code_id)
        calls = tuple(op for op in getOps(code)[0] if isinstance(op, call_types))
        source_filename = _source_filename(catalog, code)
        is_module = procedure.construct_kind == "synthetic_module"
        caller_scopes = _matching_caller_scopes(
            procedure,
            code,
            scopes_by_source.get(source_filename, ()),
            is_module,
        )
        for ordinal, operation in enumerate(calls):
            location = _source_location(catalog, code, operation)
            target_names = set()
            if location is not None:
                line, column = location
                for scope in caller_scopes:
                    target_names.update(
                        edges_by_location.get((source_filename, scope, line, column), ())
                    )
                if is_module and not target_names and not _is_interpreter_helper_call(operation):
                    target_names.update(module_edges.get((source_filename, line), ()))
            elif is_module:
                target_names.update(module_edges.get((source_filename, None), ()))
            else:
                for scope in caller_scopes:
                    target_names.update(edges.get((source_filename, scope, ordinal), ()))
            target_codes = {
                target
                for target_name in target_names
                for target in _target_codes(catalog, target_name)
            }
            targets = {
                CallTarget(catalog.procedure(target).code_id, target_context)
                for target in target_codes
                for target_context in contexts_by_code.get(catalog.procedure(target).code_id, ())
            }
            node_id = catalog.node_id(operation, code)
            published_codes[node_id] = FactResult.exact(
                (catalog.procedure(target).code_id for target in target_codes),
                "constraint-callgraph",
            )
            for context_id in contexts_by_code.get(procedure.code_id, ()):
                published[ContextualKey(node_id, context_id)] = FactResult.exact(
                    targets, "constraint-callgraph"
                )

    return catalog.facts.publish_many(
        "constraint-callgraph",
        {
            Capabilities.CALL_TARGETS: published,
            Capabilities.CALL_TARGET_CODES: published_codes,
        },
    )


__all__ = [
    "ConstraintCallgraphAnalysis",
    "analyze_constraint_callgraph_edges",
    "extract_constraint_callgraph_edges",
    "publish_constraint_callgraph_facts",
    "target_codes_for_constraint_edges",
]
