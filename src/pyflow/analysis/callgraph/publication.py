"""Publish constraint-callgraph results through the shared IR fact store."""

from __future__ import annotations

from collections import defaultdict
import os
from pathlib import Path
from typing import Iterable, Mapping

from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import CallTarget, Capabilities, ContextualKey, FactResult
from pyflow.language.python import ast
from pyflow.language.source_compat import normalize_legacy_python_syntax

from .constraint_based import extract_call_site_edge_index_constraint


def _scope_matches(code, scope: str) -> bool:
    name = code.codeName()
    return scope == name or scope.endswith(f".{name}")


def _target_codes(catalog, name: str):
    short_name = name.rsplit(".", 1)[-1]
    matches = []
    for procedure in catalog.procedures():
        code = catalog.code(procedure.code_id)
        if (
            procedure.code_id.qualname == name
            or procedure.code_id.qualname.endswith(f".{name}")
            or code.codeName() == short_name
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


def _source_line(catalog, code, operation) -> int | None:
    try:
        origin = catalog.source_of(operation, code=code)
    except KeyError:
        return None
    span = getattr(origin, "span", None)
    return getattr(span, "start_line", None)


def extract_constraint_callgraph_edges(
    paths: Iterable[str | Path],
    *,
    entry_path: str | Path | None = None,
    analyze_reachable_only: bool = False,
):
    """Compute source-level constraint edges without mutating the IR catalog."""
    source_paths = tuple(Path(path).resolve() for path in paths)
    if entry_path is None:
        if not source_paths:
            return {}
        analysis_entry = source_paths[0]
    else:
        analysis_entry = Path(entry_path).resolve()
    source = normalize_legacy_python_syntax(
        analysis_entry.read_text(encoding="utf-8", errors="replace")
    )
    additional_sources = {
        str(path): normalize_legacy_python_syntax(
            path.read_text(encoding="utf-8", errors="replace")
        )
        for path in source_paths
        if path != analysis_entry
    }
    return extract_call_site_edge_index_constraint(
        source,
        source_path=str(analysis_entry),
        context_sensitive=False,
        fixpoint_max_iterations=2000,
        allow_fixture_graph_loading=False,
        skip_external_modules=True,
        analyze_reachable_only=analyze_reachable_only,
        seed_entry_file_scopes=analyze_reachable_only,
        additional_sources=additional_sources,
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
    module_edges = defaultdict(set)
    source_paths = tuple(Path(path).resolve() for path in paths)
    if entry_path is None:
        if not source_paths:
            return 0
        analysis_entry = source_paths[0]
    else:
        analysis_entry = Path(entry_path).resolve()
    computed_edges = edge_index or extract_constraint_callgraph_edges(
        source_paths,
        entry_path=analysis_entry,
        analyze_reachable_only=analyze_reachable_only,
    )
    for site, targets in computed_edges.items():
        site_source = os.path.realpath(site.source_path or analysis_entry)
        edges[(site_source, site.caller_scope, site.ordinal)].update(targets)
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
        caller_scopes = {
            scope
            for edge_source, scope, _ordinal in edges
            if edge_source == source_filename
            and (_scope_matches(code, scope) or (is_module and scope == "main"))
        }
        for ordinal, operation in enumerate(calls):
            if is_module:
                target_names = set(
                    module_edges.get(
                        (source_filename, _source_line(catalog, code, operation)), ()
                    )
                )
            else:
                target_names = set()
                for scope in caller_scopes:
                    target_names.update(
                        edges.get((source_filename, scope, ordinal), ())
                    )
            target_codes = {
                target
                for target_name in target_names
                for target in _target_codes(catalog, target_name)
            }
            targets = {
                CallTarget(catalog.procedure(target).code_id, target_context)
                for target in target_codes
                for target_context in contexts_by_code.get(
                    catalog.procedure(target).code_id, ()
                )
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
    "extract_constraint_callgraph_edges",
    "publish_constraint_callgraph_facts",
    "target_codes_for_constraint_edges",
]
