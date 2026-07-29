"""Publish constraint-callgraph results through the shared IR fact store."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable

from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import CallTarget, Capabilities, ContextualKey, FactResult
from pyflow.language.python import ast

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


def publish_constraint_callgraph_facts(program, paths: Iterable[str | Path]) -> int:
    """Publish a complete, context-conservative call-target snapshot."""
    catalog = program.ir
    edges = defaultdict(set)
    for path in paths:
        source_path = Path(path)
        source = source_path.read_text(encoding="utf-8")
        for site, targets in extract_call_site_edge_index_constraint(
            source,
            source_path=str(source_path),
            context_sensitive=True,
            context_depth=1,
            allow_fixture_graph_loading=False,
        ).items():
            edges[(site.caller_scope, site.ordinal)].update(targets)

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
        caller_scopes = {
            scope for scope, _ordinal in edges if _scope_matches(code, scope)
        }
        for ordinal, operation in enumerate(calls):
            target_names = set()
            for scope in caller_scopes:
                target_names.update(edges.get((scope, ordinal), ()))
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


__all__ = ["publish_constraint_callgraph_facts"]
