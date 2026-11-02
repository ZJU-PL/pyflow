"""Invariant checks for the shared IR catalog."""

from __future__ import annotations

from pyflow.language.python import ast

from .catalog import IRCatalog
from .ids import SymbolId, ValueId


class IRVerificationError(ValueError):
    pass


def verify_catalog(catalog: IRCatalog, code_id=None) -> None:
    """Verify catalog invariants, optionally restricted to one procedure.

    A scoped check keeps per-function CFG/SSA transactions O(function) instead
    of re-scanning every procedure in the catalog.
    """
    scoped = code_id is not None
    procedures = None if scoped else {procedure.code_id for procedure in catalog.procedures()}

    def known_code(code) -> bool:
        if procedures is not None:
            return code in procedures
        return catalog.has_procedure(code)

    node_items = catalog.nodes_for_code(code_id) if scoped else catalog.nodes()
    for node_id, node in node_items:
        if not known_code(node_id.code):
            raise IRVerificationError(f"node belongs to unknown code: {node_id}")
        semantics = catalog.semantics.get_operation(node_id)
        if not isinstance(node, ast.PythonASTNode):
            continue
        if semantics is None:
            raise IRVerificationError(f"node has no structural semantics: {node_id}")
        for call_id in semantics.calls:
            if call_id.node != node_id:
                raise IRVerificationError(f"call site belongs to the wrong operation: {call_id}")
            try:
                call = catalog.semantics.call_site(call_id)
            except KeyError as exc:
                raise IRVerificationError(
                    f"operation refers to unknown call site: {call_id}"
                ) from exc
            if call.operation != node_id:
                raise IRVerificationError(f"call record belongs to the wrong operation: {call_id}")
        for allocation_id in semantics.allocations:
            if allocation_id.node != node_id:
                raise IRVerificationError(
                    "allocation site belongs to the wrong operation: " f"{allocation_id}"
                )

    block_items = catalog.blocks_for_code(code_id) if scoped else catalog.blocks()
    blocks = {block_id for block_id, _block in block_items}
    for block_id in blocks:
        if not known_code(block_id.code):
            raise IRVerificationError(f"block belongs to unknown code: {block_id}")
    edge_items = catalog.edges_for_code(code_id) if scoped else catalog.edges()
    for edge_id, (source, target) in edge_items:
        if edge_id.source != source:
            raise IRVerificationError(f"edge source identity mismatch: {edge_id}")
        if source not in blocks or target not in blocks:
            raise IRVerificationError(f"edge refers to unknown block: {edge_id}")

    symbol_items = catalog.symbols.for_code(code_id) if scoped else tuple(catalog.symbols)
    symbols = {symbol.id for symbol in symbol_items}
    for symbol in symbol_items:
        if not known_code(symbol.id.scope.code):
            raise IRVerificationError(f"symbol belongs to unknown code: {symbol.id}")
        if symbol.source_symbol is not None and not catalog.symbols.contains(symbol.source_symbol):
            raise IRVerificationError(f"symbol has unknown source binding: {symbol.id}")

    value_items = catalog.values.for_code(code_id) if scoped else tuple(catalog.values)
    values = {value.id for value in value_items}
    for value in value_items:
        if not catalog.symbols.contains(value.id.symbol):
            raise IRVerificationError(f"value belongs to unknown symbol: {value.id}")
        if value.definition is not None:
            try:
                catalog.node(value.definition)
            except KeyError as exc:
                raise IRVerificationError(f"value has unknown definition: {value.id}") from exc

    for node_id, _node in node_items:
        semantics = catalog.semantics.get_operation(node_id)
        if semantics is None:
            continue
        for identity in (*semantics.definitions, *semantics.uses):
            if isinstance(identity, SymbolId) and not catalog.symbols.contains(identity):
                raise IRVerificationError(f"unknown semantic symbol: {identity}")
            if isinstance(identity, ValueId) and not catalog.values.contains(identity):
                raise IRVerificationError(f"unknown semantic value: {identity}")

    context_items = catalog.contexts_for_code(code_id) if scoped else catalog.contexts()
    for context_id, _context in context_items:
        if not known_code(context_id.code):
            raise IRVerificationError(f"context belongs to unknown code: {context_id}")
