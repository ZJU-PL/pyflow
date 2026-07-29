"""Invariant checks for the shared IR catalog."""

from __future__ import annotations

from pyflow.language.python import ast

from .catalog import IRCatalog
from .ids import SymbolId, ValueId


class IRVerificationError(ValueError):
    pass


def verify_catalog(catalog: IRCatalog) -> None:
    procedures = {procedure.code_id for procedure in catalog.procedures()}

    for node_id, node in catalog.nodes():
        if node_id.code not in procedures:
            raise IRVerificationError(f"node belongs to unknown code: {node_id}")
        semantics = catalog.semantics.get_operation(node_id)
        if not isinstance(node, ast.PythonASTNode):
            continue
        if semantics is None:
            raise IRVerificationError(f"node has no structural semantics: {node_id}")
        for call_id in semantics.calls:
            if call_id.node != node_id:
                raise IRVerificationError(
                    f"call site belongs to the wrong operation: {call_id}"
                )
            try:
                call = catalog.semantics.call_site(call_id)
            except KeyError as exc:
                raise IRVerificationError(
                    f"operation refers to unknown call site: {call_id}"
                ) from exc
            if call.operation != node_id:
                raise IRVerificationError(
                    f"call record belongs to the wrong operation: {call_id}"
                )
        for allocation_id in semantics.allocations:
            if allocation_id.node != node_id:
                raise IRVerificationError(
                    "allocation site belongs to the wrong operation: "
                    f"{allocation_id}"
                )

    blocks = {block_id for block_id, _block in catalog.blocks()}
    for block_id in blocks:
        if block_id.code not in procedures:
            raise IRVerificationError(f"block belongs to unknown code: {block_id}")
    for edge_id, (source, target) in catalog.edges():
        if edge_id.source != source:
            raise IRVerificationError(f"edge source identity mismatch: {edge_id}")
        if source not in blocks or target not in blocks:
            raise IRVerificationError(f"edge refers to unknown block: {edge_id}")

    symbols = {symbol.id for symbol in catalog.symbols}
    for symbol in catalog.symbols:
        if symbol.id.scope.code not in procedures:
            raise IRVerificationError(
                f"symbol belongs to unknown code: {symbol.id}"
            )
        if symbol.source_symbol is not None and symbol.source_symbol not in symbols:
            raise IRVerificationError(
                f"symbol has unknown source binding: {symbol.id}"
            )

    values = {value.id for value in catalog.values}
    for value in catalog.values:
        if value.id.symbol not in symbols:
            raise IRVerificationError(
                f"value belongs to unknown symbol: {value.id}"
            )
        if value.definition is not None:
            try:
                catalog.node(value.definition)
            except KeyError as exc:
                raise IRVerificationError(
                    f"value has unknown definition: {value.id}"
                ) from exc

    for _node_id, semantics in catalog.semantics.items():
        for identity in (*semantics.definitions, *semantics.uses):
            if isinstance(identity, SymbolId) and identity not in symbols:
                raise IRVerificationError(f"unknown semantic symbol: {identity}")
            if isinstance(identity, ValueId) and identity not in values:
                raise IRVerificationError(f"unknown semantic value: {identity}")

    for context_id, _context in catalog.contexts():
        if context_id.code not in procedures:
            raise IRVerificationError(
                f"context belongs to unknown code: {context_id}"
            )
