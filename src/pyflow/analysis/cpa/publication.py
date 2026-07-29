"""Publish CPA solver state through the shared IR fact store."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from pyflow.ir.core import (
    CallTarget,
    Capabilities,
    ContextualKey,
    FactResult,
    IRCatalog,
)
from pyflow.ir.core.order import canonical_context_signature, stable_ir_key
from pyflow.language.python import ast


@dataclass(frozen=True)
class OperationFacts:
    operation: object
    context: object
    reads: frozenset[object]
    writes: frozenset[object]
    allocations: frozenset[object]
    targets: frozenset[tuple[object, object]]


@dataclass(frozen=True)
class ReferenceFacts:
    reference: object
    context: object
    locations: frozenset[object]


@dataclass(frozen=True)
class CodeFacts:
    code: ast.Code
    contexts: tuple[object, ...]
    reads: dict[object, frozenset[object]]
    writes: dict[object, frozenset[object]]
    allocations: dict[object, frozenset[object]]
    operations: tuple[OperationFacts, ...]
    references: tuple[ReferenceFacts, ...]


def publish_cpa_facts(
    catalog: IRCatalog,
    records: Iterable[CodeFacts],
) -> int:
    """Publish one complete CPA snapshot without consulting AST annotations."""
    records = tuple(records)
    context_ids: dict[tuple[ast.Code, object], object] = {}
    contexts_by_code: dict[object, FactResult] = {}

    for record in records:
        code_id = catalog.procedure(record.code).code_id
        ordered = tuple(
            sorted(
                record.contexts,
                key=lambda context: stable_ir_key(context, catalog, record.code),
            )
        )
        ids = []
        for context in ordered:
            context_id = catalog.register_context(
                record.code,
                context,
                canonical_context_signature(context, catalog, record.code),
            )
            context_ids[(record.code, context)] = context_id
            ids.append(context_id)
        contexts_by_code[code_id] = FactResult.exact(ids, "cpa")

    reference_values = defaultdict(set)
    call_targets = {}
    op_reads = {}
    op_writes = {}
    op_allocations = {}
    code_reads = {}
    code_writes = {}
    code_allocations = {}

    for record in records:
        code_id = catalog.procedure(record.code).code_id
        for context in record.contexts:
            context_id = context_ids[(record.code, context)]
            for symbol in catalog.symbols:
                if symbol.id.scope.code == code_id:
                    reference_values[ContextualKey(symbol.id, context_id)]
            code_key = ContextualKey(code_id, context_id)
            code_reads[code_key] = FactResult.exact(
                record.reads.get(context, ()), "cpa"
            )
            code_writes[code_key] = FactResult.exact(
                record.writes.get(context, ()), "cpa"
            )
            code_allocations[code_key] = FactResult.exact(
                record.allocations.get(context, ()), "cpa"
            )

        for fact in record.operations:
            context_id = context_ids[(record.code, fact.context)]
            node_id = catalog.node_id(fact.operation, record.code)
            key = ContextualKey(node_id, context_id)
            op_reads[key] = FactResult.exact(fact.reads, "cpa")
            op_writes[key] = FactResult.exact(fact.writes, "cpa")
            op_allocations[key] = FactResult.exact(fact.allocations, "cpa")
            targets = []
            for target_code, target_context in fact.targets:
                target_id = context_ids.get((target_code, target_context))
                if target_id is None:
                    continue
                targets.append(
                    CallTarget(catalog.procedure(target_code).code_id, target_id)
                )
            call_targets[key] = FactResult.exact(targets, "cpa")

        for fact in record.references:
            context_id = context_ids[(record.code, fact.context)]
            if isinstance(fact.reference, ast.Local):
                entity = catalog.symbol_id(fact.reference, record.code)
            else:
                entity = catalog.node_id(fact.reference, record.code)
            reference_values[ContextualKey(entity, context_id)].update(
                fact.locations
            )

    return catalog.facts.publish_many(
        "cpa",
        {
            Capabilities.CONTEXTS: contexts_by_code,
            Capabilities.REFERENCES: {
                key: FactResult.exact(values, "cpa")
                for key, values in reference_values.items()
            },
            Capabilities.CALL_TARGETS: call_targets,
            Capabilities.OP_READS: op_reads,
            Capabilities.OP_WRITES: op_writes,
            Capabilities.OP_ALLOCATIONS: op_allocations,
            Capabilities.CODE_READS: code_reads,
            Capabilities.CODE_WRITES: code_writes,
            Capabilities.CODE_ALLOCATIONS: code_allocations,
        },
    )


__all__ = [
    "CodeFacts",
    "OperationFacts",
    "ReferenceFacts",
    "publish_cpa_facts",
]
