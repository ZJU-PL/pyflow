"""Procedure-level heap summaries for IFDS heap effects."""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.language.python import ast as py_ast

from .model import HeapLocation, HeapObject, HeapWrite
from .heap_effects import HeapEffectBuilder


@dataclass(frozen=True)
class HeapSummary:
    """Monotone procedure summary over operation-level heap effects."""

    reads: tuple[HeapLocation, ...] = ()
    writes: tuple[HeapWrite, ...] = ()
    deletes: tuple[HeapLocation, ...] = ()
    escapes: tuple[HeapLocation, ...] = ()
    returns: tuple[HeapLocation, ...] = ()
    allocations: tuple[HeapObject, ...] = ()

    def strong_write_locations(self) -> tuple[HeapLocation, ...]:
        return tuple(
            dict.fromkeys(
                write.location for write in self.writes if write.policy.value == "strong"
            )
        )

    def __repr__(self) -> str:
        nz = {
            k: len(v) for k, v in (
                ("r", self.reads), ("w", self.writes),
                ("d", self.deletes), ("e", self.escapes),
                ("ret", self.returns),
            ) if v
        }
        detail = " ".join(f"{k}={c}" for k, c in sorted(nz.items()))
        n_alloc = len(self.allocations)
        if n_alloc:
            detail = f"{detail} alloc={n_alloc}" if detail else f"alloc={n_alloc}"
        return f"HeapSummary({detail or 'empty'})"

    def to_dict(self) -> dict:
        return {
            "reads": [loc.to_dict() for loc in self.reads],
            "writes": [w.to_dict() for w in self.writes],
            "deletes": [loc.to_dict() for loc in self.deletes],
            "escapes": [loc.to_dict() for loc in self.escapes],
            "returns": [loc.to_dict() for loc in self.returns],
            "allocations": [obj.to_dict() for obj in self.allocations],
        }


class HeapSummaryBuilder:
    """Build fixed heap summaries from Python IR code bodies."""

    def __init__(
        self,
        effect_builder: HeapEffectBuilder,
        *,
        collection_mutator_names: frozenset[str] = frozenset(),
    ) -> None:
        self.effect_builder = effect_builder
        self.collection_mutator_names = collection_mutator_names

    def summarize(self, procedure: object) -> HeapSummary:
        code = getattr(procedure, "code", procedure)
        body = getattr(code, "ast", None)
        reads: list[HeapLocation] = []
        writes: list[HeapWrite] = []
        deletes: list[HeapLocation] = []
        escapes: list[HeapLocation] = []
        returns: list[HeapLocation] = []
        allocations: list[HeapObject] = []
        for operation in self._iter_operations(body):
            effect = self.effect_builder.operation_effect(
                procedure,
                operation,
                collection_mutator_names=self.collection_mutator_names,
            )
            reads.extend(effect.reads)
            writes.extend(effect.writes)
            escapes.extend(effect.escapes)
            returns.extend(effect.returns)
            allocations.extend(effect.allocations)
        deletes.extend(self._must_delete_locations(procedure, body))
        return HeapSummary(
            reads=tuple(dict.fromkeys(reads)),
            writes=tuple(dict.fromkeys(writes)),
            deletes=tuple(dict.fromkeys(deletes)),
            escapes=tuple(dict.fromkeys(escapes)),
            returns=tuple(dict.fromkeys(returns)),
            allocations=tuple(dict.fromkeys(allocations)),
        )

    def _must_delete_locations(
        self,
        procedure: object,
        node: object,
    ) -> tuple[HeapLocation, ...]:
        """Compute deletes present on every bounded normal/returning path."""
        exits = self._delete_exits(procedure, node, frozenset())
        completed = [deletes for kind, deletes in exits if kind in {"normal", "return"}]
        if not completed:
            return ()
        must = set(completed[0])
        for path in completed[1:]:
            must.intersection_update(path)
        return tuple(must)

    def _delete_exits(
        self,
        procedure: object,
        node: object,
        incoming: frozenset[HeapLocation],
    ) -> list[tuple[str, frozenset[HeapLocation]]]:
        if node is None or isinstance(node, py_ast.leafTypes):
            return [("normal", incoming)]
        if isinstance(node, py_ast.Suite):
            paths = [("normal", incoming)]
            for block in node.blocks:
                next_paths: list[tuple[str, frozenset[HeapLocation]]] = []
                for kind, deletes in paths:
                    if kind != "normal":
                        next_paths.append((kind, deletes))
                    else:
                        next_paths.extend(
                            self._delete_exits(procedure, block, deletes)
                        )
                paths = next_paths
            return paths
        if isinstance(node, py_ast.Switch):
            preamble = getattr(getattr(node, "condition", None), "preamble", None)
            prefixes = self._delete_exits(procedure, preamble, incoming)
            exits: list[tuple[str, frozenset[HeapLocation]]] = []
            for kind, deletes in prefixes:
                if kind != "normal":
                    exits.append((kind, deletes))
                    continue
                exits.extend(self._delete_exits(procedure, node.t, deletes))
                exits.extend(self._delete_exits(procedure, node.f, deletes))
            return exits
        if isinstance(node, py_ast.TypeSwitch):
            exits = [("normal", incoming)]
            for case in getattr(node, "cases", ()):
                exits.extend(self._delete_exits(procedure, case.body, incoming))
            return exits
        if isinstance(node, (py_ast.While, py_ast.For, py_ast.TryExceptFinally)):
            # These constructs need a richer path protocol.  An empty-delete
            # alternative keeps the summary sound until that protocol proves
            # a must-delete.
            return [("normal", incoming)]
        effect = self.effect_builder.operation_effect(
            procedure,
            node,
            collection_mutator_names=self.collection_mutator_names,
        )
        definite = self.effect_builder.definite_delete_locations(
            node,
            effect.deletes,
        )
        deletes = frozenset((*incoming, *definite))
        if isinstance(node, py_ast.Return):
            return [("return", deletes)]
        if isinstance(node, py_ast.Raise):
            return [("raise", deletes)]
        return [("normal", deletes)]

    def _iter_operations(self, node: object):
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        if isinstance(node, py_ast.Code):
            return
        if isinstance(node, py_ast.Suite):
            for block in node.blocks:
                yield from self._iter_operations(block)
            return
        if isinstance(node, py_ast.PythonASTNode):
            yield node
            if hasattr(node, "visitChildren"):
                children: list[object] = []
                node.visitChildren(children.append)
                for child in children:
                    yield from self._iter_operations(child)
