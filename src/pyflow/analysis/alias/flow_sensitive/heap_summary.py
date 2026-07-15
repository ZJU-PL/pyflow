"""Procedure-level heap summaries for IFDS heap effects."""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.language.python import ast as py_ast

from .model import HeapLocation, HeapObject, HeapWrite
from .heap_state import HeapState
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

    @classmethod
    def from_effects(cls, effects) -> "HeapSummary":
        reads: list[HeapLocation] = []
        writes: list[HeapWrite] = []
        deletes: list[HeapLocation] = []
        escapes: list[HeapLocation] = []
        returns: list[HeapLocation] = []
        allocations: list[HeapObject] = []
        for effect in effects:
            reads.extend(effect.reads)
            writes.extend(effect.writes)
            deletes.extend(effect.deletes)
            escapes.extend(effect.escapes)
            returns.extend(effect.returns)
            allocations.extend(effect.allocations)
        return cls(
            reads=tuple(dict.fromkeys(reads)),
            writes=tuple(dict.fromkeys(writes)),
            deletes=tuple(dict.fromkeys(deletes)),
            escapes=tuple(dict.fromkeys(escapes)),
            returns=tuple(dict.fromkeys(returns)),
            allocations=tuple(dict.fromkeys(allocations)),
        )

    def merge(self, other: "HeapSummary") -> "HeapSummary":
        return HeapSummary(
            reads=tuple(dict.fromkeys((*self.reads, *other.reads))),
            writes=tuple(dict.fromkeys((*self.writes, *other.writes))),
            deletes=tuple(dict.fromkeys((*self.deletes, *other.deletes))),
            escapes=tuple(dict.fromkeys((*self.escapes, *other.escapes))),
            returns=tuple(dict.fromkeys((*self.returns, *other.returns))),
            allocations=tuple(
                dict.fromkeys((*self.allocations, *other.allocations))
            ),
        )

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


@dataclass(frozen=True)
class ProcedureHeapSummary:
    """Outcome-sensitive summary produced by the standalone transfer engine."""

    normal_state: HeapState | None = None
    raise_state: HeapState | None = None
    returns: tuple[tuple[HeapLocation, ...], ...] = ()
    raises: tuple[HeapLocation, ...] = ()
    yields: tuple[HeapLocation, ...] = ()
    deletes: tuple[HeapLocation, ...] = ()
    param_returns: dict[int, frozenset[int]] = field(default_factory=dict)
    param_escapes: frozenset[int] = frozenset()
    effects: HeapSummary = field(default_factory=HeapSummary)
    precision_degradations: frozenset[str] = frozenset()

    def merge(self, other: "ProcedureHeapSummary") -> "ProcedureHeapSummary":
        def join_optional(left, right):
            if left is None:
                return right.copy() if right is not None else None
            if right is None:
                return left.copy()
            return left.join(right)

        count = max(len(self.returns), len(other.returns))
        returns = tuple(
            tuple(
                dict.fromkeys(
                    (
                        *(self.returns[index] if index < len(self.returns) else ()),
                        *(other.returns[index] if index < len(other.returns) else ()),
                    )
                )
            )
            for index in range(count)
        )
        return ProcedureHeapSummary(
            normal_state=join_optional(self.normal_state, other.normal_state),
            raise_state=join_optional(self.raise_state, other.raise_state),
            returns=returns,
            raises=tuple(dict.fromkeys((*self.raises, *other.raises))),
            yields=tuple(dict.fromkeys((*self.yields, *other.yields))),
            deletes=tuple(dict.fromkeys((*self.deletes, *other.deletes))),
            param_returns={
                index: frozenset(
                    (*self.param_returns.get(index, ()), *other.param_returns.get(index, ()))
                )
                for index in set(self.param_returns) | set(other.param_returns)
            },
            param_escapes=frozenset((*self.param_escapes, *other.param_escapes)),
            effects=self.effects.merge(other.effects),
            precision_degradations=frozenset(
                (*self.precision_degradations, *other.precision_degradations)
            ),
        )

    def to_dict(self) -> dict:
        return {
            "normal": self.normal_state is not None,
            "raises_normally": self.raise_state is not None,
            "deletes": [loc.to_dict() for loc in self.deletes],
            "returns": [
                [location.to_dict() for location in slot]
                for slot in self.returns
            ],
            "raises": [location.to_dict() for location in self.raises],
            "yields": [location.to_dict() for location in self.yields],
            "param_returns": {
                str(index): sorted(parameters)
                for index, parameters in self.param_returns.items()
            },
            "param_escapes": sorted(self.param_escapes),
            "effects": self.effects.to_dict(),
            "precision_degradations": sorted(self.precision_degradations),
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
            effect = self.effect_builder.operation_semantics(
                procedure,
                operation,
                collection_mutator_names=self.collection_mutator_names,
            ).effect
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
        effect = self.effect_builder.operation_semantics(
            procedure,
            node,
            collection_mutator_names=self.collection_mutator_names,
        ).effect
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
