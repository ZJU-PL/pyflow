"""Context-independent semantic facts for normalized IR operations."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable
import copy

from .ids import AllocationSiteId, CallSiteId, CodeId, NodeId, SymbolId, ValueId
from .storage import StorageLocation


@dataclass(frozen=True)
class ControlEffects:
    normal: bool = True
    raises: bool = False
    errors: bool = False
    yields: bool = False
    returns: bool = False
    breaks: bool = False
    continues: bool = False


@dataclass(frozen=True)
class CallSite:
    id: CallSiteId
    operation: NodeId
    callee: NodeId | None
    positional_arguments: tuple[NodeId, ...] = ()
    keyword_arguments: tuple[tuple[str, NodeId], ...] = ()
    positional_spreads: tuple[NodeId, ...] = ()
    keyword_spreads: tuple[NodeId, ...] = ()
    result_symbols: tuple[SymbolId, ...] = ()
    direct_target: CodeId | None = None
    symbolic_name: str | None = None


@dataclass(frozen=True)
class OperationSemantics:
    definitions: tuple[SymbolId | ValueId, ...] = ()
    uses: tuple[SymbolId | ValueId, ...] = ()
    reads: tuple[StorageLocation, ...] = ()
    writes: tuple[StorageLocation, ...] = ()
    allocations: tuple[AllocationSiteId, ...] = ()
    calls: tuple[CallSiteId, ...] = ()
    evaluation_order: tuple[NodeId, ...] = ()
    control: ControlEffects = ControlEffects()
    complete: bool = True
    diagnostics: tuple[str, ...] = ()


class IRSemantics:
    """Immutable-by-convention registry populated by the semantics pass."""

    def __init__(self, loader: Callable[[frozenset | None], None] | None = None) -> None:
        self._operations: dict[NodeId, OperationSemantics] = {}
        self._operations_by_code: dict[object, dict[NodeId, OperationSemantics]] = {}
        self._calls: dict[CallSiteId, CallSite] = {}
        self._calls_by_code: dict[object, set[CallSiteId]] = {}
        self._loader = loader
        self._ready = False
        self._dirty: set = set()
        self._loading = False
        self._load_lock = RLock()

    def _ensure_ready(self) -> None:
        if self._ready and not self._dirty:
            return
        if self._loader is None:
            return
        with self._load_lock:
            if self._ready and not self._dirty:
                return
            if self._loading:
                return
            self._loading = True
            try:
                if self._ready:
                    # Only the invalidation targets need rebuilding.  Taking
                    # the set first keeps invalidations raised *during* the
                    # rebuild marked for the next pass.
                    codes = frozenset(self._dirty)
                    self._dirty.clear()
                    self._loader(codes)
                else:
                    self._loader(None)
            finally:
                self._loading = False

    def ensure_ready(self) -> None:
        """Populate the table, rebuilding only codes invalidated since the last build."""
        self._ensure_ready()

    def invalidate(self, code_id=None) -> None:
        """Retire semantics for *code_id*, or for the whole catalog when omitted."""
        if not self._ready:
            return
        if code_id is None:
            self._ready = False
            self._dirty.clear()
        else:
            self._dirty.add(code_id)

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def dirty_codes(self) -> frozenset:
        return frozenset(self._dirty)

    def discard_codes(self, codes) -> None:
        """Drop the records belonging to *codes* so they can be rebuilt alone."""
        codes = frozenset(codes)
        if not codes:
            return
        for code_id in codes:
            for node_id in tuple(self._operations_by_code.pop(code_id, {})):
                del self._operations[node_id]
            for call_id in tuple(self._calls_by_code.pop(code_id, ())):
                del self._calls[call_id]

    def mark_ready(self, codes=None) -> None:
        self._ready = True
        if codes is None:
            self._dirty.clear()
        else:
            self._dirty.difference_update(codes)

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state["_load_lock"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._load_lock = RLock()

    def __deepcopy__(self, memo: dict[int, Any]) -> "IRSemantics":
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            if k == "_load_lock":
                setattr(result, k, RLock())
            else:
                setattr(result, k, copy.deepcopy(v, memo))
        return result

    def set_operation(self, node: NodeId, semantics: OperationSemantics) -> None:
        self._operations[node] = semantics
        self._operations_by_code.setdefault(node.code, {})[node] = semantics

    def clear(self) -> None:
        self._operations.clear()
        self._operations_by_code.clear()
        self._calls.clear()
        self._calls_by_code.clear()
        self._ready = False
        self._dirty.clear()

    def operation(self, node: NodeId) -> OperationSemantics:
        self._ensure_ready()
        return self._operations[node]

    def get_operation(self, node: NodeId) -> OperationSemantics | None:
        self._ensure_ready()
        return self._operations.get(node)

    def register_call(self, call: CallSite) -> None:
        self._calls[call.id] = call
        self._calls_by_code.setdefault(call.id.node.code, set()).add(call.id)

    def call_site(self, call: CallSiteId) -> CallSite:
        self._ensure_ready()
        return self._calls[call]

    def calls_for(self, node: NodeId) -> tuple[CallSite, ...]:
        semantics = self.operation(node)
        return tuple(self._calls[call] for call in semantics.calls)

    def items(self):
        self._ensure_ready()
        return self._operations.items()
