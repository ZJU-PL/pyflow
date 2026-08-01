"""Context-independent semantic facts for normalized IR operations."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable

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

    def __init__(self, loader: Callable[[], None] | None = None) -> None:
        self._operations: dict[NodeId, OperationSemantics] = {}
        self._calls: dict[CallSiteId, CallSite] = {}
        self._loader = loader
        self._ready = False
        self._loading = False
        self._load_lock = RLock()

    def _ensure_ready(self) -> None:
        if self._ready or self._loader is None:
            return
        with self._load_lock:
            if self._ready or self._loading:
                return
            self._loading = True
            try:
                self._loader()
            finally:
                self._loading = False

    def invalidate(self) -> None:
        self._ready = False

    @property
    def ready(self) -> bool:
        return self._ready

    def mark_ready(self) -> None:
        self._ready = True

    def set_operation(self, node: NodeId, semantics: OperationSemantics) -> None:
        self._operations[node] = semantics

    def clear(self) -> None:
        self._operations.clear()
        self._calls.clear()
        self._ready = False

    def operation(self, node: NodeId) -> OperationSemantics:
        self._ensure_ready()
        return self._operations[node]

    def get_operation(self, node: NodeId) -> OperationSemantics | None:
        self._ensure_ready()
        return self._operations.get(node)

    def register_call(self, call: CallSite) -> None:
        self._calls[call.id] = call

    def call_site(self, call: CallSiteId) -> CallSite:
        self._ensure_ready()
        return self._calls[call]

    def calls_for(self, node: NodeId) -> tuple[CallSite, ...]:
        semantics = self.operation(node)
        return tuple(self._calls[call] for call in semantics.calls)

    def items(self):
        self._ensure_ready()
        return self._operations.items()
