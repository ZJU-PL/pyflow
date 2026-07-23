"""Reusable interprocedural supergraph for IFDS/IDE analyses."""

from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict, Dict, FrozenSet, Generic, Hashable, Iterable, TypeVar

ProcT = TypeVar("ProcT", bound=Hashable)
NodeT = TypeVar("NodeT", bound=Hashable)


class SupergraphError(ValueError):
    """Raised when the supergraph is malformed."""


class Supergraph(Generic[ProcT, NodeT]):
    """
    Explicit interprocedural supergraph.

    Procedures are registered up-front with one entry node and any number of
    exit nodes. Call sites then reference callees and their local return sites.
    The solver only depends on the queries exposed here, so adapters can be
    built from CFGs, IR graphs, or synthetic tests.
    """

    def __init__(self) -> None:
        self._procedure_ids: Dict[ProcT, int] = {}
        self._node_ids: Dict[NodeT, int] = {}
        self._entries: Dict[ProcT, NodeT] = {}
        self._exits: DefaultDict[ProcT, set[NodeT]] = defaultdict(set)
        self._nodes_by_proc: DefaultDict[ProcT, set[NodeT]] = defaultdict(set)
        self._node_to_proc: Dict[NodeT, ProcT] = {}
        self._normal_succs: DefaultDict[NodeT, set[NodeT]] = defaultdict(set)
        self._callees_by_call: DefaultDict[NodeT, set[ProcT]] = defaultdict(set)
        self._return_sites_by_call: DefaultDict[NodeT, set[NodeT]] = defaultdict(set)
        self._call_to_return_succs: DefaultDict[NodeT, set[NodeT]] = defaultdict(set)
        self._callers_by_proc: DefaultDict[ProcT, set[NodeT]] = defaultdict(set)

    def add_procedure(
        self, procedure: ProcT, entry: NodeT, exits: Iterable[NodeT] = ()
    ) -> None:
        """Register a new procedure and its entry/exit nodes."""
        if procedure in self._entries:
            raise SupergraphError(f"Procedure {procedure!r} is already registered")
        self._procedure_ids[procedure] = len(self._procedure_ids)
        self._entries[procedure] = entry
        self.add_node(procedure, entry)
        for exit_node in exits:
            self.add_exit(procedure, exit_node)

    def add_node(self, procedure: ProcT, node: NodeT) -> None:
        """Attach a node to a procedure."""
        if procedure not in self._entries:
            raise SupergraphError(f"Unknown procedure {procedure!r}")
        existing = self._node_to_proc.get(node)
        if existing is not None and existing != procedure:
            raise SupergraphError(
                f"Node {node!r} is already owned by procedure {existing!r}"
            )
        self._node_to_proc[node] = procedure
        if node not in self._node_ids:
            self._node_ids[node] = len(self._node_ids)
        self._nodes_by_proc[procedure].add(node)

    def add_exit(self, procedure: ProcT, node: NodeT) -> None:
        """Mark a node as an exit of a procedure."""
        self.add_node(procedure, node)
        self._exits[procedure].add(node)

    def add_normal_edge(self, source: NodeT, target: NodeT) -> None:
        """Add an intraprocedural edge."""
        self._require_known_node(source)
        self._require_known_node(target)
        if self.procedure_of(source) != self.procedure_of(target):
            raise SupergraphError("Normal edges must remain inside a single procedure")
        self._normal_succs[source].add(target)

    def add_call_edge(
        self, call_node: NodeT, callee: ProcT, return_site: NodeT | None = None
    ) -> None:
        """
        Add a call from ``call_node`` to ``callee``.

        If ``return_site`` is provided the call site is also wired to that local
        continuation and receives a synthetic call-to-return edge.
        """
        self._require_known_node(call_node)
        if callee not in self._entries:
            raise SupergraphError(f"Unknown callee procedure {callee!r}")
        self._callees_by_call[call_node].add(callee)
        self._callers_by_proc[callee].add(call_node)
        if return_site is not None:
            self.add_return_site(call_node, return_site)

    def add_return_site(self, call_node: NodeT, return_site: NodeT) -> None:
        """Register a return site for a call and add the bypass edge."""
        self._require_known_node(call_node)
        self._require_known_node(return_site)
        if self.procedure_of(call_node) != self.procedure_of(return_site):
            raise SupergraphError(
                "Call nodes and return sites must belong to the same procedure"
            )
        self._return_sites_by_call[call_node].add(return_site)
        self._call_to_return_succs[call_node].add(return_site)

    def procedures(self) -> FrozenSet[ProcT]:
        return frozenset(self._entries)

    def ordered_procedures(self) -> tuple[ProcT, ...]:
        """Return procedures in stable registration order."""
        return tuple(sorted(self._entries, key=self.procedure_id))

    def procedure_id(self, procedure: ProcT) -> int:
        """Return the compact, stable ID assigned at registration time."""
        return self._procedure_ids[procedure]

    def node_id(self, node: NodeT) -> int:
        """Return the compact, stable ID assigned at registration time."""
        return self._node_ids[node]

    def entry_of(self, procedure: ProcT) -> NodeT:
        return self._entries[procedure]

    def exits_of(self, procedure: ProcT) -> FrozenSet[NodeT]:
        return frozenset(self._exits.get(procedure, ()))

    def ordered_exits_of(self, procedure: ProcT) -> tuple[NodeT, ...]:
        return tuple(sorted(self._exits.get(procedure, ()), key=self.node_id))

    def nodes_of(self, procedure: ProcT) -> FrozenSet[NodeT]:
        return frozenset(self._nodes_by_proc.get(procedure, ()))

    def ordered_nodes_of(self, procedure: ProcT) -> tuple[NodeT, ...]:
        return tuple(sorted(self._nodes_by_proc.get(procedure, ()), key=self.node_id))

    def nodes(self) -> FrozenSet[NodeT]:
        return frozenset(self._node_to_proc)

    def ordered_nodes(self) -> tuple[NodeT, ...]:
        return tuple(sorted(self._node_to_proc, key=self.node_id))

    def procedure_of(self, node: NodeT) -> ProcT:
        return self._node_to_proc[node]

    def normal_successors(self, node: NodeT) -> FrozenSet[NodeT]:
        return frozenset(self._normal_succs.get(node, ()))

    def ordered_normal_successors(self, node: NodeT) -> tuple[NodeT, ...]:
        return tuple(sorted(self._normal_succs.get(node, ()), key=self.node_id))

    def callees_of_call_at(self, node: NodeT) -> FrozenSet[ProcT]:
        return frozenset(self._callees_by_call.get(node, ()))

    def ordered_callees_of_call_at(self, node: NodeT) -> tuple[ProcT, ...]:
        return tuple(sorted(self._callees_by_call.get(node, ()), key=self.procedure_id))

    def callers_of(self, procedure: ProcT) -> FrozenSet[NodeT]:
        return frozenset(self._callers_by_proc.get(procedure, ()))

    def ordered_callers_of(self, procedure: ProcT) -> tuple[NodeT, ...]:
        return tuple(sorted(self._callers_by_proc.get(procedure, ()), key=self.node_id))

    def return_sites_of_call_at(self, node: NodeT) -> FrozenSet[NodeT]:
        return frozenset(self._return_sites_by_call.get(node, ()))

    def ordered_return_sites_of_call_at(self, node: NodeT) -> tuple[NodeT, ...]:
        return tuple(sorted(self._return_sites_by_call.get(node, ()), key=self.node_id))

    def call_to_return_successors(self, node: NodeT) -> FrozenSet[NodeT]:
        return frozenset(self._call_to_return_succs.get(node, ()))

    def ordered_call_to_return_successors(self, node: NodeT) -> tuple[NodeT, ...]:
        return tuple(sorted(self._call_to_return_succs.get(node, ()), key=self.node_id))

    def is_call_node(self, node: NodeT) -> bool:
        return node in self._callees_by_call

    def is_exit_node(self, node: NodeT) -> bool:
        procedure = self._node_to_proc.get(node)
        if procedure is None:
            return False
        return node in self._exits.get(procedure, ())

    def _require_known_node(self, node: NodeT) -> None:
        if node not in self._node_to_proc:
            raise SupergraphError(f"Unknown node {node!r}")
