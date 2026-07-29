"""Generic monotone worklist solver for AST dataflow control-flow graphs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Generic, Hashable, Mapping, TypeVar

from ..domain import (
    AnalysisUncertainty,
    PrecisionLevel,
    TaintFact,
    TaintState,
)

Node = TypeVar("Node", bound=Hashable)


class EdgeKind(str, Enum):
    NORMAL = "normal"
    TRUE = "true"
    FALSE = "false"
    EXCEPTION = "exception"
    BREAK = "break"
    CONTINUE = "continue"
    FINALLY = "finally"


@dataclass(frozen=True)
class CFGEdge(Generic[Node]):
    source: Node
    target: Node
    kind: EdgeKind = EdgeKind.NORMAL


@dataclass(frozen=True)
class ControlFlowGraph(Generic[Node]):
    entry: Node
    nodes: frozenset[Node]
    edges: tuple[CFGEdge[Node], ...]

    def __post_init__(self) -> None:
        if self.entry not in self.nodes:
            raise ValueError("CFG entry must be a member of nodes")
        if any(
            edge.source not in self.nodes or edge.target not in self.nodes
            for edge in self.edges
        ):
            raise ValueError("CFG edges must connect declared nodes")

    def outgoing(self, node: Node) -> tuple[CFGEdge[Node], ...]:
        return tuple(edge for edge in self.edges if edge.source == node)


@dataclass(frozen=True)
class FlowOutcome:
    state: TaintState
    values: frozenset[TaintFact] = frozenset()

    def join(self, other: "FlowOutcome") -> "FlowOutcome":
        return FlowOutcome(self.state.join(other.state), self.values | other.values)


@dataclass(frozen=True)
class TransferResult(Generic[Node]):
    outgoing: tuple[tuple[CFGEdge[Node], TaintState], ...] = ()
    returned: FlowOutcome | None = None
    raised: FlowOutcome | None = None
    yielded: FlowOutcome | None = None
    events: frozenset[object] = frozenset()

    @classmethod
    def identity(
        cls, edges: tuple[CFGEdge[Node], ...], state: TaintState
    ) -> "TransferResult[Node]":
        return cls(tuple((edge, state) for edge in edges))


Transfer = Callable[[Node, TaintState, tuple[CFGEdge[Node], ...]], TransferResult[Node]]


@dataclass(frozen=True)
class SolverOptions:
    max_steps: int = 100_000


@dataclass(frozen=True)
class CFGSolverResult(Generic[Node]):
    in_states: Mapping[Node, TaintState]
    edge_states: Mapping[CFGEdge[Node], TaintState]
    returned: FlowOutcome | None
    raised: FlowOutcome | None
    yielded: FlowOutcome | None
    events: frozenset[object]
    status: str
    steps: int
    diagnostics: tuple[AnalysisUncertainty, ...] = ()

    @property
    def is_complete(self) -> bool:
        return self.status == "complete"


class MonotoneCFGDataflowSolver(Generic[Node]):
    """Least-fixed-point solver for finite monotone taint transfer functions."""

    def __init__(self, options: SolverOptions | None = None) -> None:
        self.options = options or SolverOptions()

    def solve(
        self,
        graph: ControlFlowGraph[Node],
        initial_state: TaintState,
        transfer: Transfer[Node],
    ) -> CFGSolverResult[Node]:
        bottom = TaintState.bottom(
            max_provenance_edges=initial_state.max_provenance_edges,
            max_access_path=initial_state.max_access_path,
        )
        in_states: dict[Node, TaintState] = {node: bottom for node in graph.nodes}
        in_states[graph.entry] = initial_state
        edge_states: dict[CFGEdge[Node], TaintState] = {
            edge: bottom for edge in graph.edges
        }
        outgoing_lists: dict[Node, list[CFGEdge[Node]]] = {
            node: [] for node in graph.nodes
        }
        for edge in graph.edges:
            outgoing_lists[edge.source].append(edge)
        outgoing_by_node = {
            node: tuple(edges) for node, edges in outgoing_lists.items()
        }
        returned: FlowOutcome | None = None
        raised: FlowOutcome | None = None
        yielded: FlowOutcome | None = None
        events: set[object] = set()
        queued = {graph.entry}
        worklist = deque([graph.entry])
        steps = 0

        while worklist and steps < self.options.max_steps:
            node = worklist.popleft()
            queued.discard(node)
            steps += 1
            state = in_states[node]
            outgoing_edges = outgoing_by_node[node]
            result = transfer(node, state, outgoing_edges)
            returned = self._join_outcome(returned, result.returned)
            raised = self._join_outcome(raised, result.raised)
            yielded = self._join_outcome(yielded, result.yielded)
            events.update(result.events)

            supplied = {edge for edge, _state in result.outgoing}
            declared = set(outgoing_edges)
            if not supplied <= declared:
                raise ValueError("transfer emitted a state for a non-successor edge")

            for edge, outgoing in result.outgoing:
                previous_edge = edge_states[edge]
                if outgoing.leq(previous_edge):
                    continue
                edge_states[edge] = previous_edge.join(outgoing)
                target_state = in_states[edge.target].join(edge_states[edge])
                if target_state != in_states[edge.target]:
                    in_states[edge.target] = target_state
                    if edge.target not in queued:
                        queued.add(edge.target)
                        worklist.append(edge.target)

        diagnostics: tuple[AnalysisUncertainty, ...] = ()
        status = "complete"
        if worklist:
            status = "partial"
            diagnostics = (
                AnalysisUncertainty(
                    code="ast-dataflow-step-limit",
                    message=(
                        "CFG fixed point did not converge within "
                        f"{self.options.max_steps} transfer steps"
                    ),
                    level=PrecisionLevel.UNSUPPORTED,
                ),
            )
        return CFGSolverResult(
            in_states=in_states,
            edge_states=edge_states,
            returned=returned,
            raised=raised,
            yielded=yielded,
            events=frozenset(events),
            status=status,
            steps=steps,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _join_outcome(
        current: FlowOutcome | None, incoming: FlowOutcome | None
    ) -> FlowOutcome | None:
        if incoming is None:
            return current
        if current is None:
            return incoming
        return current.join(incoming)
