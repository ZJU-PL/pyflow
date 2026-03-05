"""IFDS and IDE solvers over the reusable interprocedural supergraph."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Dict, FrozenSet, Generic, Hashable, Iterable, TypeVar

from .problem import (
    EdgeFunction,
    IDEProblem,
    IFDSProblem,
    IdentityEdgeFunction,
)
from .supergraph import NodeT, ProcT


FactT = TypeVar("FactT", bound=Hashable)
ValueT = TypeVar("ValueT")


class SolverLimitExceeded(RuntimeError):
    """Raised when solver propagation exceeds a configured safety cap."""


@dataclass(frozen=True)
class PathEdge(Generic[NodeT, FactT]):
    """A source-relative exploded-graph edge."""

    source_node: NodeT
    source_fact: FactT
    node: NodeT
    fact: FactT


@dataclass(frozen=True)
class PropagationTrace(Generic[NodeT, FactT]):
    """One propagation step recorded for debugging/explanation."""

    output_edge: PathEdge[NodeT, FactT]
    kind: str
    predecessor: PathEdge[NodeT, FactT] | None = None
    note: str | None = None


@dataclass(frozen=True)
class SolverStatistics:
    """Lightweight solver statistics."""

    processed_path_edges: int = 0
    propagated_path_edges: int = 0
    normal_flow_steps: int = 0
    call_flow_steps: int = 0
    return_flow_steps: int = 0
    call_to_return_steps: int = 0
    incoming_records: int = 0
    summary_updates: int = 0


@dataclass(frozen=True)
class _IncomingRecord(Generic[NodeT, FactT]):
    caller_source_node: NodeT
    caller_source_fact: FactT
    call_node: NodeT
    call_fact: FactT
    return_site: NodeT


@dataclass(frozen=True)
class _IDEIncomingRecord(Generic[NodeT, FactT, ValueT]):
    caller_source_node: NodeT
    caller_source_fact: FactT
    call_node: NodeT
    call_fact: FactT
    return_site: NodeT
    call_jump: EdgeFunction[ValueT]


class IFDSResult(Generic[NodeT, FactT]):
    """Reachability result for an IFDS problem."""

    def __init__(
        self,
        reached: Dict[NodeT, set[FactT]],
        path_edges: FrozenSet[PathEdge[NodeT, FactT]],
        statistics: SolverStatistics,
        traces: Dict[PathEdge[NodeT, FactT], tuple[PropagationTrace[NodeT, FactT], ...]],
        incoming: Dict[tuple[NodeT, FactT], tuple[_IncomingRecord[NodeT, FactT], ...]],
        end_summary: Dict[tuple[NodeT, FactT, NodeT], FrozenSet[FactT]],
    ) -> None:
        self._reached = reached
        self._path_edges = path_edges
        self.statistics = statistics
        self._traces = traces
        self._incoming = incoming
        self._end_summary = end_summary

    def facts_at(self, node: NodeT) -> FrozenSet[FactT]:
        return frozenset(self._reached.get(node, ()))

    def is_reached(self, node: NodeT, fact: FactT) -> bool:
        return fact in self._reached.get(node, ())

    def path_edges(self) -> FrozenSet[PathEdge[NodeT, FactT]]:
        return self._path_edges

    def traces_for(self, path_edge: PathEdge[NodeT, FactT]):
        return self._traces.get(path_edge, ())

    def explain_fact(self, node: NodeT, fact: FactT):
        return {
            edge: traces
            for edge in self._path_edges
            for traces in (self._traces.get(edge, ()),)
            if edge.node == node and edge.fact == fact
            if traces
        }

    def incoming_records(self, start_node: NodeT, start_fact: FactT):
        return self._incoming.get((start_node, start_fact), ())

    def end_summaries(self, start_node: NodeT, start_fact: FactT, exit_node: NodeT):
        return self._end_summary.get((start_node, start_fact, exit_node), frozenset())


class IDEResult(Generic[NodeT, FactT, ValueT]):
    """Value result for an IDE problem."""

    def __init__(
        self,
        values: Dict[tuple[NodeT, FactT], ValueT],
        reached: Dict[NodeT, set[FactT]],
        jump_functions: Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]],
        statistics: SolverStatistics,
        traces: Dict[PathEdge[NodeT, FactT], tuple[PropagationTrace[NodeT, FactT], ...]],
        incoming: Dict[
            tuple[NodeT, FactT], tuple[_IDEIncomingRecord[NodeT, FactT, ValueT], ...]
        ],
        end_summary: Dict[
            tuple[NodeT, FactT, NodeT, FactT], EdgeFunction[ValueT]
        ],
    ) -> None:
        self._values = values
        self._reached = reached
        self._jump_functions = jump_functions
        self.statistics = statistics
        self._traces = traces
        self._incoming = incoming
        self._end_summary = end_summary

    def facts_at(self, node: NodeT) -> FrozenSet[FactT]:
        return frozenset(self._reached.get(node, ()))

    def value_at(self, node: NodeT, fact: FactT) -> ValueT:
        return self._values[(node, fact)]

    def jump_functions(self) -> Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]]:
        return dict(self._jump_functions)

    def traces_for(self, path_edge: PathEdge[NodeT, FactT]):
        return self._traces.get(path_edge, ())

    def explain_fact(self, node: NodeT, fact: FactT):
        return {
            edge: traces
            for edge in self._jump_functions
            for traces in (self._traces.get(edge, ()),)
            if edge.node == node and edge.fact == fact
            if traces
        }

    def incoming_records(self, start_node: NodeT, start_fact: FactT):
        return self._incoming.get((start_node, start_fact), ())

    def end_summaries(self):
        return dict(self._end_summary)


class IFDSSolver(Generic[ProcT, NodeT, FactT]):
    """Classic tabulation-style IFDS solver."""

    def __init__(
        self,
        *,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
    ) -> None:
        self.record_traces = record_traces
        self.max_propagated_path_edges = max_propagated_path_edges

    def solve(self, problem: IFDSProblem[ProcT, NodeT, FactT]) -> IFDSResult[NodeT, FactT]:
        supergraph = problem.supergraph
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        seen: set[PathEdge[NodeT, FactT]] = set()
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[
            tuple[NodeT, FactT], set[_IncomingRecord[NodeT, FactT]]
        ] = defaultdict(set)
        end_summary: DefaultDict[
            tuple[NodeT, FactT, NodeT], set[FactT]
        ] = defaultdict(set)
        traces: DefaultDict[
            PathEdge[NodeT, FactT], list[PropagationTrace[NodeT, FactT]]
        ] = defaultdict(list)
        stats = {
            "processed_path_edges": 0,
            "propagated_path_edges": 0,
            "normal_flow_steps": 0,
            "call_flow_steps": 0,
            "return_flow_steps": 0,
            "call_to_return_steps": 0,
            "incoming_records": 0,
            "summary_updates": 0,
        }

        def propagate(
            path_edge: PathEdge[NodeT, FactT],
            *,
            kind: str,
            predecessor: PathEdge[NodeT, FactT] | None = None,
            note: str | None = None,
        ) -> None:
            if path_edge in seen:
                return
            if self.record_traces:
                trace = PropagationTrace(path_edge, kind, predecessor, note)
                traces[path_edge].append(trace)
            seen.add(path_edge)
            reached[path_edge.node].add(path_edge.fact)
            stats["propagated_path_edges"] += 1
            if (
                self.max_propagated_path_edges is not None
                and stats["propagated_path_edges"] > self.max_propagated_path_edges
            ):
                raise SolverLimitExceeded(
                    "IFDS propagation exceeded max_propagated_path_edges="
                    f"{self.max_propagated_path_edges}"
                )
            queue.append(path_edge)

        for node, facts in problem.initial_seeds().items():
            for fact in facts:
                propagate(PathEdge(node, fact, node, fact), kind="seed")

        while queue:
            edge = queue.popleft()
            stats["processed_path_edges"] += 1
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact

            if supergraph.is_call_node(node):
                for return_site in supergraph.call_to_return_successors(node):
                    stats["call_to_return_steps"] += 1
                    for out_fact in problem.call_to_return_flow(node, return_site, fact):
                        propagate(
                            PathEdge(
                                source_node, source_fact, return_site, out_fact
                            ),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {return_site!r}",
                        )

                for callee in supergraph.callees_of_call_at(node):
                    start = supergraph.entry_of(callee)
                    stats["call_flow_steps"] += 1
                    for start_fact in problem.call_flow(node, callee, fact):
                        incoming_key = (start, start_fact)
                        for return_site in supergraph.return_sites_of_call_at(node):
                            incoming_record = _IncomingRecord(
                                source_node,
                                source_fact,
                                node,
                                fact,
                                return_site,
                            )
                            if incoming_record not in incoming[incoming_key]:
                                incoming[incoming_key].add(incoming_record)
                                stats["incoming_records"] += 1
                                for exit_node in supergraph.exits_of(callee):
                                    for exit_fact in end_summary.get(
                                        (start, start_fact, exit_node), ()
                                    ):
                                        stats["return_flow_steps"] += 1
                                        for return_fact in problem.return_flow(
                                            node,
                                            callee,
                                            exit_node,
                                            return_site,
                                            fact,
                                            exit_fact,
                                        ):
                                            propagate(
                                                PathEdge(
                                                    source_node,
                                                    source_fact,
                                                    return_site,
                                                    return_fact,
                                                ),
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {return_site!r}",
                                            )

                        propagate(
                            PathEdge(start, start_fact, start, start_fact),
                            kind="call_flow",
                            predecessor=edge,
                            note=f"{node!r} -> {callee!r}",
                        )

            if supergraph.is_exit_node(node):
                summary_key = (source_node, source_fact, node)
                if fact not in end_summary[summary_key]:
                    end_summary[summary_key].add(fact)
                    stats["summary_updates"] += 1
                    callee = supergraph.procedure_of(node)
                    for incoming_record in incoming.get((source_node, source_fact), ()):
                        stats["return_flow_steps"] += 1
                        for return_fact in problem.return_flow(
                            incoming_record.call_node,
                            callee,
                            node,
                            incoming_record.return_site,
                            incoming_record.call_fact,
                            fact,
                        ):
                            propagate(
                                PathEdge(
                                    incoming_record.caller_source_node,
                                    incoming_record.caller_source_fact,
                                    incoming_record.return_site,
                                    return_fact,
                                ),
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.return_site!r}",
                            )

            for successor in supergraph.normal_successors(node):
                stats["normal_flow_steps"] += 1
                for out_fact in problem.normal_flow(node, successor, fact):
                    propagate(
                        PathEdge(source_node, source_fact, successor, out_fact),
                        kind="normal_flow",
                        predecessor=edge,
                        note=f"{node!r} -> {successor!r}",
                    )

        return IFDSResult(
            dict(reached),
            frozenset(seen),
            SolverStatistics(**stats),
            {edge: tuple(records) for edge, records in traces.items()},
            {key: tuple(value) for key, value in incoming.items()},
            {key: frozenset(value) for key, value in end_summary.items()},
        )


class IDESolver(Generic[ProcT, NodeT, FactT, ValueT]):
    """Jump-function IDE solver keyed by source-relative path edges."""

    def __init__(
        self,
        *,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
    ) -> None:
        self.record_traces = record_traces
        self.max_propagated_path_edges = max_propagated_path_edges

    def solve(self, problem: IDEProblem[ProcT, NodeT, FactT, ValueT]) -> IDEResult[NodeT, FactT, ValueT]:
        supergraph = problem.supergraph
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        jump_functions: Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]] = {}
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[
            tuple[NodeT, FactT], set[_IDEIncomingRecord[NodeT, FactT, ValueT]]
        ] = defaultdict(set)
        end_summary: Dict[
            tuple[NodeT, FactT, NodeT, FactT], EdgeFunction[ValueT]
        ] = {}
        traces: DefaultDict[
            PathEdge[NodeT, FactT], list[PropagationTrace[NodeT, FactT]]
        ] = defaultdict(list)
        stats = {
            "processed_path_edges": 0,
            "propagated_path_edges": 0,
            "normal_flow_steps": 0,
            "call_flow_steps": 0,
            "return_flow_steps": 0,
            "call_to_return_steps": 0,
            "incoming_records": 0,
            "summary_updates": 0,
        }
        identity = IdentityEdgeFunction[ValueT]()
        seed_values = dict(problem.initial_seed_values())

        def join_edge_functions(
            left: EdgeFunction[ValueT], right: EdgeFunction[ValueT]
        ) -> EdgeFunction[ValueT]:
            return left.join(right, problem.join_values)

        def propagate(
            path_edge: PathEdge[NodeT, FactT],
            jump: EdgeFunction[ValueT],
            *,
            kind: str,
            predecessor: PathEdge[NodeT, FactT] | None = None,
            note: str | None = None,
        ) -> None:
            current = jump_functions.get(path_edge)
            if current is None:
                if self.record_traces:
                    traces[path_edge].append(
                        PropagationTrace(path_edge, kind, predecessor, note)
                    )
                jump_functions[path_edge] = jump
                reached[path_edge.node].add(path_edge.fact)
                stats["propagated_path_edges"] += 1
                if (
                    self.max_propagated_path_edges is not None
                    and stats["propagated_path_edges"] > self.max_propagated_path_edges
                ):
                    raise SolverLimitExceeded(
                        "IDE propagation exceeded max_propagated_path_edges="
                        f"{self.max_propagated_path_edges}"
                    )
                queue.append(path_edge)
                return
            joined = join_edge_functions(current, jump)
            if joined != current:
                if self.record_traces:
                    traces[path_edge].append(
                        PropagationTrace(path_edge, kind, predecessor, note)
                    )
                jump_functions[path_edge] = joined
                reached[path_edge.node].add(path_edge.fact)
                stats["propagated_path_edges"] += 1
                if (
                    self.max_propagated_path_edges is not None
                    and stats["propagated_path_edges"] > self.max_propagated_path_edges
                ):
                    raise SolverLimitExceeded(
                        "IDE propagation exceeded max_propagated_path_edges="
                        f"{self.max_propagated_path_edges}"
                    )
                queue.append(path_edge)

        for seed, value in seed_values.items():
            node, fact = seed
            _ = value
            propagate(PathEdge(node, fact, node, fact), identity, kind="seed")

        while queue:
            edge = queue.popleft()
            stats["processed_path_edges"] += 1
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact
            current_jump = jump_functions[edge]

            if supergraph.is_call_node(node):
                for return_site in supergraph.call_to_return_successors(node):
                    stats["call_to_return_steps"] += 1
                    for transition in problem.call_to_return_flow(node, return_site, fact):
                        propagate(
                            PathEdge(
                                source_node,
                                source_fact,
                                return_site,
                                transition.fact,
                            ),
                            transition.edge_function.compose(current_jump),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {return_site!r}",
                        )

                for callee in supergraph.callees_of_call_at(node):
                    start = supergraph.entry_of(callee)
                    stats["call_flow_steps"] += 1
                    for transition in problem.call_flow(node, callee, fact):
                        call_jump = transition.edge_function.compose(current_jump)
                        incoming_key = (start, transition.fact)
                        for return_site in supergraph.return_sites_of_call_at(node):
                            incoming_record = _IDEIncomingRecord(
                                source_node,
                                source_fact,
                                node,
                                fact,
                                return_site,
                                call_jump,
                            )
                            if incoming_record not in incoming[incoming_key]:
                                incoming[incoming_key].add(incoming_record)
                                stats["incoming_records"] += 1
                                for exit_node in supergraph.exits_of(callee):
                                    for exit_fact in reached.get(exit_node, ()):
                                        summary = end_summary.get(
                                            (start, transition.fact, exit_node, exit_fact)
                                        )
                                        if summary is None:
                                            continue
                                        for return_transition in problem.return_flow(
                                            node,
                                            callee,
                                            exit_node,
                                            return_site,
                                            fact,
                                            exit_fact,
                                        ):
                                            combined = (
                                                return_transition.edge_function.compose(
                                                    summary
                                                ).compose(call_jump)
                                            )
                                            propagate(
                                                PathEdge(
                                                    source_node,
                                                    source_fact,
                                                    return_site,
                                                    return_transition.fact,
                                                ),
                                                combined,
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {return_site!r}",
                                            )

                        propagate(
                            PathEdge(start, transition.fact, start, transition.fact),
                            identity,
                            kind="call_flow",
                            predecessor=edge,
                            note=f"{node!r} -> {callee!r}",
                        )

            if supergraph.is_exit_node(node):
                summary_key = (source_node, source_fact, node, fact)
                current_summary = end_summary.get(summary_key)
                if current_summary is None:
                    end_summary[summary_key] = current_jump
                    summary_changed = True
                else:
                    joined_summary = join_edge_functions(current_summary, current_jump)
                    summary_changed = joined_summary != current_summary
                    if summary_changed:
                        end_summary[summary_key] = joined_summary
                if summary_changed:
                    stats["summary_updates"] += 1
                    callee = supergraph.procedure_of(node)
                    summary = end_summary[summary_key]
                    for incoming_record in incoming.get((source_node, source_fact), ()):
                        stats["return_flow_steps"] += 1
                        for return_transition in problem.return_flow(
                            incoming_record.call_node,
                            callee,
                            node,
                            incoming_record.return_site,
                            incoming_record.call_fact,
                            fact,
                        ):
                            combined = (
                                return_transition.edge_function.compose(summary).compose(
                                    incoming_record.call_jump
                                )
                            )
                            propagate(
                                PathEdge(
                                    incoming_record.caller_source_node,
                                    incoming_record.caller_source_fact,
                                    incoming_record.return_site,
                                    return_transition.fact,
                                ),
                                combined,
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.return_site!r}",
                            )

            for successor in supergraph.normal_successors(node):
                stats["normal_flow_steps"] += 1
                for transition in problem.normal_flow(node, successor, fact):
                    propagate(
                        PathEdge(source_node, source_fact, successor, transition.fact),
                        transition.edge_function.compose(current_jump),
                        kind="normal_flow",
                        predecessor=edge,
                        note=f"{node!r} -> {successor!r}",
                    )

        values: Dict[tuple[NodeT, FactT], ValueT] = {}
        source_values: Dict[tuple[NodeT, FactT], ValueT] = {}

        source_keys: set[tuple[NodeT, FactT]] = set(seed_values)
        source_keys.update((edge.source_node, edge.source_fact) for edge in jump_functions)
        source_keys.update(incoming)
        for incoming_records in incoming.values():
            source_keys.update(
                (record.caller_source_node, record.caller_source_fact)
                for record in incoming_records
            )

        changed = True
        while changed:
            changed = False
            for source_key in source_keys:
                resolved = seed_values.get(source_key)
                for incoming_record in incoming.get(source_key, ()):
                    caller_key = (
                        incoming_record.caller_source_node,
                        incoming_record.caller_source_fact,
                    )
                    caller_value = source_values.get(caller_key)
                    if caller_value is None:
                        continue
                    incoming_value = incoming_record.call_jump(caller_value)
                    if resolved is None:
                        resolved = incoming_value
                    else:
                        resolved = problem.join_values(resolved, incoming_value)

                current = source_values.get(source_key)
                if resolved is None:
                    continue
                if current is None or resolved != current:
                    source_values[source_key] = resolved
                    changed = True

        for path_edge, jump in jump_functions.items():
            source_key = (path_edge.source_node, path_edge.source_fact)
            seed_value = source_values.get(source_key)
            if seed_value is None:
                continue
            value = jump(seed_value)
            key = (path_edge.node, path_edge.fact)
            if key in values:
                values[key] = problem.join_values(values[key], value)
            else:
                values[key] = value

        for node, facts in reached.items():
            for fact in facts:
                values.setdefault((node, fact), problem.bottom_value)

        return IDEResult(
            values,
            dict(reached),
            jump_functions,
            SolverStatistics(**stats),
            {edge: tuple(records) for edge, records in traces.items()},
            {key: tuple(value) for key, value in incoming.items()},
            dict(end_summary),
        )
