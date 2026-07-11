"""IFDS and IDE solvers over the reusable interprocedural supergraph."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Dict, FrozenSet, Generic, Hashable, TypeVar

from .problem import (
    EdgeFunction,
    FactTransition,
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
class CallContext:
    """Bounded call-string context for context-sensitive IFDS/IDE solving.

    Each call site visited along the current interprocedural path is recorded.
    When ``max_depth`` is exceeded the oldest entries are truncated, keeping
    the context bounded and the analysis polynomial.

    ``CallContext()`` with no arguments represents the empty (entry-point)
    context.
    """

    call_sites: tuple[Hashable, ...] = ()
    max_depth: int = 3

    def push(self, call_site: Hashable) -> "CallContext":
        sites = self.call_sites + (call_site,)
        if len(sites) > self.max_depth:
            sites = sites[-self.max_depth :]
        return CallContext(call_sites=sites, max_depth=self.max_depth)

    def pop(self) -> "CallContext":
        if not self.call_sites:
            return self
        return CallContext(call_sites=self.call_sites[:-1], max_depth=self.max_depth)


@dataclass(frozen=True)
class PathEdge(Generic[NodeT, FactT]):
    """A source-relative exploded-graph edge.

    The optional *context* field distinguishes the same (source, node, fact)
    tuple when it is reached through different call strings.  When ``None``
    the solver operates context-insensitively (the default).
    """

    source_node: NodeT
    source_fact: FactT
    node: NodeT
    fact: FactT
    context: Hashable | None = None


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


class _SolverBookkeeping(Generic[NodeT, FactT]):
    """Shared statistics/tracing/limit tracking for IFDS and IDE solvers."""

    def __init__(
        self,
        *,
        record_traces: bool,
        max_propagated_path_edges: int | None,
        limit_label: str,
    ) -> None:
        self.record_traces = record_traces
        self.max_propagated_path_edges = max_propagated_path_edges
        self.limit_label = limit_label
        self.traces: DefaultDict[
            PathEdge[NodeT, FactT], list[PropagationTrace[NodeT, FactT]]
        ] = defaultdict(list)
        self.stats = {
            "processed_path_edges": 0,
            "propagated_path_edges": 0,
            "normal_flow_steps": 0,
            "call_flow_steps": 0,
            "return_flow_steps": 0,
            "call_to_return_steps": 0,
            "incoming_records": 0,
            "summary_updates": 0,
        }

    def increment(self, key: str) -> None:
        self.stats[key] += 1

    def record_propagation(
        self,
        path_edge: PathEdge[NodeT, FactT],
        *,
        kind: str,
        predecessor: PathEdge[NodeT, FactT] | None = None,
        note: str | None = None,
    ) -> None:
        if self.record_traces:
            self.traces[path_edge].append(
                PropagationTrace(path_edge, kind, predecessor, note)
            )
        self.stats["propagated_path_edges"] += 1
        if (
            self.max_propagated_path_edges is not None
            and self.stats["propagated_path_edges"] > self.max_propagated_path_edges
        ):
            raise SolverLimitExceeded(
                f"{self.limit_label} propagation exceeded max_propagated_path_edges="
                f"{self.max_propagated_path_edges}"
            )

    def frozen_traces(
        self,
    ) -> Dict[PathEdge[NodeT, FactT], tuple[PropagationTrace[NodeT, FactT], ...]]:
        return {edge: tuple(records) for edge, records in self.traces.items()}

    def statistics(self) -> SolverStatistics:
        return SolverStatistics(**self.stats)


def _normalize_ifds_transitions(outputs) -> tuple[FactTransition[FactT], ...]:
    """Accept raw IFDS facts or explicit FactTransition wrappers."""
    normalized: list[FactTransition[FactT]] = []
    for output in outputs:
        if isinstance(output, FactTransition):
            normalized.append(output)
        else:
            normalized.append(FactTransition(output))
    return tuple(normalized)


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
    """Classic tabulation-style IFDS solver.

    Set *max_call_string_depth* to an integer (e.g. 3) to enable bounded
    call-string context sensitivity.  The default ``None`` runs the solver
    context-insensitively, matching the original IFDS algorithm.
    """

    def __init__(
        self,
        *,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
        max_call_string_depth: int | None = None,
    ) -> None:
        self.record_traces = record_traces
        self.max_propagated_path_edges = max_propagated_path_edges
        self.max_call_string_depth = max_call_string_depth

    def solve(self, problem: IFDSProblem[ProcT, NodeT, FactT]) -> IFDSResult[NodeT, FactT]:
        supergraph = problem.supergraph
        use_context = self.max_call_string_depth is not None
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        seen: set[PathEdge[NodeT, FactT]] = set()
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[
            tuple, set[_IncomingRecord[NodeT, FactT]]
        ] = defaultdict(set)
        end_summary: DefaultDict[
            tuple, set[FactT]
        ] = defaultdict(set)
        bookkeeping = _SolverBookkeeping[NodeT, FactT](
            record_traces=self.record_traces,
            max_propagated_path_edges=self.max_propagated_path_edges,
            limit_label="IFDS",
        )

        def propagate(
            path_edge: PathEdge[NodeT, FactT],
            *,
            kind: str,
            predecessor: PathEdge[NodeT, FactT] | None = None,
            note: str | None = None,
        ) -> None:
            if path_edge in seen:
                return
            seen.add(path_edge)
            reached[path_edge.node].add(path_edge.fact)
            bookkeeping.record_propagation(
                path_edge,
                kind=kind,
                predecessor=predecessor,
                note=note,
            )
            queue.append(path_edge)

        def _seed_context() -> Hashable | None:
            if not use_context:
                return None
            depth: int = self.max_call_string_depth  # type: ignore[assignment]
            return CallContext(max_depth=depth)

        def _push_context(ctx: Hashable | None, call_site: Hashable) -> Hashable | None:
            if ctx is None or not use_context:
                return None
            if isinstance(ctx, CallContext):
                return ctx.push(call_site)
            return ctx

        def _contextual_key(*parts: Hashable, ctx: Hashable | None = None) -> tuple:
            if ctx is None or not use_context:
                return parts
            return (*parts, ctx)

        for node, facts in problem.initial_seeds().items():
            ctx = _seed_context()
            for fact in facts:
                propagate(
                    PathEdge(node, fact, node, fact, context=ctx),
                    kind="seed",
                )

        while queue:
            edge = queue.popleft()
            bookkeeping.increment("processed_path_edges")
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact
            edge_ctx = edge.context

            if supergraph.is_call_node(node):
                for return_site in supergraph.call_to_return_successors(node):
                    bookkeeping.increment("call_to_return_steps")
                    for transition in _normalize_ifds_transitions(
                        problem.call_to_return_flow(node, return_site, fact)
                    ):
                        propagate(
                            PathEdge(
                                source_node,
                                source_fact,
                                return_site,
                                transition.fact,
                                context=edge_ctx,
                            ),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {return_site!r}",
                        )

                for callee in supergraph.callees_of_call_at(node):
                    start = supergraph.entry_of(callee)
                    bookkeeping.increment("call_flow_steps")
                    for transition in _normalize_ifds_transitions(
                        problem.call_flow(node, callee, fact)
                    ):
                        start_fact = transition.fact
                        callee_ctx = _push_context(edge_ctx, node)
                        incoming_key = _contextual_key(start, start_fact, ctx=callee_ctx)
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
                                bookkeeping.increment("incoming_records")
                                for exit_node in supergraph.exits_of(callee):
                                    summary_key = _contextual_key(
                                        start, start_fact, exit_node, ctx=callee_ctx,
                                    )
                                    for exit_fact in end_summary.get(summary_key, ()):
                                        bookkeeping.increment("return_flow_steps")
                                        for transition in _normalize_ifds_transitions(
                                            problem.return_flow(
                                                node,
                                                callee,
                                                exit_node,
                                                return_site,
                                                fact,
                                                exit_fact,
                                            )
                                        ):
                                            propagate(
                                                PathEdge(
                                                    source_node,
                                                    source_fact,
                                                    return_site,
                                                    transition.fact,
                                                    context=edge_ctx,
                                                ),
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {return_site!r}",
                                            )

                        propagate(
                            PathEdge(
                                start, start_fact, start, start_fact, context=callee_ctx,
                            ),
                            kind="call_flow",
                            predecessor=edge,
                            note=f"{node!r} -> {callee!r}",
                        )

            if supergraph.is_exit_node(node):
                summary_key = _contextual_key(source_node, source_fact, node, ctx=edge_ctx)
                if fact not in end_summary[summary_key]:
                    end_summary[summary_key].add(fact)
                    bookkeeping.increment("summary_updates")
                    callee = supergraph.procedure_of(node)
                    caller_incoming_key = _contextual_key(source_node, source_fact, ctx=edge_ctx)
                    for incoming_record in incoming.get(caller_incoming_key, ()):
                        bookkeeping.increment("return_flow_steps")
                        for transition in _normalize_ifds_transitions(
                            problem.return_flow(
                                incoming_record.call_node,
                                callee,
                                node,
                                incoming_record.return_site,
                                incoming_record.call_fact,
                                fact,
                            )
                        ):
                            propagate(
                                PathEdge(
                                    incoming_record.caller_source_node,
                                    incoming_record.caller_source_fact,
                                    incoming_record.return_site,
                                    transition.fact,
                                    context=edge_ctx,
                                ),
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.return_site!r}",
                            )

            for successor in supergraph.normal_successors(node):
                bookkeeping.increment("normal_flow_steps")
                for transition in _normalize_ifds_transitions(
                    problem.normal_flow(node, successor, fact)
                ):
                    propagate(
                        PathEdge(
                            source_node,
                            source_fact,
                            successor,
                            transition.fact,
                            context=edge_ctx,
                        ),
                        kind="normal_flow",
                        predecessor=edge,
                        note=f"{node!r} -> {successor!r}",
                    )

        return IFDSResult(
            dict(reached),
            frozenset(seen),
            bookkeeping.statistics(),
            bookkeeping.frozen_traces(),
            {key: tuple(value) for key, value in incoming.items()},
            {key: frozenset(value) for key, value in end_summary.items()},
        )


class IDESolver(Generic[ProcT, NodeT, FactT, ValueT]):
    """Jump-function IDE solver keyed by source-relative path edges.

    Set *max_call_string_depth* to an integer (e.g. 3) to enable bounded
    call-string context sensitivity.
    """

    def __init__(
        self,
        *,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
        max_call_string_depth: int | None = None,
    ) -> None:
        self.record_traces = record_traces
        self.max_propagated_path_edges = max_propagated_path_edges
        self.max_call_string_depth = max_call_string_depth

    def solve(self, problem: IDEProblem[ProcT, NodeT, FactT, ValueT]) -> IDEResult[NodeT, FactT, ValueT]:
        supergraph = problem.supergraph
        use_context = self.max_call_string_depth is not None
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        jump_functions: Dict[PathEdge[NodeT, FactT], EdgeFunction[ValueT]] = {}
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[
            tuple, set[_IDEIncomingRecord[NodeT, FactT, ValueT]]
        ] = defaultdict(set)
        end_summary: Dict[
            tuple, EdgeFunction[ValueT]
        ] = {}
        bookkeeping = _SolverBookkeeping[NodeT, FactT](
            record_traces=self.record_traces,
            max_propagated_path_edges=self.max_propagated_path_edges,
            limit_label="IDE",
        )
        identity = IdentityEdgeFunction[ValueT]()
        seed_values = dict(problem.initial_seed_values())

        def join_edge_functions(
            left: EdgeFunction[ValueT], right: EdgeFunction[ValueT]
        ) -> EdgeFunction[ValueT]:
            return left.join(right, problem.join_values)

        def _seed_context() -> Hashable | None:
            if not use_context:
                return None
            depth: int = self.max_call_string_depth  # type: ignore[assignment]
            return CallContext(max_depth=depth)

        def _push_context(ctx: Hashable | None, call_site: Hashable) -> Hashable | None:
            if ctx is None or not use_context:
                return None
            if isinstance(ctx, CallContext):
                return ctx.push(call_site)
            return ctx

        def _contextual_key(*parts: Hashable, ctx: Hashable | None = None) -> tuple:
            if ctx is None or not use_context:
                return parts
            return (*parts, ctx)

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
                jump_functions[path_edge] = jump
                reached[path_edge.node].add(path_edge.fact)
                bookkeeping.record_propagation(
                    path_edge,
                    kind=kind,
                    predecessor=predecessor,
                    note=note,
                )
                queue.append(path_edge)
                return
            joined = join_edge_functions(current, jump)
            if joined != current:
                jump_functions[path_edge] = joined
                reached[path_edge.node].add(path_edge.fact)
                bookkeeping.record_propagation(
                    path_edge,
                    kind=kind,
                    predecessor=predecessor,
                    note=note,
                )
                queue.append(path_edge)

        for seed, value in seed_values.items():
            node, fact = seed
            _ = value
            ctx = _seed_context()
            propagate(
                PathEdge(node, fact, node, fact, context=ctx),
                identity,
                kind="seed",
            )

        while queue:
            edge = queue.popleft()
            bookkeeping.increment("processed_path_edges")
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact
            edge_ctx = edge.context
            current_jump = jump_functions[edge]

            if supergraph.is_call_node(node):
                for return_site in supergraph.call_to_return_successors(node):
                    bookkeeping.increment("call_to_return_steps")
                    for transition in problem.call_to_return_flow(node, return_site, fact):
                        propagate(
                            PathEdge(
                                source_node,
                                source_fact,
                                return_site,
                                transition.fact,
                                context=edge_ctx,
                            ),
                            transition.edge_function.compose(current_jump),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {return_site!r}",
                        )

                for callee in supergraph.callees_of_call_at(node):
                    start = supergraph.entry_of(callee)
                    bookkeeping.increment("call_flow_steps")
                    for transition in problem.call_flow(node, callee, fact):
                        call_jump = transition.edge_function.compose(current_jump)
                        callee_ctx = _push_context(edge_ctx, node)
                        incoming_key = _contextual_key(start, transition.fact, ctx=callee_ctx)
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
                                bookkeeping.increment("incoming_records")
                                for exit_node in supergraph.exits_of(callee):
                                    for exit_fact in reached.get(exit_node, ()):
                                        summary_key = _contextual_key(
                                            start, transition.fact, exit_node, exit_fact,
                                            ctx=callee_ctx,
                                        )
                                        summary = end_summary.get(summary_key)
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
                                                    context=edge_ctx,
                                                ),
                                                combined,
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {return_site!r}",
                                            )

                        propagate(
                            PathEdge(
                                start, transition.fact, start, transition.fact,
                                context=callee_ctx,
                            ),
                            identity,
                            kind="call_flow",
                            predecessor=edge,
                            note=f"{node!r} -> {callee!r}",
                        )

            if supergraph.is_exit_node(node):
                summary_key = _contextual_key(
                    source_node, source_fact, node, fact, ctx=edge_ctx,
                )
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
                    bookkeeping.increment("summary_updates")
                    callee = supergraph.procedure_of(node)
                    summary = end_summary[summary_key]
                    caller_incoming_key = _contextual_key(
                        source_node, source_fact, ctx=edge_ctx,
                    )
                    for incoming_record in incoming.get(caller_incoming_key, ()):
                        bookkeeping.increment("return_flow_steps")
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
                                    context=edge_ctx,
                                ),
                                combined,
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.return_site!r}",
                            )

            for successor in supergraph.normal_successors(node):
                bookkeeping.increment("normal_flow_steps")
                for transition in problem.normal_flow(node, successor, fact):
                    propagate(
                        PathEdge(
                            source_node, source_fact, successor, transition.fact,
                            context=edge_ctx,
                        ),
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
            bookkeeping.statistics(),
            bookkeeping.frozen_traces(),
            {key: tuple(value) for key, value in incoming.items()},
            dict(end_summary),
        )
