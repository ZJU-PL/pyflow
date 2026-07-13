from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Generic, Hashable, Mapping, TypeVar

from .solver import (
    AnalysisStatus,
    IFDSResult,
    PathEdge,
    SolverOptions,
    _SolverBookkeeping,
    _normalize_ifds_transitions,
    _solver_options,
    _stable_value_key,
)
from .supergraph import NodeT, ProcT, Supergraph

FactT = TypeVar("FactT", bound=Hashable)


@dataclass(frozen=True)
class _BackwardIncomingRecord(Generic[NodeT, FactT]):
    caller_source_node: NodeT
    caller_source_fact: FactT
    return_site: NodeT
    call_fact: FactT
    call_site: NodeT


class BackwardIFDSProblem(Generic[ProcT, NodeT, FactT], ABC):
    @property
    @abstractmethod
    def supergraph(self) -> Supergraph[ProcT, NodeT]:
        raise NotImplementedError

    @property
    @abstractmethod
    def zero_fact(self) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def initial_seeds(self) -> Mapping[NodeT, frozenset[FactT]]:
        raise NotImplementedError

    def normal_flow(self, predecessor: NodeT, successor: NodeT, fact: FactT):
        return ()

    def call_flow(self, return_site: NodeT, callee: ProcT, fact: FactT):
        return ()

    def return_flow(
        self, return_site: NodeT, callee: ProcT, callee_entry: NodeT, call_fact: FactT
    ):
        return ()

    def call_to_return_flow(self, return_site: NodeT, call_site: NodeT, fact: FactT):
        return ()


class BackwardIFDSSolver(Generic[ProcT, NodeT, FactT]):
    def __init__(
        self,
        *,
        options: SolverOptions | None = None,
        record_traces: bool = False,
        max_propagated_path_edges: int | None = None,
    ) -> None:
        self.options = _solver_options(
            options=options,
            record_traces=record_traces,
            max_propagated_path_edges=max_propagated_path_edges,
            max_call_string_depth=None,
        )
        self.record_traces = self.options.trace_mode == "all"
        self.max_propagated_path_edges = self.options.max_propagated_path_edges

    def solve(
        self, problem: BackwardIFDSProblem[ProcT, NodeT, FactT]
    ) -> IFDSResult[NodeT, FactT]:
        supergraph = problem.supergraph
        queue: deque[PathEdge[NodeT, FactT]] = deque()
        seen: set[PathEdge[NodeT, FactT]] = set()
        reached: DefaultDict[NodeT, set[FactT]] = defaultdict(set)
        incoming: DefaultDict[
            tuple[NodeT, FactT], set[_BackwardIncomingRecord[NodeT, FactT]]
        ] = defaultdict(set)
        end_summary: DefaultDict[tuple[NodeT, FactT, NodeT], set[FactT]] = defaultdict(
            set
        )
        incoming_total = 0
        summary_entries = 0
        bookkeeping = _SolverBookkeeping[NodeT, FactT](
            options=self.options,
            limit_label="Backward IFDS",
        )
        normal_preds = self._build_normal_predecessors(supergraph)
        return_site_to_call_sites = self._build_return_site_call_map(supergraph)
        callees_by_return_site = self._build_callees_by_return_site(supergraph)

        def propagate(
            path_edge: PathEdge[NodeT, FactT],
            *,
            kind: str,
            predecessor: PathEdge[NodeT, FactT] | None = None,
            note: str | None = None,
        ) -> None:
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                return
            if path_edge in seen:
                return
            seen.add(path_edge)
            reached[path_edge.node].add(path_edge.fact)
            facts_at_node = len(reached[path_edge.node])
            bookkeeping.observe("peak_facts_at_node", facts_at_node)
            max_facts = self.options.max_facts_per_node
            if max_facts is not None and facts_at_node > max_facts:
                bookkeeping.stop(
                    AnalysisStatus.PARTIAL,
                    f"Backward IFDS exceeded max_facts_per_node={max_facts}",
                )
                return
            bookkeeping.record_propagation(
                path_edge, kind=kind, predecessor=predecessor, note=note
            )
            if bookkeeping.status is not AnalysisStatus.COMPLETE:
                return
            queue.append(path_edge)
            bookkeeping.check_budget(
                queue_size=len(queue),
                incoming_records=incoming_total,
                summary_entries=summary_entries,
            )

        for node, facts in sorted(
            problem.initial_seeds().items(),
            key=lambda item: supergraph.node_id(item[0]),
        ):
            for fact in sorted(facts, key=_stable_value_key):
                propagate(PathEdge(node, fact, node, fact), kind="seed")

        while queue and bookkeeping.status is AnalysisStatus.COMPLETE:
            bookkeeping.check_budget(
                queue_size=len(queue),
                incoming_records=incoming_total,
                summary_entries=summary_entries,
            )
            edge = queue.popleft()
            bookkeeping.increment("processed_path_edges")
            source_node = edge.source_node
            source_fact = edge.source_fact
            node = edge.node
            fact = edge.fact

            if node in return_site_to_call_sites:
                for call_site in return_site_to_call_sites[node]:
                    bookkeeping.increment("call_to_return_steps")
                    for transition in _normalize_ifds_transitions(
                        problem.call_to_return_flow(node, call_site, fact)
                    ):
                        propagate(
                            PathEdge(
                                source_node, source_fact, call_site, transition.fact
                            ),
                            kind="call_to_return",
                            predecessor=edge,
                            note=f"{node!r} -> {call_site!r}",
                        )

                for callee in callees_by_return_site.get(node, ()):
                    bookkeeping.increment("call_flow_steps")
                    for transition in _normalize_ifds_transitions(
                        problem.call_flow(node, callee, fact)
                    ):
                        start_fact = transition.fact
                        for callee_exit in supergraph.ordered_exits_of(callee):
                            incoming_key = (callee_exit, start_fact)
                            for call_site in return_site_to_call_sites.get(node, ()):
                                incoming_record = _BackwardIncomingRecord(
                                    source_node,
                                    source_fact,
                                    node,
                                    fact,
                                    call_site,
                                )
                                if incoming_record not in incoming[incoming_key]:
                                    incoming[incoming_key].add(incoming_record)
                                    incoming_total += 1
                                    bookkeeping.increment("incoming_records")
                                    bookkeeping.check_budget(
                                        queue_size=len(queue),
                                        incoming_records=incoming_total,
                                        summary_entries=summary_entries,
                                    )
                                    entry_node = supergraph.entry_of(callee)
                                    for exit_fact in sorted(
                                        end_summary.get(
                                            (callee_exit, start_fact, entry_node), ()
                                        ),
                                        key=_stable_value_key,
                                    ):
                                        bookkeeping.increment("return_flow_steps")
                                        for transition in _normalize_ifds_transitions(
                                            problem.return_flow(
                                                node, callee, entry_node, exit_fact
                                            )
                                        ):
                                            propagate(
                                                PathEdge(
                                                    source_node,
                                                    source_fact,
                                                    call_site,
                                                    transition.fact,
                                                ),
                                                kind="return_flow(summary_replay)",
                                                note=f"{callee!r} via {entry_node!r}",
                                            )

                            propagate(
                                PathEdge(
                                    callee_exit, start_fact, callee_exit, start_fact
                                ),
                                kind="call_flow",
                                predecessor=edge,
                                note=f"{node!r} -> {callee!r}",
                            )

            if self._is_entry_node(supergraph, node):
                callee = supergraph.procedure_of(node)
                summary_key = (source_node, source_fact, node)
                if fact not in end_summary[summary_key]:
                    end_summary[summary_key].add(fact)
                    summary_entries += 1
                    bookkeeping.increment("summary_updates")
                    bookkeeping.check_budget(
                        queue_size=len(queue),
                        incoming_records=incoming_total,
                        summary_entries=summary_entries,
                    )
                    for incoming_record in sorted(
                        incoming.get((source_node, source_fact), ()),
                        key=_stable_value_key,
                    ):
                        bookkeeping.increment("return_flow_steps")
                        for transition in _normalize_ifds_transitions(
                            problem.return_flow(
                                incoming_record.return_site,
                                callee,
                                node,
                                incoming_record.call_fact,
                            )
                        ):
                            propagate(
                                PathEdge(
                                    incoming_record.caller_source_node,
                                    incoming_record.caller_source_fact,
                                    incoming_record.call_site,
                                    transition.fact,
                                ),
                                kind="return_flow",
                                predecessor=edge,
                                note=f"{callee!r} -> {incoming_record.call_site!r}",
                            )

            for pred in normal_preds.get(node, ()):
                bookkeeping.increment("normal_flow_steps")
                for transition in _normalize_ifds_transitions(
                    problem.normal_flow(pred, node, fact)
                ):
                    propagate(
                        PathEdge(source_node, source_fact, pred, transition.fact),
                        kind="normal_flow",
                        predecessor=edge,
                        note=f"{node!r} -> {pred!r}",
                    )

        return IFDSResult(
            dict(reached),
            frozenset(seen),
            bookkeeping.statistics(
                check_budget=bookkeeping.status is AnalysisStatus.COMPLETE
            ),
            bookkeeping.frozen_traces(),
            {key: tuple(value) for key, value in incoming.items()},
            {key: frozenset(value) for key, value in end_summary.items()},
            status=bookkeeping.status,
            termination_reason=bookkeeping.termination_reason,
        )

    def _is_entry_node(self, sg: Supergraph[ProcT, NodeT], node: NodeT) -> bool:
        proc = sg.procedure_of(node)
        return node == sg.entry_of(proc)

    def _build_normal_predecessors(self, sg):
        preds: DefaultDict[NodeT, set[NodeT]] = defaultdict(set)
        for node in sg.ordered_nodes():
            for succ in sg.ordered_normal_successors(node):
                preds[succ].add(node)
        return {
            node: tuple(sorted(values, key=sg.node_id))
            for node, values in preds.items()
        }

    def _build_return_site_call_map(self, sg):
        mapping: DefaultDict[NodeT, set[NodeT]] = defaultdict(set)
        for call_node in sg.ordered_nodes():
            if not sg.is_call_node(call_node):
                continue
            for ret_site in sg.ordered_return_sites_of_call_at(call_node):
                mapping[ret_site].add(call_node)
        return {
            node: tuple(sorted(values, key=sg.node_id))
            for node, values in mapping.items()
        }

    def _build_callees_by_return_site(self, sg):
        mapping: DefaultDict[NodeT, set[ProcT]] = defaultdict(set)
        for call_node in sg.ordered_nodes():
            if not sg.is_call_node(call_node):
                continue
            for callee in sg.ordered_callees_of_call_at(call_node):
                for ret_site in sg.ordered_return_sites_of_call_at(call_node):
                    mapping[ret_site].add(callee)
        return {
            node: tuple(sorted(values, key=sg.procedure_id))
            for node, values in mapping.items()
        }
