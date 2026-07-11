from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Mapping, Sequence

from pyflow.analysis.cfg import graph as cfg_graph

from ..cfg_adapter import CFGNode, CFGSupergraphAdapter
from ..problem import IDEProblem, IdentityEdgeFunction, ValueTransition
from ..solver import IDESolver
from ._client_common import AnnotatedFactProblemBase


ZERO_COLLECTOR = "ZERO_COLLECTOR"


@dataclass(frozen=True)
class CollectorConfiguration:
    pass


@dataclass(frozen=True)
class CollectorResult:
    labels_by_node: Mapping[CFGNode, FrozenSet[str]]


class _AccumulateLabels(IdentityEdgeFunction[frozenset[str]]):
    def __init__(self, labels: frozenset[str]) -> None:
        self.labels = labels

    def compute(self, value: frozenset[str]) -> frozenset[str]:
        return value | self.labels

    def is_idempotent(self) -> bool:
        return True

    def __eq__(self, other):
        return isinstance(other, _AccumulateLabels) and self.labels == other.labels

    def __hash__(self):
        return hash(self.labels)


class InterproceduralFlowPathProblem(
    AnnotatedFactProblemBase[str],
    IDEProblem[cfg_graph.Code, CFGNode, str, frozenset[str]],
):
    analysis_name = "IFDS flow-path collector"

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        entry_nodes: Sequence[CFGNode],
    ) -> None:
        super().__init__(adapter)
        self.entry_nodes = tuple(entry_nodes)

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self) -> str:
        return ZERO_COLLECTOR

    @property
    def bottom_value(self) -> frozenset[str]:
        return frozenset()

    def join_values(self, left: frozenset[str], right: frozenset[str]) -> frozenset[str]:
        return left | right

    def initial_seed_values(self):
        return {(node, ZERO_COLLECTOR): frozenset() for node in self.entry_nodes}

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: str):
        if fact != ZERO_COLLECTOR:
            return ()
        return (ValueTransition(ZERO_COLLECTOR, IdentityEdgeFunction()),)

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: str):
        if fact != ZERO_COLLECTOR:
            return ()
        call_effect = self._call_effect(call_node)
        label = self._label_for_call(call_node, call_effect, callee)
        return (ValueTransition(ZERO_COLLECTOR, _AccumulateLabels(frozenset({label}))),)

    def return_flow(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
        exit_node: CFGNode,
        return_site: CFGNode,
        call_fact: str,
        exit_fact: str,
    ):
        if call_fact != ZERO_COLLECTOR or exit_fact != ZERO_COLLECTOR:
            return ()
        call_effect = self._call_effect(call_node)
        label = self._label_for_call(call_node, call_effect, callee)
        return (ValueTransition(ZERO_COLLECTOR, _AccumulateLabels(frozenset({label}))),)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: str):
        if fact != ZERO_COLLECTOR:
            return ()
        return (ValueTransition(ZERO_COLLECTOR, IdentityEdgeFunction()),)

    def _label_for_call(self, call_node, call_effect, callee):
        call_name = self._call_name(call_node)
        if call_name is not None:
            return f"{call_name}()"
        callee_name = getattr(getattr(callee, "code", None), "codeName", None)
        if callable(callee_name):
            try:
                name = callee_name()
            except Exception:
                name = None
            if isinstance(name, str):
                return f"{name}()"
        return "<call>"

    def _make_slot_fact(self, slot: object) -> str:
        return ZERO_COLLECTOR

    def _make_expression_fact(self, procedure, expression, result_index=0) -> str:
        return ZERO_COLLECTOR

    def _slot_from_fact(self, fact: str) -> object | None:
        return None

    def _expression_fact_result(self, fact: str):
        return None


class InterproceduralFlowPathAnalysis:
    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        entry_nodes: Sequence[CFGNode],
    ) -> None:
        self.problem = InterproceduralFlowPathProblem(adapter, entry_nodes)

    def solve(self) -> CollectorResult:
        result = IDESolver().solve(self.problem)
        labels_by_node: dict[CFGNode, frozenset[str]] = {}
        for node in self.adapter.supergraph.nodes():
            facts = result.facts_at(node)
            for fact in facts:
                value = result.value_at(node, fact)
                if value:
                    labels_by_node[node] = value
        return CollectorResult(labels_by_node)


def collect_flow_paths(
    adapter: CFGSupergraphAdapter,
    entry_nodes: Sequence[CFGNode],
) -> CollectorResult:
    return InterproceduralFlowPathAnalysis(adapter, entry_nodes).solve()
