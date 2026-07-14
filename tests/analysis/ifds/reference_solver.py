"""Small, deliberately slow IFDS oracle used by differential tests."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from pyflow.analysis.ifds.solver import _normalize_ifds_transitions


@dataclass(frozen=True)
class _Frame:
    call_node: object
    callee: object
    return_site: object
    call_fact: object


@dataclass(frozen=True)
class _Configuration:
    node: object
    fact: object
    stack: tuple[_Frame, ...] = ()


def solve_reference(problem, *, max_stack_depth: int = 8):
    """Explore concrete call stacks; suitable only for small test graphs."""
    graph = problem.supergraph
    reached = defaultdict(set)
    queue = deque()
    seen = set()

    def propagate(configuration):
        if configuration in seen:
            return
        seen.add(configuration)
        reached[configuration.node].add(configuration.fact)
        queue.append(configuration)

    for node, facts in problem.initial_seeds().items():
        for fact in facts:
            propagate(_Configuration(node, fact))

    while queue:
        current = queue.popleft()
        node, fact, stack = current.node, current.fact, current.stack

        if graph.is_call_node(node):
            for return_site in graph.ordered_call_to_return_successors(node):
                for transition in _normalize_ifds_transitions(
                    problem.call_to_return_flow(node, return_site, fact)
                ):
                    propagate(_Configuration(return_site, transition.fact, stack))
            if len(stack) < max_stack_depth:
                for callee in graph.ordered_callees_of_call_at(node):
                    entry = graph.entry_of(callee)
                    for transition in _normalize_ifds_transitions(
                        problem.call_flow(node, callee, fact)
                    ):
                        for return_site in graph.ordered_return_sites_of_call_at(node):
                            frame = _Frame(node, callee, return_site, fact)
                            propagate(
                                _Configuration(
                                    entry,
                                    transition.fact,
                                    (*stack, frame),
                                )
                            )

        if graph.is_exit_node(node) and stack:
            frame = stack[-1]
            if graph.procedure_of(node) == frame.callee:
                for transition in _normalize_ifds_transitions(
                    problem.return_flow(
                        frame.call_node,
                        frame.callee,
                        node,
                        frame.return_site,
                        frame.call_fact,
                        fact,
                    )
                ):
                    propagate(
                        _Configuration(
                            frame.return_site,
                            transition.fact,
                            stack[:-1],
                        )
                    )

        for successor in graph.ordered_normal_successors(node):
            for transition in _normalize_ifds_transitions(
                problem.normal_flow(node, successor, fact)
            ):
                propagate(_Configuration(successor, transition.fact, stack))

    return {node: frozenset(facts) for node, facts in reached.items()}
