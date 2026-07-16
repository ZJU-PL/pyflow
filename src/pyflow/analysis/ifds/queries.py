"""Query helpers built on top of IFDS solver results."""

from __future__ import annotations

from collections import deque
from typing import TypeVar


NodeT = TypeVar("NodeT")
FactT = TypeVar("FactT")


def is_reached_prefix(result, node: NodeT, fact: FactT) -> bool:
    """Check if *fact* or a prefix-matched stored fact reaches *node*.

    Supports field-sensitive queries: a stored fact with
    ``access_path=("f",)`` matches a query for ``("f", "g")`` when both
    facts share the same base identity.
    """
    if result.is_reached(node, fact):
        return True
    for stored in result.facts_at(node):
        if _fact_prefix_match(stored, fact):
            return True
    return False


def _fact_prefix_match(stored: object, query: object) -> bool:
    """True when *stored* implies *query* via access-path prefix."""
    if stored == query:
        return True
    s_location = getattr(stored, "location", None)
    q_location = getattr(query, "location", None)
    if s_location is not None and q_location is not None:
        if hasattr(s_location, "is_prefix_of"):
            if not s_location.is_prefix_of(q_location):
                return False
        elif s_location != q_location:
            return False
        return _paths_prefix_match(stored, query)

    s_expr = getattr(stored, "expression", None)
    q_expr = getattr(query, "expression", None)
    s_proc = getattr(stored, "procedure", None)
    q_proc = getattr(query, "procedure", None)
    if (
        s_expr is not None
        and q_expr is not None
        and s_expr == q_expr
        and s_proc is not None
        and q_proc is not None
        and s_proc == q_proc
    ):
        return _paths_prefix_match(stored, query)
    return False


def _paths_prefix_match(stored: object, query: object) -> bool:
    """True when *stored*'s ``access_path`` is a prefix of *query*'s."""
    s_path: tuple[str, ...] = getattr(stored, "access_path", ())
    q_path: tuple[str, ...] = getattr(query, "access_path", ())
    if s_path == q_path:
        return True
    return len(s_path) <= len(q_path) and q_path[: len(s_path)] == s_path


def verify_call_chain(
    result,
    supergraph,
    sink_node: NodeT,
    sink_fact: FactT,
    *,
    source_node: NodeT | None = None,
    source_fact: FactT | None = None,
    max_depth: int = 12,
) -> tuple[bool, tuple[NodeT, ...]]:
    """Demand-driven backward verification of an interprocedural chain."""
    del source_fact
    visited: set[NodeT] = set()
    parent: dict[NodeT, NodeT | None] = {}
    chain_start: NodeT | None = None

    queue: deque[NodeT] = deque([sink_node])
    visited.add(sink_node)
    parent[sink_node] = None

    depth = 0
    while queue and depth < max_depth:
        next_queue: deque[NodeT] = deque()
        for current in queue:
            proc = supergraph.procedure_of(current)
            if proc is None:
                continue
            entry = supergraph.entry_of(proc)
            for fact in result.facts_at(entry):
                for record in result.incoming_records(entry, fact):
                    call_site: NodeT = record.call_node
                    if call_site not in visited:
                        visited.add(call_site)
                        parent[call_site] = current
                        next_queue.append(call_site)
                        if source_node is not None and call_site == source_node:
                            chain_start = call_site
                            break
                if chain_start is not None:
                    break
            if chain_start is not None:
                break
        if chain_start is not None:
            break
        queue = next_queue
        depth += 1

    if source_node is None and chain_start is None:
        for node in visited:
            proc = supergraph.procedure_of(node)
            if proc is None:
                continue
            entry = supergraph.entry_of(proc)
            has_incoming = any(
                result.incoming_records(entry, fact) for fact in result.facts_at(entry)
            )
            if not has_incoming:
                chain_start = node
                break

    if chain_start is None:
        return (False, ())

    chain: list[NodeT] = []
    current: NodeT | None = sink_node
    while current is not None:
        chain.append(current)
        next_node = parent.get(current)
        if next_node == chain_start:
            chain.append(chain_start)
            break
        current = next_node
    chain.reverse()
    if chain and chain[0] != chain_start:
        chain.insert(0, chain_start)
    return (True, tuple(chain))
