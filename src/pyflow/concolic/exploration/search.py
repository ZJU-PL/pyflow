"""Pending-state selection strategies for concolic exploration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from ..core.runtime import BranchCoverage, _Branch


@dataclass(frozen=True)
class _ExplorationState:
    inputs: tuple[Any, ...]
    schedule_prefix: tuple[int, ...]
    target_branch: BranchCoverage | None = None
    target_depth: int = 0
    target_visits: int = 0


@dataclass
class _PathTreeNode:
    edges: dict[tuple[str, bool], "_PathTreeNode"]
    reserved: set[tuple[str, bool]]
    exhausted: set[tuple[str, bool]]
    visits: int = 0

    def __init__(self) -> None:
        self.edges = {}
        self.reserved = set()
        self.exhausted = set()
        self.visits = 0


class _PathTree:
    """Persistent trie of observed, pending, and exhausted branch prefixes."""

    def __init__(self) -> None:
        self.root = _PathTreeNode()
        self.node_count = 1

    def observe(self, path: Iterable[_Branch]) -> None:
        node = self.root
        node.visits += 1
        for branch in path:
            key = branch.key()
            node.reserved.discard(key)
            child = node.edges.get(key)
            if child is None:
                child = _PathTreeNode()
                node.edges[key] = child
                self.node_count += 1
            node = child
            node.visits += 1

    def reserve(self, prefix: tuple[_Branch, ...], branch: _Branch) -> tuple[int, int] | None:
        node = self._node_for(prefix)
        target = (branch.expression.sexpr(), not branch.taken)
        if target in node.edges or target in node.reserved or target in node.exhausted:
            return None
        node.reserved.add(target)
        return len(prefix) + 1, node.visits

    def exhaust(self, prefix: tuple[_Branch, ...], branch: _Branch) -> None:
        node = self._node_for(prefix)
        target = (branch.expression.sexpr(), not branch.taken)
        node.reserved.discard(target)
        node.exhausted.add(target)

    def _node_for(self, prefix: tuple[_Branch, ...]) -> _PathTreeNode:
        node = self.root
        for branch in prefix:
            child = node.edges.get(branch.key())
            if child is None:
                child = _PathTreeNode()
                node.edges[branch.key()] = child
                self.node_count += 1
            node = child
        return node


class _PathingOracle(Protocol):
    def priority(
        self,
        state: _ExplorationState,
        sequence: int,
        covered_branches: set[BranchCoverage],
    ) -> tuple[int, int, int, int]: ...


class _BreadthFirstOracle:
    def priority(
        self,
        state: _ExplorationState,
        sequence: int,
        covered_branches: set[BranchCoverage],
    ) -> tuple[int, int, int, int]:
        del covered_branches
        return state.target_depth, state.target_visits, len(state.schedule_prefix), sequence


class _CoverageOracle:
    def priority(
        self,
        state: _ExplorationState,
        sequence: int,
        covered_branches: set[BranchCoverage],
    ) -> tuple[int, int, int, int]:
        target = state.target_branch
        if target is not None and target not in covered_branches:
            novelty = 0
        elif target is None:
            novelty = 1
        else:
            novelty = 2
        return novelty, state.target_visits, state.target_depth, sequence


class _ExplorationQueue:
    """A small dynamically rescored queue for exploration states."""

    def __init__(self, strategy: str, initial: _ExplorationState) -> None:
        self.strategy = strategy
        self._oracle: _PathingOracle | None = {
            "breadth_first": _BreadthFirstOracle(),
            "coverage": _CoverageOracle(),
        }.get(strategy)
        self._states = [initial]
        self._sequences = [0]
        self._next_sequence = 1

    def __bool__(self) -> bool:
        return bool(self._states)

    def __len__(self) -> int:
        return len(self._states)

    def append(self, state: _ExplorationState) -> None:
        self._states.append(state)
        self._sequences.append(self._next_sequence)
        self._next_sequence += 1

    def pop(self, covered_branches: set[BranchCoverage]) -> _ExplorationState:
        if self.strategy == "fifo":
            index = 0
        else:
            assert self._oracle is not None
            index = min(
                range(len(self._states)),
                key=lambda candidate: self._oracle.priority(
                    self._states[candidate],
                    self._sequences[candidate],
                    covered_branches,
                ),
            )
        self._sequences.pop(index)
        return self._states.pop(index)
