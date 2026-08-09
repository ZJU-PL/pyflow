"""Pending-state selection strategies for concolic exploration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.runtime import BranchCoverage


@dataclass(frozen=True)
class _ExplorationState:
    inputs: tuple[Any, ...]
    schedule_prefix: tuple[int, ...]
    target_branch: BranchCoverage | None = None


class _ExplorationQueue:
    """A small dynamically rescored queue for exploration states."""

    def __init__(self, strategy: str, initial: _ExplorationState) -> None:
        self.strategy = strategy
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
            index = min(
                range(len(self._states)),
                key=lambda candidate: self._priority(
                    self._states[candidate],
                    self._sequences[candidate],
                    covered_branches,
                ),
            )
        self._sequences.pop(index)
        return self._states.pop(index)

    @staticmethod
    def _priority(
        state: _ExplorationState,
        sequence: int,
        covered_branches: set[BranchCoverage],
    ) -> tuple[int, int]:
        target = state.target_branch
        if target is not None and target not in covered_branches:
            novelty = 0
        elif target is None:
            novelty = 1
        else:
            novelty = 2
        return novelty, sequence
