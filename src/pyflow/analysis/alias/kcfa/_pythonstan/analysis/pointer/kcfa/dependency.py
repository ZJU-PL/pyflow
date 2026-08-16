"""Generic monotone dependencies between derived semantic facts.

Semantic layers often need to reconsider a conclusion when one of several
points-to sources grows.  Encoding each case as a bespoke constraint makes it
easy to accidentally implement one-shot behavior.  This module provides a
small keyed subscription engine: source growth schedules a callback once, and
the solver executes callbacks as ordinary fixpoint work.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Hashable, Iterable


@dataclass(frozen=True)
class Dependency:
    key: Hashable
    sources: FrozenSet[Hashable]
    callback: Callable[[], None]


class DependencyManager:
    """Deduplicated source-growth subscriptions owned by one analysis."""

    def __init__(self) -> None:
        self._dependencies: Dict[Hashable, Dependency] = {}
        self._by_source = defaultdict(set)
        self._pending = deque()
        self._pending_keys = set()

    def subscribe(
        self,
        key: Hashable,
        sources: Iterable[Hashable],
        callback: Callable[[], None],
        *,
        run_initial: bool = False,
    ) -> bool:
        """Register ``callback`` and return whether the key was new."""
        if key in self._dependencies:
            return False
        dependency = Dependency(key, frozenset(sources), callback)
        self._dependencies[key] = dependency
        for source in dependency.sources:
            self._by_source[source].add(key)
        if run_initial:
            self._schedule(key)
        return True

    def notify_growth(self, source: Hashable) -> None:
        for key in self._by_source.get(source, ()):
            self._schedule(key)

    def _schedule(self, key: Hashable) -> None:
        if key in self._pending_keys:
            return
        self._pending_keys.add(key)
        self._pending.append(key)

    def has_pending(self) -> bool:
        return bool(self._pending)

    def run_next(self) -> None:
        key = self._pending.popleft()
        self._pending_keys.remove(key)
        self._dependencies[key].callback()

    def __len__(self) -> int:
        return len(self._dependencies)
