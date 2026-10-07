"""Default taint sources, sinks, sanitizers, and propagation protocols."""

from __future__ import annotations
from typing import FrozenSet

_SQL_SINKS: FrozenSet[str] = frozenset({"execute", "executemany", "executescript"})

_DUNDER_PROPAGATE: FrozenSet[str] = frozenset(
    {
        "__str__",
        "__repr__",
        "__add__",
        "__getattr__",
        "__getitem__",
        "__iter__",
    }
)
