"""Heap abstraction model for static analysis.

The heap model provides canonical :class:`HeapLocation` objects,
:class:`HeapAbstraction` for alias tracking and strong/weak update policy.

The IFDS-dependent submodules (:mod:`.heap_effects`, :mod:`.heap_summary`)
are importable separately to avoid circular imports with the IFDS package.
"""

from .heap import (
    AllocationSensitivity,
    ContainerSensitivity,
    FieldSensitivity,
    HeapAbstraction,
    HeapEscapeState,
    HeapLocation,
    HeapObject,
    HeapObjectFreshness,
    HeapObjectKind,
    HeapPolicy,
    HeapSelector,
    HeapWrite,
    UpdatePolicy,
)

__all__ = [
    "AllocationSensitivity",
    "ContainerSensitivity",
    "FieldSensitivity",
    "HeapAbstraction",
    "HeapEscapeState",
    "HeapLocation",
    "HeapObject",
    "HeapObjectFreshness",
    "HeapObjectKind",
    "HeapPolicy",
    "HeapSelector",
    "HeapWrite",
    "UpdatePolicy",
]
