"""Heap abstraction model for static analysis.

The heap model provides canonical :class:`HeapLocation` objects,
:class:`HeapAbstraction` for alias tracking and strong/weak update policy,
and factory classes for translating Python IR operations into heap effects.

Submodules
----------
* :mod:`.heap` — Core model: HeapObject, HeapLocation, HeapPolicy, HeapAbstraction
* :mod:`.heap_effects` — Translates IR operations into HeapEffect records
* :mod:`.heap_summary` — Procedure-level heap summaries

Examples
--------

>>> from pyflow.analysis.heap import HeapPolicy, HeapAbstraction, HeapEffect

>>> policy = HeapPolicy.context_sensitive(depth=2)
>>> policy.validate()  # catch misconfigurations early

>>> effect = HeapEffect(reads=(...), writes=(...))
>>> bool(effect)
True
>>> effect.is_empty
False
>>> merged = effect.merge(other_effect)

>>> heap = HeapAbstraction(raw_storage_provider, policy=policy)
>>> heap.to_dict()
{'policy': {...}, 'next_site': 0, 'cached_objects': 0, ...}
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
    RawStorageProvider,
    UpdatePolicy,
)

from .heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    HeapEffect,
    HeapEffectBuilder,
)

from .heap_summary import (
    HeapSummary,
    HeapSummaryBuilder,
)

__all__ = [
    "AllocationSensitivity",
    "CALL_RETURN_COPY",
    "CALL_RETURN_FRESH",
    "CALL_RETURN_OPAQUE",
    "CALL_RETURN_SUMMARY",
    "ContainerSensitivity",
    "FieldSensitivity",
    "HeapAbstraction",
    "HeapEffect",
    "HeapEffectBuilder",
    "HeapEscapeState",
    "HeapLocation",
    "HeapObject",
    "HeapObjectFreshness",
    "HeapObjectKind",
    "HeapPolicy",
    "HeapSelector",
    "HeapSummary",
    "HeapSummaryBuilder",
    "HeapWrite",
    "RawStorageProvider",
    "UpdatePolicy",
]
