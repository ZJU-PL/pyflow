"""Public data-model façade for the flow-sensitive heap abstraction.

The implementations live in focused modules, while this module preserves the
original import surface for callers that use ``flow_sensitive.model``.
"""

from .locations import HeapLocation, HeapSelector, HeapWrite
from .objects import (
    HeapEscapeState,
    HeapObject,
    HeapObjectCardinality,
    HeapObjectFreshness,
    HeapObjectIdentity,
    HeapObjectKind,
    RawStorageProvider,
)
from .policy import (
    AllocationSensitivity,
    ContainerSensitivity,
    FieldSensitivity,
    HeapPolicy,
    UpdatePolicy,
)

__all__ = [
    "AllocationSensitivity",
    "ContainerSensitivity",
    "FieldSensitivity",
    "HeapEscapeState",
    "HeapLocation",
    "HeapObject",
    "HeapObjectCardinality",
    "HeapObjectFreshness",
    "HeapObjectIdentity",
    "HeapObjectKind",
    "HeapPolicy",
    "HeapSelector",
    "HeapWrite",
    "RawStorageProvider",
    "UpdatePolicy",
]
