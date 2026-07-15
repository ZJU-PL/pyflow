"""Heap abstraction model for static analysis.

The heap model provides canonical :class:`HeapLocation` objects,
:class:`HeapAbstraction` for alias tracking and strong/weak update policy,
and factory classes for translating Python IR operations into heap effects.

Submodules
----------
* :mod:`.model` — Data model: enums, HeapPolicy, HeapObject, HeapLocation, HeapSelector, HeapWrite
* :mod:`.abstraction` — HeapAbstraction engine: canonicalization, alias tracking, update policies
* :mod:`.heap_effects` — Translates IR operations into HeapEffect records
* :mod:`.heap_state` — Flow-sensitive, path-insensitive value state
* :mod:`.heap_summary` — Procedure-level heap summaries
* :mod:`.points_to_graph` — Read-only PointsToGraph snapshot for optimization passes
* :mod:`.heap_analysis` — Standalone HeapAnalysis engine and pass integration
* :mod:`.intrinsics` — Heap-owned built-in call and collection models
* :mod:`.transfer` — Standalone forward transfer engine

Examples
--------

>>> from pyflow.analysis.alias.flow_sensitive import HeapPolicy, HeapAbstraction, HeapEffect

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

Standalone ``HeapAnalysis`` performs a flow-sensitive, path-insensitive
forward sweep over discoverable code objects.  It keeps precise field and
literal-key values when possible and records wildcard writes as contaminating
overlapping paths instead of flattening unrelated exact facts.
"""

from .model import (
    AllocationSensitivity,
    ContainerSensitivity,
    FieldSensitivity,
    HeapEscapeState,
    HeapLocation,
    HeapObject,
    HeapObjectCardinality,
    HeapObjectIdentity,
    HeapObjectFreshness,
    HeapObjectKind,
    HeapPolicy,
    HeapSelector,
    HeapWrite,
    RawStorageProvider,
    UpdatePolicy,
)

from .abstraction import (
    HeapAbstraction,
    HeapEnvironment,
)

from .heap_effects import (
    CALL_RETURN_COPY,
    CALL_RETURN_FRESH,
    CALL_RETURN_OPAQUE,
    CALL_RETURN_SUMMARY,
    COLLECTION_DELETE_MUTATOR_NAMES,
    COLLECTION_VALUE_MUTATOR_NAMES,
    DEFAULT_COLLECTION_MUTATOR_NAMES,
    HeapEffect,
    HeapEffectBuilder,
    HeapOperationSemantics,
)

from .intrinsics import (
    CollectionMutatorModel,
    DEFAULT_HEAP_INTRINSICS,
    HeapIntrinsicModels,
)

from .heap_state import HeapState

from .heap_summary import (
    HeapSummary,
    HeapSummaryBuilder,
    ProcedureHeapSummary,
)

from .points_to_graph import (
    HeapValueSnapshot,
    PossibleValues,
    PointsToEntry,
    PointsToGraph,
)

from .heap_analysis import (
    HeapAnalysis,
)

from .transfer import HeapTransferEngine

__all__ = [
    "AllocationSensitivity",
    "CALL_RETURN_COPY",
    "CALL_RETURN_FRESH",
    "CALL_RETURN_OPAQUE",
    "CALL_RETURN_SUMMARY",
    "COLLECTION_DELETE_MUTATOR_NAMES",
    "COLLECTION_VALUE_MUTATOR_NAMES",
    "CollectionMutatorModel",
    "ContainerSensitivity",
    "DEFAULT_COLLECTION_MUTATOR_NAMES",
    "DEFAULT_HEAP_INTRINSICS",
    "FieldSensitivity",
    "HeapAbstraction",
    "HeapAnalysis",
    "HeapEffect",
    "HeapEffectBuilder",
    "HeapOperationSemantics",
    "HeapEnvironment",
    "HeapEscapeState",
    "HeapLocation",
    "HeapObject",
    "HeapObjectCardinality",
    "HeapObjectIdentity",
    "HeapObjectFreshness",
    "HeapObjectKind",
    "HeapPolicy",
    "HeapSelector",
    "HeapState",
    "HeapSummary",
    "HeapTransferEngine",
    "HeapIntrinsicModels",
    "HeapSummaryBuilder",
    "ProcedureHeapSummary",
    "HeapWrite",
    "HeapValueSnapshot",
    "PointsToEntry",
    "PointsToGraph",
    "PossibleValues",
    "RawStorageProvider",
    "UpdatePolicy",
]
