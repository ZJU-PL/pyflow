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

from .domain.abstraction import (
    HeapAbstraction,
    HeapEnvironment,
)

from .semantics.effects import (
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

from .semantics.intrinsics import (
    CollectionMutatorModel,
    DEFAULT_HEAP_INTRINSICS,
    HeapIntrinsicModels,
)

from .domain.state import HeapState

from .domain.summary import (
    HeapSummary,
    HeapSummaryBuilder,
    ProcedureHeapSummary,
)

from .domain.points_to import (
    HeapValueSnapshot,
    PossibleValues,
    PointsToEntry,
    PointsToGraph,
)

from .heap_analysis import (
    HeapAnalysis,
)

from .transfer import HeapTransferEngine


# Preserve the historical module paths while keeping implementation files in
# responsibility-focused subpackages.
import sys as _sys

from .domain import abstraction as _abstraction_module
from .domain import points_to as _points_to_module
from .domain import state as _state_module
from .domain import summary as _summary_module
from .semantics import effects as _effects_module
from .semantics import intrinsics as _intrinsics_module

_LEGACY_MODULES = {
    "abstraction": _abstraction_module,
    "heap_effects": _effects_module,
    "heap_state": _state_module,
    "heap_summary": _summary_module,
    "intrinsics": _intrinsics_module,
    "points_to_graph": _points_to_module,
}
for _legacy_name, _legacy_module in _LEGACY_MODULES.items():
    _sys.modules[f"{__name__}.{_legacy_name}"] = _legacy_module
    globals()[_legacy_name] = _legacy_module

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
