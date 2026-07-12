"""Built-in heap behavior models.

The tables here are intentionally small and heap-owned.  They describe common
Python calls in terms of allocation/copy behavior and collection mutation
shape without depending on older lifetime/storegraph analyses.
"""

from __future__ import annotations

from dataclasses import dataclass, field


CALL_RETURN_FRESH = "fresh"
CALL_RETURN_COPY = "copy"
CALL_RETURN_SUMMARY = "summary"
CALL_RETURN_OPAQUE = "opaque"


@dataclass(frozen=True)
class CollectionMutatorModel:
    """Behavior for a collection-mutating call."""

    writes_value: bool = False
    deletes_value: bool = False
    value_arg_indices: tuple[int, ...] | None = None
    key_arg_index: int | None = None

    def value_args(self, actuals: tuple[object, ...]) -> tuple[object, ...]:
        if not self.writes_value:
            return ()
        if self.value_arg_indices is None:
            return actuals
        return tuple(
            actuals[index] for index in self.value_arg_indices if index < len(actuals)
        )


@dataclass(frozen=True)
class HeapIntrinsicModels:
    """Heap-owned intrinsic call behavior table."""

    return_kinds: dict[str, str] = field(default_factory=dict)
    collection_mutators: dict[str, CollectionMutatorModel] = field(default_factory=dict)

    def return_kind(self, name: str | None) -> str | None:
        if name is None:
            return None
        return self.return_kinds.get(name)

    def collection_mutator(self, name: str | None) -> CollectionMutatorModel | None:
        if name is None:
            return None
        return self.collection_mutators.get(name)

    def collection_mutator_names(self) -> frozenset[str]:
        return frozenset(self.collection_mutators)


DEFAULT_HEAP_INTRINSICS = HeapIntrinsicModels(
    return_kinds={
        "copy": CALL_RETURN_COPY,
        "copy.copy": CALL_RETURN_COPY,
        "copy.deepcopy": CALL_RETURN_COPY,
        "dataclasses.replace": CALL_RETURN_COPY,
        "list": CALL_RETURN_COPY,
        "tuple": CALL_RETURN_COPY,
        "set": CALL_RETURN_COPY,
        "dict": CALL_RETURN_COPY,
        "builtins.list": CALL_RETURN_COPY,
        "builtins.tuple": CALL_RETURN_COPY,
        "builtins.set": CALL_RETURN_COPY,
        "builtins.dict": CALL_RETURN_COPY,
    },
    collection_mutators={
        "append": CollectionMutatorModel(writes_value=True),
        "add": CollectionMutatorModel(writes_value=True),
        "extend": CollectionMutatorModel(writes_value=True),
        "update": CollectionMutatorModel(writes_value=True),
        "insert": CollectionMutatorModel(
            writes_value=True,
            value_arg_indices=(1,),
        ),
        "setdefault": CollectionMutatorModel(
            writes_value=True,
            value_arg_indices=(1,),
            key_arg_index=0,
        ),
        "clear": CollectionMutatorModel(deletes_value=True),
        "pop": CollectionMutatorModel(deletes_value=True, key_arg_index=0),
        "remove": CollectionMutatorModel(deletes_value=True),
        "discard": CollectionMutatorModel(deletes_value=True),
    },
)


COLLECTION_VALUE_MUTATOR_NAMES = frozenset(
    name
    for name, model in DEFAULT_HEAP_INTRINSICS.collection_mutators.items()
    if model.writes_value
)
COLLECTION_DELETE_MUTATOR_NAMES = frozenset(
    name
    for name, model in DEFAULT_HEAP_INTRINSICS.collection_mutators.items()
    if model.deletes_value
)
DEFAULT_COLLECTION_MUTATOR_NAMES = DEFAULT_HEAP_INTRINSICS.collection_mutator_names()
