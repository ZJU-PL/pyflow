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
        "sorted": CALL_RETURN_FRESH,
        "builtins.sorted": CALL_RETURN_FRESH,
        "reversed": CALL_RETURN_FRESH,
        "builtins.reversed": CALL_RETURN_FRESH,
        "zip": CALL_RETURN_FRESH,
        "builtins.zip": CALL_RETURN_FRESH,
        "enumerate": CALL_RETURN_FRESH,
        "builtins.enumerate": CALL_RETURN_FRESH,
        "filter": CALL_RETURN_FRESH,
        "builtins.filter": CALL_RETURN_FRESH,
        "map": CALL_RETURN_FRESH,
        "builtins.map": CALL_RETURN_FRESH,
        "functools.partial": CALL_RETURN_FRESH,
        "itertools.chain": CALL_RETURN_FRESH,
        "itertools.count": CALL_RETURN_FRESH,
        "itertools.cycle": CALL_RETURN_FRESH,
        "itertools.repeat": CALL_RETURN_FRESH,
        "itertools.product": CALL_RETURN_FRESH,
        "itertools.permutations": CALL_RETURN_FRESH,
        "itertools.combinations": CALL_RETURN_FRESH,
        "collections.defaultdict": CALL_RETURN_FRESH,
        "collections.Counter": CALL_RETURN_FRESH,
        "collections.OrderedDict": CALL_RETURN_FRESH,
        "collections.deque": CALL_RETURN_FRESH,
        "dataclasses.field": CALL_RETURN_FRESH,
        "bytes": CALL_RETURN_COPY,
        "builtins.bytes": CALL_RETURN_COPY,
        "bytearray": CALL_RETURN_FRESH,
        "builtins.bytearray": CALL_RETURN_FRESH,
        "split": CALL_RETURN_FRESH,
        "rsplit": CALL_RETURN_FRESH,
        "splitlines": CALL_RETURN_FRESH,
        "join": CALL_RETURN_FRESH,
        "format": CALL_RETURN_FRESH,
        "encode": CALL_RETURN_FRESH,
        "decode": CALL_RETURN_FRESH,
        "replace": CALL_RETURN_FRESH,
        "removeprefix": CALL_RETURN_FRESH,
        "removesuffix": CALL_RETURN_FRESH,
        "strip": CALL_RETURN_FRESH,
        "lstrip": CALL_RETURN_FRESH,
        "rstrip": CALL_RETURN_FRESH,
        "lower": CALL_RETURN_FRESH,
        "upper": CALL_RETURN_FRESH,
        "casefold": CALL_RETURN_FRESH,
        "capitalize": CALL_RETURN_FRESH,
        "title": CALL_RETURN_FRESH,
        "translate": CALL_RETURN_FRESH,
        "zfill": CALL_RETURN_FRESH,
        "center": CALL_RETURN_FRESH,
        "ljust": CALL_RETURN_FRESH,
        "rjust": CALL_RETURN_FRESH,
        "partition": CALL_RETURN_FRESH,
        "rpartition": CALL_RETURN_FRESH,
    },
    collection_mutators={
        "append": CollectionMutatorModel(writes_value=True),
        "appendleft": CollectionMutatorModel(writes_value=True),
        "add": CollectionMutatorModel(writes_value=True),
        "extend": CollectionMutatorModel(writes_value=True),
        "extendleft": CollectionMutatorModel(writes_value=True),
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
        "popleft": CollectionMutatorModel(deletes_value=True),
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
