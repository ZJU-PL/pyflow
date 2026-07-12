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
        # ── constructors returning new objects ──
        "copy": CALL_RETURN_COPY,
        "copy.copy": CALL_RETURN_COPY,
        "copy.deepcopy": CALL_RETURN_COPY,
        "dataclasses.replace": CALL_RETURN_COPY,
        "list": CALL_RETURN_COPY,
        "tuple": CALL_RETURN_COPY,
        "set": CALL_RETURN_COPY,
        "dict": CALL_RETURN_COPY,
        "frozenset": CALL_RETURN_COPY,
        "builtins.list": CALL_RETURN_COPY,
        "builtins.tuple": CALL_RETURN_COPY,
        "builtins.set": CALL_RETURN_COPY,
        "builtins.dict": CALL_RETURN_COPY,
        "builtins.frozenset": CALL_RETURN_COPY,
        "bytes": CALL_RETURN_COPY,
        "builtins.bytes": CALL_RETURN_COPY,
        # ── containers / collections ──
        "bytearray": CALL_RETURN_FRESH,
        "builtins.bytearray": CALL_RETURN_FRESH,
        "range": CALL_RETURN_FRESH,
        "builtins.range": CALL_RETURN_FRESH,
        "collections.defaultdict": CALL_RETURN_FRESH,
        "collections.Counter": CALL_RETURN_FRESH,
        "collections.OrderedDict": CALL_RETURN_FRESH,
        "collections.deque": CALL_RETURN_FRESH,
        "collections.namedtuple": CALL_RETURN_FRESH,
        "collections.ChainMap": CALL_RETURN_FRESH,
        "collections.UserDict": CALL_RETURN_FRESH,
        "collections.UserList": CALL_RETURN_FRESH,
        "collections.UserString": CALL_RETURN_FRESH,
        # ── container copy methods ──
        "dict.copy": CALL_RETURN_COPY,
        "list.copy": CALL_RETURN_COPY,
        "set.copy": CALL_RETURN_COPY,
        # ── dict view methods ──
        "keys": CALL_RETURN_FRESH,
        "values": CALL_RETURN_FRESH,
        "items": CALL_RETURN_FRESH,
        # ── builtin functions returning fresh ──
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
        "dataclasses.field": CALL_RETURN_FRESH,
        # ── itertools ──
        "itertools.chain": CALL_RETURN_FRESH,
        "itertools.count": CALL_RETURN_FRESH,
        "itertools.cycle": CALL_RETURN_FRESH,
        "itertools.repeat": CALL_RETURN_FRESH,
        "itertools.product": CALL_RETURN_FRESH,
        "itertools.permutations": CALL_RETURN_FRESH,
        "itertools.combinations": CALL_RETURN_FRESH,
        "itertools.islice": CALL_RETURN_FRESH,
        "itertools.groupby": CALL_RETURN_FRESH,
        "itertools.accumulate": CALL_RETURN_FRESH,
        "itertools.compress": CALL_RETURN_FRESH,
        "itertools.dropwhile": CALL_RETURN_FRESH,
        "itertools.takewhile": CALL_RETURN_FRESH,
        "itertools.filterfalse": CALL_RETURN_FRESH,
        "itertools.starmap": CALL_RETURN_FRESH,
        # ── string methods returning fresh ──
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
        "swapcase": CALL_RETURN_FRESH,
        "translate": CALL_RETURN_FRESH,
        "zfill": CALL_RETURN_FRESH,
        "center": CALL_RETURN_FRESH,
        "ljust": CALL_RETURN_FRESH,
        "rjust": CALL_RETURN_FRESH,
        "partition": CALL_RETURN_FRESH,
        "rpartition": CALL_RETURN_FRESH,
        "expandtabs": CALL_RETURN_FRESH,
        # ── string inspection methods (return bool/int — immutable, no heap effect needed
        #     but classifying as fresh helps tracking) ──
        "startswith": CALL_RETURN_FRESH,
        "endswith": CALL_RETURN_FRESH,
        "find": CALL_RETURN_FRESH,
        "rfind": CALL_RETURN_FRESH,
        "index": CALL_RETURN_FRESH,
        "rindex": CALL_RETURN_FRESH,
        "count": CALL_RETURN_FRESH,
        # ── serialization ──
        "json.loads": CALL_RETURN_FRESH,
        "json.dumps": CALL_RETURN_FRESH,
        "json.load": CALL_RETURN_FRESH,
        "json.dump": CALL_RETURN_COPY,  # writes to file, returns None
        # ── path operations ──
        "os.path.join": CALL_RETURN_FRESH,
        "os.path.abspath": CALL_RETURN_FRESH,
        "os.path.dirname": CALL_RETURN_FRESH,
        "os.path.basename": CALL_RETURN_FRESH,
        "os.path.normpath": CALL_RETURN_FRESH,
        "os.path.splitext": CALL_RETURN_FRESH,
        "pathlib.Path": CALL_RETURN_FRESH,
        # ── misc stdlib ──
        "re.compile": CALL_RETURN_FRESH,
        "re.match": CALL_RETURN_FRESH,
        "re.search": CALL_RETURN_FRESH,
        "re.findall": CALL_RETURN_FRESH,
        "re.sub": CALL_RETURN_FRESH,
        "math.ceil": CALL_RETURN_FRESH,
        "math.floor": CALL_RETURN_FRESH,
        "math.sqrt": CALL_RETURN_FRESH,
        "random.choice": CALL_RETURN_FRESH,
        "random.sample": CALL_RETURN_FRESH,
        "random.randint": CALL_RETURN_FRESH,
        "datetime.datetime.now": CALL_RETURN_FRESH,
        "datetime.datetime.utcnow": CALL_RETURN_FRESH,
        "datetime.datetime.fromtimestamp": CALL_RETURN_FRESH,
    },
    collection_mutators={
        # ── value-inserting mutators ──
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
        # ── deleting mutators ──
        "clear": CollectionMutatorModel(deletes_value=True),
        "pop": CollectionMutatorModel(deletes_value=True, key_arg_index=0),
        "popleft": CollectionMutatorModel(deletes_value=True),
        "popitem": CollectionMutatorModel(deletes_value=True),
        "remove": CollectionMutatorModel(deletes_value=True),
        "discard": CollectionMutatorModel(deletes_value=True),
        # ── in-place reordering mutators (no value track, but escape existing elements) ──
        "sort": CollectionMutatorModel(deletes_value=True),
        "reverse": CollectionMutatorModel(deletes_value=True),
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
