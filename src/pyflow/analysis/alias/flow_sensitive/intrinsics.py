"""Built-in heap behavior models for alias analysis.

The tables describe common Python calls in terms of return-value kind,
argument read/write effects, and collection mutation shape.  They let
the analysis resolve call semantics without computing a full summary.

Each model is a frozen dataclass so that default instances can be shared
safely across analysis contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════════════
# Return-kind constants
# ═══════════════════════════════════════════════════════════════════════

CALL_RETURN_FRESH = "fresh"
"""Return value is a *new allocation* that does not alias any live location."""

CALL_RETURN_COPY = "copy"
"""Return value is a *new allocation* (shallow copy of inputs).

Treated identically to FRESH in the flow-sensitive heap analysis today.  The distinction
is reserved for copy-elision / escape reasoning.
"""

CALL_RETURN_SUMMARY = "summary"
"""Return value should be resolved via the callee's computed summary.

The analysis will compute (or replay) a call summary to determine the
return's heap locations.
"""

CALL_RETURN_OPAQUE = "opaque"
"""Return semantics are unknown.

The analysis conservatively creates a fresh *call-result* object that may
alias any live location.
"""

CALL_RETURN_NONE = "none"
"""Return value is statically ``None``.

The caller never needs to bind heap locations for the return target.
"""

CALL_RETURN_SELF = "self"
"""Return value is the *receiver* of a method call.

The return target aliases the receiver's locations.  Example:
``context_manager.__enter__()`` returns the manager itself.
"""

CALL_RETURN_ARG = "arg"
"""Return value is one of the call's *arguments*.

Use ``FunctionModel.return_arg_index`` to specify which argument.
Convention: ``-1`` means "any argument (conservative)".
"""


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class CollectionMutatorModel:
    """Behavior for a collection-mutating call.

    Parameters
    ----------
    writes_value:
        Whether the call writes a value into the container.
    deletes_value:
        Whether the call deletes a value from the container.
    reorders_values:
        Whether existing values may move to different indices/keys without
        being added or removed.
    value_arg_indices:
        Indices within *actuals* that contain the value being written.
        ``None`` means "all arguments are values" (e.g. ``extend``).
    key_arg_index:
        Index within *actuals* of the key/subscript being written/deleted.
    """

    writes_value: bool = False
    deletes_value: bool = False
    reorders_values: bool = False
    value_arg_indices: tuple[int, ...] | None = None
    key_arg_index: int | None = None

    def value_args(self, actuals: tuple[object, ...]) -> tuple[object, ...]:
        """Return the argument expressions that carry written values."""
        if not self.writes_value:
            return ()
        if self.value_arg_indices is None:
            return actuals
        return tuple(
            actuals[index] for index in self.value_arg_indices if index < len(actuals)
        )


@dataclass(frozen=True)
class FunctionModel:
    """Fine-grained behaviour model for an arbitrary function or method.

    Unlike the flat ``return_kind`` table, this lets callers model
    argument-level read/write/escape effects and precise return-value
    aliasing (e.g. "returns self" or "returns arg[0]").

    All fields default to the most conservative setting (``OPAQUE``,
    no reads, no writes, no escape) so that partial models are safe.

    Parameters
    ----------
    return_kind:
        How the return value relates to live locations.
    return_arg_index:
        For ``CALL_RETURN_ARG`` — which argument index is returned.
        ``None`` (or ``CALL_RETURN_OPAQUE``) selects the default.
    returns_self:
        Whether the receiver (``self``) is returned by a method call.
    reads_self:
        Whether the receiver is read during the call.
    mutates_self:
        Whether the receiver is mutated during the call.
    escapes_self:
        Whether the receiver is stored to the (global) heap.
    read_arg_indices:
        Positions of call arguments that are read.
        An empty tuple means "no argument is read".
    write_arg_indices:
        Positions of call arguments that are written.
    escape_arg_indices:
        Positions of call arguments that are stored to the heap
        (and therefore escape).
    """

    # ── return-value behaviour ────────────────────────────────────────
    return_kind: str = CALL_RETURN_OPAQUE
    return_arg_index: int | None = None

    # ── receiver (self) effects ───────────────────────────────────────
    returns_self: bool = False
    reads_self: bool = False
    mutates_self: bool = False
    escapes_self: bool = False

    # ── argument effects ──────────────────────────────────────────────
    read_arg_indices: tuple[int, ...] = ()
    write_arg_indices: tuple[int, ...] = ()
    escape_arg_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class HeapIntrinsicModels:
    """Heap-owned intrinsic call behaviour table.

    Three tiers of modelling are supported:

    1. ``return_kinds`` — flat name→kind mapping (legacy).
    2. ``collection_mutators`` — mutator shape for common methods.
    3. ``function_models`` — detailed arg/self/return models (preferred).

    Lookups check ``function_models`` first, then fall back to
    ``return_kinds`` and ``collection_mutators``, so all three dicts can
    coexist without conflicts.
    """

    return_kinds: dict[str, str] = field(default_factory=dict)
    collection_mutators: dict[str, CollectionMutatorModel] = field(
        default_factory=dict
    )
    function_models: dict[str, FunctionModel] = field(default_factory=dict)

    # ── return-kind lookup ────────────────────────────────────────────

    def return_kind(self, name: str | None) -> str | None:
        """Resolve a call's return kind by qualified name.

        Checks ``function_models`` first (more precise), then falls back
        to the legacy ``return_kinds`` table.  Returns ``None`` when the
        name is unknown.
        """
        if name is None:
            return None
        model = self.function_models.get(name)
        if model is not None:
            return model.return_kind
        return self.return_kinds.get(name)

    def function_model(self, name: str | None) -> FunctionModel | None:
        """Return the detailed ``FunctionModel`` for *name*, or ``None``."""
        if name is None:
            return None
        return self.function_models.get(name)

    # ── collection-mutator lookup ─────────────────────────────────────

    def collection_mutator(
        self, name: str | None
    ) -> CollectionMutatorModel | None:
        """Resolve a method name to its ``CollectionMutatorModel``."""
        if name is None:
            return None
        return self.collection_mutators.get(name)

    def collection_mutator_names(self) -> frozenset[str]:
        """All method names that have a known collection-mutator model."""
        return frozenset(self.collection_mutators)

    # ── convenience ───────────────────────────────────────────────────

    def all_return_names(self) -> frozenset[str]:
        """Every name with a known return kind (either model or legacy)."""
        return frozenset(self.return_kinds) | frozenset(self.function_models)


# ═══════════════════════════════════════════════════════════════════════
# Default model table
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_HEAP_INTRINSICS = HeapIntrinsicModels(
    return_kinds={
        # ── type constructors returning *copies* of their input ────────
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
        "interpreter_slice_copy": CALL_RETURN_COPY,
        "interpreter_build_map": CALL_RETURN_COPY,
        "interpreter_merge_varargs": CALL_RETURN_COPY,
        "interpreter_merge_kwargs": CALL_RETURN_COPY,
        "interpreter_make_generator": CALL_RETURN_COPY,
        "bytes": CALL_RETURN_COPY,
        "builtins.bytes": CALL_RETURN_COPY,
        "str": CALL_RETURN_FRESH,
        "builtins.str": CALL_RETURN_FRESH,
        "int": CALL_RETURN_FRESH,
        "builtins.int": CALL_RETURN_FRESH,
        "float": CALL_RETURN_FRESH,
        "builtins.float": CALL_RETURN_FRESH,
        "bool": CALL_RETURN_FRESH,
        "builtins.bool": CALL_RETURN_FRESH,
        "complex": CALL_RETURN_FRESH,
        "builtins.complex": CALL_RETURN_FRESH,
        "slice": CALL_RETURN_FRESH,
        "builtins.slice": CALL_RETURN_FRESH,
        # ── copy module ────────────────────────────────────────────────
        "copy": CALL_RETURN_COPY,
        "copy.copy": CALL_RETURN_COPY,
        "copy.deepcopy": CALL_RETURN_COPY,
        # ── dataclasses ────────────────────────────────────────────────
        "dataclasses.replace": CALL_RETURN_COPY,
        "dataclasses.field": CALL_RETURN_FRESH,
        # ── containers that allocate fresh storage ─────────────────────
        "bytearray": CALL_RETURN_FRESH,
        "builtins.bytearray": CALL_RETURN_FRESH,
        "memoryview": CALL_RETURN_COPY,
        "builtins.memoryview": CALL_RETURN_COPY,
        "range": CALL_RETURN_FRESH,
        "builtins.range": CALL_RETURN_FRESH,
        "collections.defaultdict": CALL_RETURN_COPY,
        "collections.Counter": CALL_RETURN_COPY,
        "collections.OrderedDict": CALL_RETURN_COPY,
        "collections.deque": CALL_RETURN_COPY,
        "collections.namedtuple": CALL_RETURN_FRESH,
        "collections.ChainMap": CALL_RETURN_COPY,
        "collections.UserDict": CALL_RETURN_COPY,
        "collections.UserList": CALL_RETURN_COPY,
        "collections.UserString": CALL_RETURN_COPY,
        "queue.Queue": CALL_RETURN_FRESH,
        "queue.LifoQueue": CALL_RETURN_FRESH,
        "queue.PriorityQueue": CALL_RETURN_FRESH,
        "queue.SimpleQueue": CALL_RETURN_FRESH,
        "heapq.heapify": CALL_RETURN_NONE,
        # ── container copy methods ─────────────────────────────────────
        "dict.copy": CALL_RETURN_COPY,
        "list.copy": CALL_RETURN_COPY,
        "set.copy": CALL_RETURN_COPY,
        # ── dict view methods ──────────────────────────────────────────
        "keys": CALL_RETURN_COPY,
        "values": CALL_RETURN_COPY,
        "items": CALL_RETURN_COPY,
        # ── builtin iterator-like constructors ─────────────────────────
        "sorted": CALL_RETURN_COPY,
        "builtins.sorted": CALL_RETURN_COPY,
        "reversed": CALL_RETURN_FRESH,
        "builtins.reversed": CALL_RETURN_FRESH,
        "zip": CALL_RETURN_COPY,
        "builtins.zip": CALL_RETURN_COPY,
        "enumerate": CALL_RETURN_COPY,
        "builtins.enumerate": CALL_RETURN_COPY,
        "filter": CALL_RETURN_COPY,
        "builtins.filter": CALL_RETURN_COPY,
        "map": CALL_RETURN_COPY,
        "builtins.map": CALL_RETURN_COPY,
        "iter": CALL_RETURN_FRESH,
        "builtins.iter": CALL_RETURN_FRESH,
        "all": CALL_RETURN_FRESH,
        "builtins.all": CALL_RETURN_FRESH,
        "any": CALL_RETURN_FRESH,
        "builtins.any": CALL_RETURN_FRESH,
        "sum": CALL_RETURN_FRESH,
        "builtins.sum": CALL_RETURN_FRESH,
        "len": CALL_RETURN_FRESH,
        "builtins.len": CALL_RETURN_FRESH,
        "abs": CALL_RETURN_FRESH,
        "builtins.abs": CALL_RETURN_FRESH,
        "pow": CALL_RETURN_FRESH,
        "builtins.pow": CALL_RETURN_FRESH,
        "round": CALL_RETURN_FRESH,
        "builtins.round": CALL_RETURN_FRESH,
        "divmod": CALL_RETURN_FRESH,
        "builtins.divmod": CALL_RETURN_FRESH,
        "ord": CALL_RETURN_FRESH,
        "builtins.ord": CALL_RETURN_FRESH,
        "chr": CALL_RETURN_FRESH,
        "builtins.chr": CALL_RETURN_FRESH,
        "repr": CALL_RETURN_FRESH,
        "builtins.repr": CALL_RETURN_FRESH,
        "ascii": CALL_RETURN_FRESH,
        "builtins.ascii": CALL_RETURN_FRESH,
        "hash": CALL_RETURN_FRESH,
        "builtins.hash": CALL_RETURN_FRESH,
        "id": CALL_RETURN_FRESH,
        "builtins.id": CALL_RETURN_FRESH,
        "type": CALL_RETURN_FRESH,
        "builtins.type": CALL_RETURN_FRESH,
        "isinstance": CALL_RETURN_FRESH,
        "builtins.isinstance": CALL_RETURN_FRESH,
        "issubclass": CALL_RETURN_FRESH,
        "builtins.issubclass": CALL_RETURN_FRESH,
        "callable": CALL_RETURN_FRESH,
        "builtins.callable": CALL_RETURN_FRESH,
        "hasattr": CALL_RETURN_FRESH,
        "builtins.hasattr": CALL_RETURN_FRESH,
        "open": CALL_RETURN_FRESH,
        "builtins.open": CALL_RETURN_FRESH,
        "input": CALL_RETURN_FRESH,
        "builtins.input": CALL_RETURN_FRESH,
        "exit": CALL_RETURN_NONE,
        "builtins.exit": CALL_RETURN_NONE,
        "print": CALL_RETURN_NONE,
        "builtins.print": CALL_RETURN_NONE,
        # ── in-place mutation APIs returning None ─────────────────────
        "append": CALL_RETURN_NONE,
        "appendleft": CALL_RETURN_NONE,
        "add": CALL_RETURN_NONE,
        "extend": CALL_RETURN_NONE,
        "extendleft": CALL_RETURN_NONE,
        "update": CALL_RETURN_NONE,
        "insert": CALL_RETURN_NONE,
        "push": CALL_RETURN_NONE,
        "enqueue": CALL_RETURN_NONE,
        "put": CALL_RETURN_NONE,
        "offer": CALL_RETURN_NONE,
        "symmetric_difference_update": CALL_RETURN_NONE,
        "intersection_update": CALL_RETURN_NONE,
        "difference_update": CALL_RETURN_NONE,
        "clear": CALL_RETURN_NONE,
        "remove": CALL_RETURN_NONE,
        "discard": CALL_RETURN_NONE,
        "sort": CALL_RETURN_NONE,
        "reverse": CALL_RETURN_NONE,
        "rotate": CALL_RETURN_NONE,
        "shuffle": CALL_RETURN_NONE,
        "setattr": CALL_RETURN_NONE,
        "builtins.setattr": CALL_RETURN_NONE,
        "delattr": CALL_RETURN_NONE,
        "builtins.delattr": CALL_RETURN_NONE,
        "__setitem__": CALL_RETURN_NONE,
        "__delitem__": CALL_RETURN_NONE,
        "interpreter_setitem": CALL_RETURN_NONE,
        "interpreter_delitem": CALL_RETURN_NONE,
        "interpreter_list_append": CALL_RETURN_NONE,
        "interpreter_set_add": CALL_RETURN_NONE,
        "copy": CALL_RETURN_COPY,
        # ── functools ──────────────────────────────────────────────────
        "functools.partial": CALL_RETURN_COPY,
        "functools.lru_cache": CALL_RETURN_COPY,
        "functools.cached_property": CALL_RETURN_COPY,
        "functools.reduce": CALL_RETURN_FRESH,
        "functools.singledispatch": CALL_RETURN_COPY,
        "functools.wraps": CALL_RETURN_COPY,
        # ── itertools ──────────────────────────────────────────────────
        "itertools.chain": CALL_RETURN_COPY,
        "itertools.count": CALL_RETURN_FRESH,
        "itertools.cycle": CALL_RETURN_COPY,
        "itertools.repeat": CALL_RETURN_COPY,
        "itertools.product": CALL_RETURN_COPY,
        "itertools.permutations": CALL_RETURN_COPY,
        "itertools.combinations": CALL_RETURN_COPY,
        "itertools.combinations_with_replacement": CALL_RETURN_COPY,
        "itertools.islice": CALL_RETURN_COPY,
        "itertools.groupby": CALL_RETURN_COPY,
        "itertools.accumulate": CALL_RETURN_COPY,
        "itertools.compress": CALL_RETURN_COPY,
        "itertools.dropwhile": CALL_RETURN_COPY,
        "itertools.takewhile": CALL_RETURN_COPY,
        "itertools.filterfalse": CALL_RETURN_COPY,
        "itertools.starmap": CALL_RETURN_COPY,
        "itertools.pairwise": CALL_RETURN_COPY,
        "itertools.batched": CALL_RETURN_COPY,
        "itertools.tee": CALL_RETURN_COPY,
        # ── string methods returning fresh values ──────────────────────
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
        "maketrans": CALL_RETURN_FRESH,
        # ── string inspection (return scalars — no heap effect needed) ─
        "startswith": CALL_RETURN_FRESH,
        "endswith": CALL_RETURN_FRESH,
        "find": CALL_RETURN_FRESH,
        "rfind": CALL_RETURN_FRESH,
        "index": CALL_RETURN_FRESH,
        "rindex": CALL_RETURN_FRESH,
        "count": CALL_RETURN_FRESH,
        "isalnum": CALL_RETURN_FRESH,
        "isalpha": CALL_RETURN_FRESH,
        "isascii": CALL_RETURN_FRESH,
        "isdecimal": CALL_RETURN_FRESH,
        "isdigit": CALL_RETURN_FRESH,
        "isidentifier": CALL_RETURN_FRESH,
        "islower": CALL_RETURN_FRESH,
        "isnumeric": CALL_RETURN_FRESH,
        "isprintable": CALL_RETURN_FRESH,
        "isspace": CALL_RETURN_FRESH,
        "istitle": CALL_RETURN_FRESH,
        "isupper": CALL_RETURN_FRESH,
        # ── serialization ──────────────────────────────────────────────
        "json.loads": CALL_RETURN_FRESH,
        "json.dumps": CALL_RETURN_FRESH,
        "json.load": CALL_RETURN_FRESH,
        "json.dump": CALL_RETURN_NONE,
        "json.JSONEncoder": CALL_RETURN_FRESH,
        "json.JSONDecoder": CALL_RETURN_FRESH,
        "pickle.loads": CALL_RETURN_FRESH,
        "pickle.dumps": CALL_RETURN_FRESH,
        "pickle.load": CALL_RETURN_FRESH,
        "pickle.dump": CALL_RETURN_NONE,
        "csv.reader": CALL_RETURN_FRESH,
        "csv.writer": CALL_RETURN_FRESH,
        "csv.DictReader": CALL_RETURN_FRESH,
        "csv.DictWriter": CALL_RETURN_FRESH,
        # ── path / filesystem ──────────────────────────────────────────
        "os.path.join": CALL_RETURN_FRESH,
        "os.path.abspath": CALL_RETURN_FRESH,
        "os.path.dirname": CALL_RETURN_FRESH,
        "os.path.basename": CALL_RETURN_FRESH,
        "os.path.normpath": CALL_RETURN_FRESH,
        "os.path.splitext": CALL_RETURN_FRESH,
        "os.path.split": CALL_RETURN_FRESH,
        "os.path.splitdrive": CALL_RETURN_FRESH,
        "os.path.splitroot": CALL_RETURN_FRESH,
        "os.path.expanduser": CALL_RETURN_FRESH,
        "os.path.expandvars": CALL_RETURN_FRESH,
        "os.path.relpath": CALL_RETURN_FRESH,
        "os.path.realpath": CALL_RETURN_FRESH,
        "os.path.commonpath": CALL_RETURN_FRESH,
        "os.path.commonprefix": CALL_RETURN_FRESH,
        "os.getcwd": CALL_RETURN_FRESH,
        "os.listdir": CALL_RETURN_FRESH,
        "os.environ.get": CALL_RETURN_FRESH,
        "pathlib.Path": CALL_RETURN_FRESH,
        "pathlib.PurePath": CALL_RETURN_FRESH,
        "pathlib.PosixPath": CALL_RETURN_FRESH,
        "pathlib.WindowsPath": CALL_RETURN_FRESH,
        "pathlib.PurePosixPath": CALL_RETURN_FRESH,
        "pathlib.PureWindowsPath": CALL_RETURN_FRESH,
        "glob.glob": CALL_RETURN_FRESH,
        "glob.iglob": CALL_RETURN_FRESH,
        "shutil.copy": CALL_RETURN_FRESH,
        "shutil.copytree": CALL_RETURN_FRESH,
        "shutil.move": CALL_RETURN_FRESH,
        "shutil.make_archive": CALL_RETURN_FRESH,
        "tempfile.NamedTemporaryFile": CALL_RETURN_FRESH,
        "tempfile.TemporaryDirectory": CALL_RETURN_FRESH,
        "tempfile.mkstemp": CALL_RETURN_FRESH,
        "tempfile.mkdtemp": CALL_RETURN_FRESH,
        # ── re (regular expressions) ───────────────────────────────────
        "re.compile": CALL_RETURN_FRESH,
        "re.match": CALL_RETURN_FRESH,
        "re.search": CALL_RETURN_FRESH,
        "re.fullmatch": CALL_RETURN_FRESH,
        "re.findall": CALL_RETURN_FRESH,
        "re.finditer": CALL_RETURN_FRESH,
        "re.sub": CALL_RETURN_FRESH,
        "re.subn": CALL_RETURN_FRESH,
        "re.split": CALL_RETURN_FRESH,
        "re.escape": CALL_RETURN_FRESH,
        # ── math ───────────────────────────────────────────────────────
        "math.ceil": CALL_RETURN_FRESH,
        "math.floor": CALL_RETURN_FRESH,
        "math.trunc": CALL_RETURN_FRESH,
        "math.sqrt": CALL_RETURN_FRESH,
        "math.isqrt": CALL_RETURN_FRESH,
        "math.exp": CALL_RETURN_FRESH,
        "math.log": CALL_RETURN_FRESH,
        "math.log10": CALL_RETURN_FRESH,
        "math.log2": CALL_RETURN_FRESH,
        "math.sin": CALL_RETURN_FRESH,
        "math.cos": CALL_RETURN_FRESH,
        "math.tan": CALL_RETURN_FRESH,
        "math.asin": CALL_RETURN_FRESH,
        "math.acos": CALL_RETURN_FRESH,
        "math.atan": CALL_RETURN_FRESH,
        "math.atan2": CALL_RETURN_FRESH,
        "math.hypot": CALL_RETURN_FRESH,
        "math.degrees": CALL_RETURN_FRESH,
        "math.radians": CALL_RETURN_FRESH,
        "math.factorial": CALL_RETURN_FRESH,
        "math.gcd": CALL_RETURN_FRESH,
        "math.lcm": CALL_RETURN_FRESH,
        "math.comb": CALL_RETURN_FRESH,
        "math.perm": CALL_RETURN_FRESH,
        "math.prod": CALL_RETURN_FRESH,
        "math.fsum": CALL_RETURN_FRESH,
        "math.dist": CALL_RETURN_FRESH,
        "math.nextafter": CALL_RETURN_FRESH,
        "math.ulp": CALL_RETURN_FRESH,
        # ── random ─────────────────────────────────────────────────────
        "random.random": CALL_RETURN_FRESH,
        "random.uniform": CALL_RETURN_FRESH,
        "random.randint": CALL_RETURN_FRESH,
        "random.randrange": CALL_RETURN_FRESH,
        "random.choice": CALL_RETURN_FRESH,
        "random.choices": CALL_RETURN_COPY,
        "random.sample": CALL_RETURN_COPY,
        "random.shuffle": CALL_RETURN_NONE,
        "random.seed": CALL_RETURN_NONE,
        "random.getrandbits": CALL_RETURN_FRESH,
        "random.gauss": CALL_RETURN_FRESH,
        "random.expovariate": CALL_RETURN_FRESH,
        # ── statistics ─────────────────────────────────────────────────
        "statistics.mean": CALL_RETURN_FRESH,
        "statistics.median": CALL_RETURN_FRESH,
        "statistics.mode": CALL_RETURN_FRESH,
        "statistics.stdev": CALL_RETURN_FRESH,
        "statistics.variance": CALL_RETURN_FRESH,
        # ── datetime ───────────────────────────────────────────────────
        "datetime.datetime.now": CALL_RETURN_FRESH,
        "datetime.datetime.utcnow": CALL_RETURN_FRESH,
        "datetime.datetime.fromtimestamp": CALL_RETURN_FRESH,
        "datetime.datetime.fromisoformat": CALL_RETURN_FRESH,
        "datetime.datetime.fromordinal": CALL_RETURN_FRESH,
        "datetime.datetime.combine": CALL_RETURN_FRESH,
        "datetime.datetime.strptime": CALL_RETURN_FRESH,
        "datetime.date.today": CALL_RETURN_FRESH,
        "datetime.date.fromtimestamp": CALL_RETURN_FRESH,
        "datetime.date.fromisoformat": CALL_RETURN_FRESH,
        "datetime.date.fromordinal": CALL_RETURN_FRESH,
        "datetime.time.fromisoformat": CALL_RETURN_FRESH,
        "datetime.timedelta": CALL_RETURN_FRESH,
        "datetime.timezone": CALL_RETURN_FRESH,
        # ── typing ─────────────────────────────────────────────────────
        "typing.TypeVar": CALL_RETURN_FRESH,
        "typing.Generic": CALL_RETURN_FRESH,
        "typing.NamedTuple": CALL_RETURN_FRESH,
        "typing.NewType": CALL_RETURN_FRESH,
        # ── io / stream helpers ────────────────────────────────────────
        "io.StringIO": CALL_RETURN_FRESH,
        "io.BytesIO": CALL_RETURN_FRESH,
        "io.open": CALL_RETURN_FRESH,
        # ── os / sys ───────────────────────────────────────────────────
        "os.getpid": CALL_RETURN_FRESH,
        "os.getppid": CALL_RETURN_FRESH,
        "os.cpu_count": CALL_RETURN_FRESH,
        "os.getlogin": CALL_RETURN_FRESH,
        "os.uname": CALL_RETURN_FRESH,
        "os.urandom": CALL_RETURN_FRESH,
        "sys.version": CALL_RETURN_FRESH,
        "sys.platform": CALL_RETURN_FRESH,
        "sys.executable": CALL_RETURN_FRESH,
        "sys.argv": CALL_RETURN_FRESH,
        "sys.path": CALL_RETURN_FRESH,
        "sys.modules": CALL_RETURN_FRESH,
        "sys.getsizeof": CALL_RETURN_FRESH,
        "sys.intern": CALL_RETURN_FRESH,
        # ── contextlib ─────────────────────────────────────────────────
        "contextlib.contextmanager": CALL_RETURN_FRESH,
        "contextlib.suppress": CALL_RETURN_FRESH,
        "contextlib.redirect_stdout": CALL_RETURN_FRESH,
        "contextlib.redirect_stderr": CALL_RETURN_FRESH,
        "contextlib.closing": CALL_RETURN_FRESH,
        "contextlib.nullcontext": CALL_RETURN_FRESH,
        "contextlib.ExitStack": CALL_RETURN_FRESH,
        # ── logging ────────────────────────────────────────────────────
        "logging.getLogger": CALL_RETURN_SUMMARY,
        "logging.FileHandler": CALL_RETURN_FRESH,
        "logging.StreamHandler": CALL_RETURN_FRESH,
        "logging.Formatter": CALL_RETURN_FRESH,
        "logging.info": CALL_RETURN_NONE,
        "logging.debug": CALL_RETURN_NONE,
        "logging.warning": CALL_RETURN_NONE,
        "logging.error": CALL_RETURN_NONE,
        "logging.critical": CALL_RETURN_NONE,
        # ── uuid ───────────────────────────────────────────────────────
        "uuid.uuid1": CALL_RETURN_FRESH,
        "uuid.uuid3": CALL_RETURN_FRESH,
        "uuid.uuid4": CALL_RETURN_FRESH,
        "uuid.uuid5": CALL_RETURN_FRESH,
        "uuid.UUID": CALL_RETURN_FRESH,
        # ── hashlib ────────────────────────────────────────────────────
        "hashlib.md5": CALL_RETURN_FRESH,
        "hashlib.sha1": CALL_RETURN_FRESH,
        "hashlib.sha256": CALL_RETURN_FRESH,
        "hashlib.sha512": CALL_RETURN_FRESH,
        "hashlib.new": CALL_RETURN_FRESH,
        # ── base64 ─────────────────────────────────────────────────────
        "base64.b64encode": CALL_RETURN_FRESH,
        "base64.b64decode": CALL_RETURN_FRESH,
        "base64.urlsafe_b64encode": CALL_RETURN_FRESH,
        "base64.urlsafe_b64decode": CALL_RETURN_FRESH,
        # ── subprocess ─────────────────────────────────────────────────
        "subprocess.run": CALL_RETURN_FRESH,
        "subprocess.Popen": CALL_RETURN_FRESH,
        "subprocess.check_output": CALL_RETURN_FRESH,
        "subprocess.check_call": CALL_RETURN_FRESH,
        # ── socket ─────────────────────────────────────────────────────
        "socket.socket": CALL_RETURN_FRESH,
        "socket.create_connection": CALL_RETURN_FRESH,
        "socket.gethostname": CALL_RETURN_FRESH,
        "socket.gethostbyname": CALL_RETURN_FRESH,
        # ── decimal / fractions ────────────────────────────────────────
        "decimal.Decimal": CALL_RETURN_FRESH,
        "decimal.getcontext": CALL_RETURN_SUMMARY,
        "fractions.Fraction": CALL_RETURN_FRESH,
        # ── enum ───────────────────────────────────────────────────────
        "enum.Enum": CALL_RETURN_FRESH,
        "enum.IntEnum": CALL_RETURN_FRESH,
        "enum.auto": CALL_RETURN_FRESH,
        # ── textwrap ───────────────────────────────────────────────────
        "textwrap.dedent": CALL_RETURN_FRESH,
        "textwrap.indent": CALL_RETURN_FRESH,
        "textwrap.shorten": CALL_RETURN_FRESH,
        "textwrap.wrap": CALL_RETURN_FRESH,
        "textwrap.fill": CALL_RETURN_FRESH,
        # ── pprint ────────────────────────────────────────────────────
        "pprint.pformat": CALL_RETURN_FRESH,
        "pprint.pprint": CALL_RETURN_NONE,
        # ── argparse ───────────────────────────────────────────────────
        "argparse.ArgumentParser": CALL_RETURN_FRESH,
        # ── configparser ───────────────────────────────────────────────
        "configparser.ConfigParser": CALL_RETURN_FRESH,
        # ── ast / inspect ──────────────────────────────────────────────
        "ast.parse": CALL_RETURN_FRESH,
        "ast.literal_eval": CALL_RETURN_FRESH,
        "inspect.signature": CALL_RETURN_FRESH,
        "inspect.getsource": CALL_RETURN_FRESH,
        "inspect.iscoroutinefunction": CALL_RETURN_FRESH,
        # ── importlib ──────────────────────────────────────────────────
        "importlib.import_module": CALL_RETURN_SUMMARY,
        # ── operator ───────────────────────────────────────────────────
        "operator.itemgetter": CALL_RETURN_FRESH,
        "operator.attrgetter": CALL_RETURN_FRESH,
        "operator.methodcaller": CALL_RETURN_FRESH,
    },
    function_models={
        # ── return one of the arguments ────────────────────────────────
        "max": FunctionModel(return_kind=CALL_RETURN_ARG, return_arg_index=-1),
        "builtins.max": FunctionModel(
            return_kind=CALL_RETURN_ARG, return_arg_index=-1
        ),
        "min": FunctionModel(return_kind=CALL_RETURN_ARG, return_arg_index=-1),
        "builtins.min": FunctionModel(
            return_kind=CALL_RETURN_ARG, return_arg_index=-1
        ),
        # next(it) → returns elements from the iterator
        "next": FunctionModel(return_kind=CALL_RETURN_ARG, return_arg_index=0),
        "builtins.next": FunctionModel(
            return_kind=CALL_RETURN_ARG, return_arg_index=0
        ),
        # getattr(obj, attr) → returns the attribute from obj
        "getattr": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        "builtins.getattr": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        "random.choice": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        # ── property-style access (conservative — returns from self) ───
        "dict.get": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            reads_self=True,
        ),
        "dict.setdefault": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            reads_self=True,
            mutates_self=True,
        ),
        "dict.pop": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            reads_self=True,
            mutates_self=True,
        ),
        "list.pop": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            reads_self=True,
            mutates_self=True,
        ),
        # ── context-manager __enter__ → returns self ───────────────────
        "__enter__": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            reads_self=True,
        ),
        "interpreter_enter": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            read_arg_indices=(0,),
        ),
        "interpreter_aenter": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            read_arg_indices=(0,),
        ),
        "__exit__": FunctionModel(return_kind=CALL_RETURN_NONE),
        # ── iteration protocol ─────────────────────────────────────────
        "__iter__": FunctionModel(return_kind=CALL_RETURN_FRESH),
        "__next__": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        "send": FunctionModel(return_kind=CALL_RETURN_OPAQUE, reads_self=True),
        "throw": FunctionModel(return_kind=CALL_RETURN_OPAQUE, reads_self=True),
        "anext": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        "builtins.anext": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        "__anext__": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        "close": FunctionModel(return_kind=CALL_RETURN_NONE, reads_self=True),
        # ── descriptors ────────────────────────────────────────────────
        "__get__": FunctionModel(return_kind=CALL_RETURN_OPAQUE),
        # ── `open()` returns a fresh file object that wraps arg[0] ─────
        "open": FunctionModel(return_kind=CALL_RETURN_FRESH),
        "builtins.open": FunctionModel(return_kind=CALL_RETURN_FRESH),
        # ── operator.itemgetter returns a callable — opaque ────────────
        "operator.itemgetter": FunctionModel(return_kind=CALL_RETURN_FRESH),
        # ── functools.reduce reads args[0] (callable) + args[1] (iter) ─
        "functools.reduce": FunctionModel(
            return_kind=CALL_RETURN_OPAQUE,
            read_arg_indices=(0, 1),
        ),
        # ── isinstance / issubclass read arg[0] only ───────────────────
        "isinstance": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        "builtins.isinstance": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        "issubclass": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        "builtins.issubclass": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        # ── `type()` reads its argument ────────────────────────────────
        "type": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        "builtins.type": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        # ── `len()` reads arg[0] ───────────────────────────────────────
        "len": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        "builtins.len": FunctionModel(
            return_kind=CALL_RETURN_FRESH,
            read_arg_indices=(0,),
        ),
        # ── `sorted()` reads arg[0], returns fresh ────────────────────
        "sorted": FunctionModel(
            return_kind=CALL_RETURN_COPY,
            read_arg_indices=(0,),
        ),
        "builtins.sorted": FunctionModel(
            return_kind=CALL_RETURN_COPY,
            read_arg_indices=(0,),
        ),
        # ── `reversed()` reads arg[0], returns fresh ──────────────────
        "reversed": FunctionModel(
            return_kind=CALL_RETURN_COPY,
            read_arg_indices=(0,),
        ),
        "builtins.reversed": FunctionModel(
            return_kind=CALL_RETURN_COPY,
            read_arg_indices=(0,),
        ),
        # ── `enumerate()` reads arg[0], returns fresh ─────────────────
        "enumerate": FunctionModel(
            return_kind=CALL_RETURN_COPY,
            read_arg_indices=(0,),
        ),
        "builtins.enumerate": FunctionModel(
            return_kind=CALL_RETURN_COPY,
            read_arg_indices=(0,),
        ),
    },
    collection_mutators={
        # ── value-inserting mutators ──────────────────────────────────
        "append": CollectionMutatorModel(writes_value=True),
        "interpreter_list_append": CollectionMutatorModel(writes_value=True),
        "interpreter_set_add": CollectionMutatorModel(writes_value=True),
        "appendleft": CollectionMutatorModel(
            writes_value=True,
            reorders_values=True,
        ),
        "add": CollectionMutatorModel(writes_value=True),
        "extend": CollectionMutatorModel(writes_value=True),
        "extendleft": CollectionMutatorModel(
            writes_value=True,
            reorders_values=True,
        ),
        "update": CollectionMutatorModel(writes_value=True),
        "insert": CollectionMutatorModel(
            writes_value=True,
            reorders_values=True,
            value_arg_indices=(1,),
        ),
        "setdefault": CollectionMutatorModel(
            writes_value=True,
            value_arg_indices=(1,),
            key_arg_index=0,
        ),
        "push": CollectionMutatorModel(writes_value=True),
        "enqueue": CollectionMutatorModel(writes_value=True),
        "put": CollectionMutatorModel(writes_value=True),
        "offer": CollectionMutatorModel(writes_value=True),
        "symmetric_difference_update": CollectionMutatorModel(
            writes_value=True
        ),
        "intersection_update": CollectionMutatorModel(writes_value=True),
        "difference_update": CollectionMutatorModel(writes_value=True),
        # ── deleting mutators ─────────────────────────────────────────
        "clear": CollectionMutatorModel(deletes_value=True),
        "pop": CollectionMutatorModel(
            deletes_value=True,
            reorders_values=True,
            key_arg_index=0,
        ),
        "popleft": CollectionMutatorModel(
            deletes_value=True,
            reorders_values=True,
        ),
        "popitem": CollectionMutatorModel(deletes_value=True),
        "remove": CollectionMutatorModel(
            deletes_value=True,
            reorders_values=True,
        ),
        "discard": CollectionMutatorModel(deletes_value=True),
        "popfirst": CollectionMutatorModel(deletes_value=True),
        "get_and_del": CollectionMutatorModel(
            deletes_value=True, key_arg_index=0
        ),
        # ── in-place reordering (escape existing elements) ────────────
        "sort": CollectionMutatorModel(reorders_values=True),
        "reverse": CollectionMutatorModel(reorders_values=True),
        "rotate": CollectionMutatorModel(reorders_values=True),
        "shuffle": CollectionMutatorModel(reorders_values=True),
    },
)


# ═══════════════════════════════════════════════════════════════════════
# Derived sets (for fast membership checks in the analysis engine)
# ═══════════════════════════════════════════════════════════════════════

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
