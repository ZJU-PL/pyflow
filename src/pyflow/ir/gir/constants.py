"""Internal symbol and operation constants for GIR emission.

These mirror the values used by Lian (``lian.config.constants.LIAN_INTERNAL``)
so that the GIR emitted by pyflow is byte-compatible with the GIR that Lian's
own Python frontend produces. Keeping the values in one place makes it easy to
re-sync them against an upstream Lian checkout.
"""


class LIAN_INTERNAL:
    """GIR-internal prefixes and well-known symbol names (Lian-compatible)."""

    # Sentinel values for boolean / none literals.
    TRUE: str = "true"
    FALSE: str = "false"
    NULL: str = "null"

    # Temporary variable prefixes. Counters are per-parser (per-file-unit).
    VARIABLE_DECL_PREF: str = "%vv"
    DEFAULT_VALUE_PREF: str = "%dvv"
    METHOD_DECL_PREF: str = "%mm"
    CLASS_DECL_PREF: str = "%cc"

    # Well-known receiver / parent symbols.
    THIS: str = "%this"
    SELF: str = "%this"
    PARENT: str = "%parent"
    SUPER: str = "%parent"
    CLASS: str = "%class"

    # Well-known synthetic method names.
    UNIT_INIT: str = "%unit_init"
    CLASS_INIT: str = "%class_init"
    CLASS_STATIC_INIT: str = "%class_sinit"

    # Parameter / argument markers.
    PACKED_POSITIONAL_PARAMETER: str = "%packed_pos_pmt"
    PACKED_NAMED_PARAMETER: str = "%packed_named_pmt"
    POSITIONAL_ONLY_PARAMETER: str = "%pos_pmt"
    KEYWORLD_ONLY_PARAMETER: str = "%keyword_pmt"
    PACKED_POSTIONAL_ARGUMENT: str = "%pos_arg"
    PACKED_NAMED_ARGUMENT: str = "%named_arg"


# Prefix used when a fresh temporary variable is materialized during emission.
def tmp_variable(counter: "GirCounter") -> str:
    return LIAN_INTERNAL.VARIABLE_DECL_PREF + str(counter.next_var())


def default_value_variable(counter: "GirCounter") -> str:
    return LIAN_INTERNAL.DEFAULT_VALUE_PREF + str(counter.next_var())


def tmp_method(counter: "GirCounter") -> str:
    return LIAN_INTERNAL.METHOD_DECL_PREF + str(counter.next_method())


def tmp_class(counter: "GirCounter") -> str:
    return LIAN_INTERNAL.CLASS_DECL_PREF + str(counter.next_class())


class GirCounter:
    """Monotonic per-unit counters for temporary names.

    Lian allocates temporary names from a per-parser (per-file) counter that
    starts at 1. A fresh :class:`GirCounter` must be created for every emitted
    unit (module) so that ``%vv1`` is reused across files, exactly like Lian.
    """

    __slots__ = ("_var_id", "_method_id", "_class_id")

    def __init__(self, start: int = 1) -> None:
        self._var_id = start - 1
        self._method_id = start - 1
        self._class_id = start - 1

    def next_var(self) -> int:
        self._var_id += 1
        return self._var_id

    def next_method(self) -> int:
        self._method_id += 1
        return self._method_id

    def next_class(self) -> int:
        self._class_id += 1
        return self._class_id
