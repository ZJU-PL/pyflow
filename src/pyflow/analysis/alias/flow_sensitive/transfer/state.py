"""Internal state and outcome records shared by transfer components."""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.language.python import ast as py_ast

from ..domain.abstraction import HeapEnvironment
from ..domain.state import HeapState
from ..model import HeapLocation


@dataclass(frozen=True)
class ExpressionValue:
    """Reference and non-reference alternatives produced by an expression."""

    refs: tuple[HeapLocation, ...] = ()
    may_non_reference: bool = False

    def join(self, other: "ExpressionValue") -> "ExpressionValue":
        return ExpressionValue(
            refs=tuple(dict.fromkeys((*self.refs, *other.refs))),
            may_non_reference=(
                self.may_non_reference or other.may_non_reference
            ),
        )


@dataclass(frozen=True)
class _CallSummary:
    state: HeapState
    returns: tuple[tuple[HeapLocation, ...], ...]
    environment: HeapEnvironment | None = None
    normal_state: HeapState | None = None
    normal_environment: HeapEnvironment | None = None
    raise_state: HeapState | None = None
    raise_environment: HeapEnvironment | None = None
    deletes: tuple[HeapLocation, ...] = ()
    raises: tuple[HeapLocation, ...] = ()
    yields: tuple[HeapLocation, ...] = ()
    yield_steps: tuple[
        tuple[HeapState, HeapEnvironment, tuple[HeapLocation, ...]], ...
    ] = ()
    param_returns: dict[int, frozenset[int]] = field(default_factory=dict)
    param_escapes: frozenset[int] = field(default_factory=frozenset)


@dataclass(frozen=True)
class _FlowState:
    """Complete flow value: heap contents plus local binding environment."""

    heap_state: HeapState
    environment: HeapEnvironment
    definition_defaults: dict[tuple[object, int], tuple[HeapLocation, ...]]


@dataclass(frozen=True)
class _FlowOutcome:
    """Normal successor plus path-insensitive abrupt control-flow exits."""

    normal: _FlowState | None
    abrupt: dict[str, _FlowState] = field(default_factory=dict)


@dataclass(frozen=True)
class _ExpressionOutcome:
    """Values and control-flow exits produced by expression evaluation."""

    values: tuple[HeapLocation, ...]
    normal: _FlowState | None
    raises: _FlowState | None = None


@dataclass(frozen=True)
class _CallBindingResult:
    """Resolved actual/formal bindings plus Python call feasibility."""

    bindings: dict[int, tuple[HeapLocation, ...]]
    definitely_invalid: bool = False
    maybe_invalid: bool = False
    reasons: frozenset[str] = frozenset()


@dataclass
class _DeferredActivation:
    callee: py_ast.Code
    actual_bindings: dict[int, tuple[HeapLocation, ...]]
    resume_index: int = 0
    summary: _CallSummary | None = None
    frame_environment: HeapEnvironment | None = None
