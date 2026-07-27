"""Bounded-soundness validation against observed runtime types.

Concrete executions cannot prove a static analysis sound, but every observed
runtime type must be admitted by a conservative may-type result.  These models
make that invariant easy to enforce in corpus and differential tests.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyflow.analysis.typeinfo.core.typesystem import (
    AnyType,
    Instance,
    NoneType,
    ProperType,
    TupleType,
    TypeVarType,
)
from pyflow.analysis.typeinfo.inference.models import (
    ModuleInferenceResult,
    SourceSpan,
)


@dataclass(frozen=True)
class ObservedType:
    """A runtime type observed for a symbol or source expression."""

    raw_type: type
    symbol: str | None = None
    span: SourceSpan | None = None

    def __post_init__(self) -> None:
        if (self.symbol is None) == (self.span is None):
            raise ValueError("exactly one of symbol or span must be supplied")


@dataclass(frozen=True)
class SoundnessViolation:
    """An observation excluded by the engine's closed inferred type set."""

    observation: ObservedType
    inferred: ProperType | None
    message: str


def validate_observed_types(
    result: ModuleInferenceResult,
    observations: list[ObservedType],
) -> list[SoundnessViolation]:
    """Return all bounded-soundness violations for concrete observations."""
    violations: list[SoundnessViolation] = []
    for observation in observations:
        if observation.symbol is not None:
            value = result.value_of(observation.symbol)
        else:
            assert observation.span is not None
            value = result.expressions.get(observation.span)
            if value is None:
                value = result.expression_value(
                    observation.span.lineno,
                    observation.span.col_offset,
                )

        # Unknown explicitly admits unmodelled alternatives.  It is imprecise,
        # but it is not an under-approximation.
        if value is not None and value.unknown:
            continue
        inferred = None if value is None else value.public_type()
        if inferred is not None and _admits_runtime_type(
            inferred, observation.raw_type
        ):
            continue
        location = observation.symbol or str(observation.span)
        violations.append(
            SoundnessViolation(
                observation=observation,
                inferred=inferred,
                message=(
                    f"Observed {observation.raw_type.__module__}."
                    f"{observation.raw_type.__qualname__} at {location}, "
                    f"but inferred {inferred or '<no type>'}"
                ),
            )
        )
    return violations


def _admits_runtime_type(inferred: ProperType, observed: type) -> bool:
    if isinstance(inferred, (AnyType, TypeVarType)):
        return True
    if isinstance(inferred, NoneType):
        return observed is type(None)
    if isinstance(inferred, TupleType):
        return observed is tuple
    if isinstance(inferred, Instance):
        raw = inferred.type.raw_type
        if not isinstance(raw, type):
            return False
        try:
            return issubclass(observed, raw)
        except TypeError:
            return observed is raw
    # UnionType is normally retained as individual members inside the abstract
    # domain.  This fallback keeps the validator robust for external results.
    items = getattr(inferred, "items", None)
    if items is not None:
        return any(_admits_runtime_type(item, observed) for item in items)
    return False
