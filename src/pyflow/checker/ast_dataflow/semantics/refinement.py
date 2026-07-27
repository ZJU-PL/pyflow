"""Precision-refinement interface shared by source and PyFlow-IR frontends."""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol, Sequence, cast

from ..domain import AnalysisUncertainty, TaintLocation


@dataclass(frozen=True)
class UpdateDecision:
    strong: bool
    reasons: tuple[str, ...] = ()
    uncertainties: tuple[AnalysisUncertainty, ...] = ()


class RefinementProvider(Protocol):
    def update_decision(
        self, location: TaintLocation, program_point: object | None
    ) -> UpdateDecision: ...


class HeapGraphQuery(Protocol):
    def strong_update_possible(self, location: object) -> bool: ...

    def locations_by_label(self) -> Mapping[str, Sequence[object]]: ...


class SyntacticRefinementProvider:
    """Safe source-only policy: locals and precise fresh paths update strongly."""

    def update_decision(
        self, location: TaintLocation, program_point: object | None
    ) -> UpdateDecision:
        if not location.selectors:
            return UpdateDecision(True, ("local-binding",))
        if location.is_precise:
            # Without heap cardinality evidence, precise object paths still may
            # alias and therefore receive a weak update.
            return UpdateDecision(False, ("heap-cardinality-unknown",))
        return UpdateDecision(False, ("wildcard-selector",))


class AdaptiveRefinementProvider:
    """Invoke heavier refiners only when cheap syntactic proof is insufficient."""

    def __init__(
        self,
        refiners: Sequence[RefinementProvider],
        *,
        base: RefinementProvider | None = None,
    ) -> None:
        self.base = base or SyntacticRefinementProvider()
        self.refiners = tuple(refiners)
        self.refinement_requests = 0
        self.successful_refinements = 0
        self._cache: dict[tuple[TaintLocation, object], UpdateDecision] = {}

    def update_decision(
        self, location: TaintLocation, program_point: object | None
    ) -> UpdateDecision:
        point_key: object = (
            program_point if isinstance(program_point, Hashable) else id(program_point)
        )
        cache_key = (location, point_key)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        decision = self.base.update_decision(location, program_point)
        if decision.strong or not location.selectors:
            self._cache[cache_key] = decision
            return decision
        reasons = list(decision.reasons)
        uncertainties = list(decision.uncertainties)
        for refiner in self.refiners:
            self.refinement_requests += 1
            refined = refiner.update_decision(location, program_point)
            reasons.extend(refined.reasons)
            uncertainties.extend(refined.uncertainties)
            if refined.strong:
                self.successful_refinements += 1
                result = UpdateDecision(
                    True,
                    tuple(dict.fromkeys(reasons)),
                    tuple(dict.fromkeys(uncertainties)),
                )
                self._cache[cache_key] = result
                return result
        result = UpdateDecision(
            False,
            tuple(dict.fromkeys(reasons)),
            tuple(dict.fromkeys(uncertainties)),
        )
        self._cache[cache_key] = result
        return result


class HeapGraphRefinementProvider:
    """Adapter for points-to graphs exposing ``strong_update_possible``."""

    def __init__(
        self,
        graph: HeapGraphQuery,
        location_adapter: Callable[[TaintLocation, object | None], object | None],
    ) -> None:
        self.graph = graph
        self.location_adapter = location_adapter

    def update_decision(
        self, location: TaintLocation, program_point: object | None
    ) -> UpdateDecision:
        heap_location = self.location_adapter(location, program_point)
        if heap_location is None:
            return SyntacticRefinementProvider().update_decision(
                location, program_point
            )
        try:
            strong = bool(self.graph.strong_update_possible(heap_location))
        except Exception as error:
            return UpdateDecision(False, (f"heap-query-failed:{type(error).__name__}",))
        return UpdateDecision(
            strong,
            ("heap-singleton" if strong else "heap-may-alias",),
        )


def heap_location_adapter(
    graph: HeapGraphQuery,
) -> Callable[[TaintLocation, object | None], object | None]:
    """Translate source access paths to unambiguous PyFlow heap locations."""

    try:
        from pyflow.analysis.alias.flow_sensitive.model import (
            HeapLocation,
            HeapSelector,
        )
    except ImportError:
        return lambda _location, _program_point: None

    try:
        labels = graph.locations_by_label()
    except Exception:
        labels = {}

    def adapt(location: TaintLocation, program_point: object | None):
        root = location.root
        if not (
            isinstance(root, tuple) and len(root) == 2 and isinstance(root[1], str)
        ):
            return None
        candidates = {
            candidate.root_location()
            for candidate in labels.get(root[1], ())
            if hasattr(candidate, "root_location")
        }
        if len(candidates) != 1:
            return None
        base = next(iter(candidates))
        selectors = []
        for selector in location.selectors:
            kind = selector.kind.value
            if kind == "attribute":
                selectors.append(HeapSelector.field(str(selector.value)))
            elif kind == "key":
                selectors.append(HeapSelector.key(str(selector.value)))
            elif kind == "index":
                selectors.append(HeapSelector.index(cast(int, selector.value)))
            elif kind == "wildcard":
                selectors.append(HeapSelector.unknown_element())
            else:
                selectors.append(HeapSelector.summary())
        return HeapLocation(base.root, tuple(selectors))

    return adapt
