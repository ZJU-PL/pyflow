"""Client-facing access to context-sensitive facts in an IR catalog."""

from __future__ import annotations

from typing import cast

from pyflow.language.python import ast

from .analysis_facts import CallTarget, Capabilities, ContextualKey
from .facts import FactResult, Precision
from .ids import ContextId


class MissingAnalysisFact(LookupError):
    pass


class StaleAnalysisFacts(RuntimeError):
    pass


def _require(result: FactResult, capability: str):
    if result.precision is Precision.UNKNOWN:
        detail = "; ".join(str(item) for item in result.diagnostics)
        raise MissingAnalysisFact(f"{capability}: {detail or 'unknown'}")
    return result.values


class AnalysisFacts:
    """Resolve typed fact-store identities back to client-facing objects."""

    def __init__(self, catalog) -> None:
        self.catalog = catalog
        self.ir_revision = catalog.revision

    def _require_current(self) -> None:
        if self.catalog.revision != self.ir_revision:
            raise StaleAnalysisFacts(
                f"analysis view was created for {self.ir_revision}; "
                f"current IR is {self.catalog.revision}"
            )

    @classmethod
    def for_code(cls, code):
        catalog = getattr(code, "ir_catalog", None)
        if catalog is None:
            raise MissingAnalysisFact(f"code has no IR catalog: {code!r}")
        return cls(catalog)

    def context_ids(
        self, code, *, producer: str | None = None
    ) -> tuple[ContextId, ...]:
        self._require_current()
        code_id = self.catalog.procedure(code).code_id
        if producer is None and self.catalog.facts.has_producer(
            Capabilities.CONTEXTS, "cpa"
        ):
            producer = "cpa"
        result = (
            self.catalog.facts.query_producer(
                Capabilities.CONTEXTS, producer, code_id
            )
            if producer is not None
            else self.catalog.facts.query(Capabilities.CONTEXTS, code_id)
        )
        values = _require(
            result,
            Capabilities.CONTEXTS,
        )
        return tuple(sorted(values))

    def contexts(self, code, *, producer: str | None = None) -> tuple[object, ...]:
        return tuple(
            self.catalog.context(identity)
            for identity in self.context_ids(code, producer=producer)
        )

    def context_id(self, code, context) -> ContextId:
        self._require_current()
        return cast(ContextId, self.catalog.context_id(code, context))

    def references(self, code, reference, context) -> frozenset[object]:
        self._require_current()
        if isinstance(reference, ast.Local):
            entity = self.catalog.symbol_id(reference, code)
        else:
            entity = self.catalog.node_id(reference, code)
        key = ContextualKey(entity, self.context_id(code, context))
        return frozenset(
            _require(
                self.catalog.facts.query(Capabilities.REFERENCES, key),
                Capabilities.REFERENCES,
            )
        )

    def merged_references(self, code, reference) -> frozenset[object]:
        return frozenset(
            location
            for context in self.contexts(code)
            for location in self.references(code, reference, context)
        )

    def call_targets(self, code, operation, context) -> frozenset[tuple[object, object]]:
        self._require_current()
        key = ContextualKey(
            self.catalog.node_id(operation, code), self.context_id(code, context)
        )
        targets = _require(
            self.catalog.facts.query(Capabilities.CALL_TARGETS, key),
            Capabilities.CALL_TARGETS,
        )
        return frozenset(
            (self.catalog.code(target.code), self.catalog.context(target.context))
            for target in targets
            if isinstance(target, CallTarget)
        )

    def merged_call_targets(self, code, operation) -> frozenset[tuple[object, object]]:
        return frozenset(
            target
            for context in self.contexts(code)
            for target in self.call_targets(code, operation, context)
        )

    def operation_effect(self, capability: str, code, operation, context):
        self._require_current()
        key = ContextualKey(
            self.catalog.node_id(operation, code), self.context_id(code, context)
        )
        return _require(self.catalog.facts.query(capability, key), capability)

    def merged_operation_effect(self, capability: str, code, operation):
        return frozenset(
            value
            for context in self.contexts(code)
            for value in self.operation_effect(capability, code, operation, context)
        )

    def code_effect(self, capability: str, code, context):
        self._require_current()
        key = ContextualKey(
            self.catalog.procedure(code).code_id, self.context_id(code, context)
        )
        return _require(self.catalog.facts.query(capability, key), capability)

    def merged_code_effect(self, capability: str, code):
        return frozenset(
            value
            for context in self.contexts(code)
            for value in self.code_effect(capability, code, context)
        )

    def points_to(self, location) -> frozenset[object]:
        """Return the published flow-sensitive alias class for a location."""
        self._require_current()
        return frozenset(
            _require(
                self.catalog.facts.query(Capabilities.ALIAS_POINTS_TO, location),
                Capabilities.ALIAS_POINTS_TO,
            )
        )

    def is_escaped(self, location) -> bool:
        self._require_current()
        values = _require(
            self.catalog.facts.query(Capabilities.ALIAS_ESCAPED, location),
            Capabilities.ALIAS_ESCAPED,
        )
        if len(values) != 1:
            raise MissingAnalysisFact("alias escape fact is not singular")
        return bool(next(iter(values)))

    def reference_count(self, location) -> int:
        self._require_current()
        values = _require(
            self.catalog.facts.query(
                Capabilities.ALIAS_REFERENCE_COUNT, location
            ),
            Capabilities.ALIAS_REFERENCE_COUNT,
        )
        if len(values) != 1:
            raise MissingAnalysisFact("alias reference-count fact is not singular")
        return int(next(iter(values)))

    def alias_precision(self, code, operation) -> FactResult:
        """Return precision diagnostics for one heap-transfer program point."""
        self._require_current()
        node_id = self.catalog.node_id(operation, code)
        return cast(
            FactResult,
            self.catalog.facts.query(Capabilities.ALIAS_PRECISION, node_id),
        )

    def alias_locations(self) -> tuple[object, ...]:
        """Return every location covered by the published alias snapshot."""
        self._require_current()
        if not self.catalog.facts.has(Capabilities.ALIAS_POINTS_TO):
            raise MissingAnalysisFact(f"missing {Capabilities.ALIAS_POINTS_TO}")
        locations = []
        for location, result in self.catalog.facts.items(
            Capabilities.ALIAS_POINTS_TO
        ):
            _require(result, Capabilities.ALIAS_POINTS_TO)
            locations.append(location)
        return tuple(locations)

    def locations_by_label(self) -> dict[str, tuple[object, ...]]:
        """Group published heap locations by stable source-level labels."""
        grouped: dict[str, list[object]] = {}
        for location in self.alias_locations():
            root = getattr(location, "root", None)
            label = getattr(root, "label", None)
            if label:
                grouped.setdefault(label, []).append(location)
        return {
            label: tuple(sorted(locations, key=repr))
            for label, locations in sorted(grouped.items())
        }

    def strong_update_possible(self, location) -> bool:
        """Conservatively derive strong-update eligibility from alias facts."""
        return self.reference_count(location) <= 1 and not self.is_escaped(location)

    def must_alias(self, left, right) -> bool:
        """Return whether two precise locations share one published alias class."""
        if left == right:
            return bool(getattr(left, "is_precise", lambda: True)())
        left_points_to = self.points_to(left)
        right_points_to = self.points_to(right)
        return bool(left_points_to & right_points_to) and (
            getattr(left, "selectors", None) == getattr(right, "selectors", None)
            and bool(getattr(left, "is_precise", lambda: True)())
            and bool(getattr(right, "is_precise", lambda: True)())
        )

    def ipa_summaries(self, code):
        self._require_current()
        code_id = self.catalog.procedure(code).code_id
        return _require(
            self.catalog.facts.query(Capabilities.IPA_SUMMARIES, code_id),
            Capabilities.IPA_SUMMARIES,
        )


__all__ = ["AnalysisFacts", "MissingAnalysisFact", "StaleAnalysisFacts"]
