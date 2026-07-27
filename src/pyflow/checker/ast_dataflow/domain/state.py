"""Formal may-taint lattice for the redesigned AST dataflow engine."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from .locations import TaintLocation
from .provenance import (
    ProvenanceEdge,
    ProvenanceNode,
    ProvenanceOperation,
    TaintOrigin,
)
from .uncertainty import AnalysisUncertainty, PrecisionLevel


@dataclass(frozen=True, order=True)
class TaintFact:
    """One source-kind fact attached to an abstract location."""

    location: TaintLocation
    kind: str
    origin: TaintOrigin

    @property
    def provenance_node(self) -> ProvenanceNode:
        return ProvenanceNode(self.location, self.kind, self.origin)


@dataclass(frozen=True)
class TaintState:
    """Immutable product lattice used at CFG program points.

    ``facts`` and ``uncertainties`` are may properties and therefore join by
    union.  ``guarantees`` are must-sanitization properties and join by
    intersection.  The explicit unreachable value supplies the lattice bottom
    without requiring a representation of universal sanitizer guarantees.
    """

    reachable: bool = True
    facts: frozenset[TaintFact] = frozenset()
    guarantees: frozenset[tuple[TaintLocation, str]] = frozenset()
    provenance: frozenset[ProvenanceEdge] = frozenset()
    provenance_is_top: bool = False
    uncertainties: frozenset[AnalysisUncertainty] = frozenset()
    max_provenance_edges: int = 4096
    max_access_path: int = 4

    @classmethod
    def bottom(
        cls, *, max_provenance_edges: int = 4096, max_access_path: int = 4
    ) -> "TaintState":
        return cls(
            reachable=False,
            max_provenance_edges=max_provenance_edges,
            max_access_path=max_access_path,
        )

    def leq(self, other: "TaintState") -> bool:
        """The lattice order: ``other`` is at least as conservative as self."""

        if not self.reachable:
            return True
        if not other.reachable:
            return False
        return (
            self.facts <= other.facts
            and self.guarantees >= other.guarantees
            and (
                other.provenance_is_top
                or (not self.provenance_is_top and self.provenance <= other.provenance)
            )
            and self.uncertainties <= other.uncertainties
        )

    def join(self, other: "TaintState") -> "TaintState":
        if not self.reachable:
            return other
        if not other.reachable:
            return self
        limit = min(self.max_provenance_edges, other.max_provenance_edges)
        path_limit = min(self.max_access_path, other.max_access_path)
        provenance, provenance_is_top = self._join_provenance(other, limit)
        uncertainties = self.uncertainties | other.uncertainties
        if provenance_is_top:
            uncertainties = uncertainties | {self._provenance_overflow_uncertainty()}
        return TaintState(
            facts=self._normalize_facts(self.facts | other.facts, path_limit),
            guarantees=self._normalize_guarantees(
                self.guarantees & other.guarantees, path_limit
            ),
            provenance=provenance,
            provenance_is_top=provenance_is_top,
            uncertainties=uncertainties,
            max_provenance_edges=limit,
            max_access_path=path_limit,
        )

    def facts_at(self, location: TaintLocation) -> frozenset[TaintFact]:
        """Read facts that may contaminate ``location``."""

        location = self.abstract_location(location)
        candidates = (
            fact
            for fact in self.facts
            if fact.location.is_prefix_of(location)
            or location.is_prefix_of(fact.location)
        )
        return frozenset(
            fact
            for fact in candidates
            if not any(
                guarantee_kind == fact.kind
                and guarantee_location.is_prefix_of(location)
                and len(guarantee_location.selectors) >= len(fact.location.selectors)
                for guarantee_location, guarantee_kind in self.guarantees
            )
        )

    def is_tainted(self, location: TaintLocation, kinds: Iterable[str] = ()) -> bool:
        expected = frozenset(kinds)
        return any(
            not expected or fact.kind in expected for fact in self.facts_at(location)
        )

    def introduce(
        self,
        location: TaintLocation,
        kinds: Iterable[str],
        origin: TaintOrigin,
    ) -> "TaintState":
        if not self.reachable:
            return self
        location = self.abstract_location(location)
        additions = frozenset(TaintFact(location, kind, origin) for kind in kinds)
        guarantees = frozenset(
            guarantee
            for guarantee in self.guarantees
            if guarantee[0] != location
            or guarantee[1] not in {fact.kind for fact in additions}
        )
        return replace(self, facts=self.facts | additions, guarantees=guarantees)

    def write(
        self,
        location: TaintLocation,
        values: Iterable[TaintFact],
        *,
        strong: bool,
        source_base: TaintLocation | None = None,
        operation: ProvenanceOperation = ProvenanceOperation.WRITE,
        filename: str | None = None,
        line: int | None = None,
        detail: str | None = None,
    ) -> "TaintState":
        """Write relocated taint facts with strong or weak update semantics."""

        if not self.reachable:
            return self
        location = self.abstract_location(location)
        source_base = (
            self.abstract_location(source_base) if source_base is not None else None
        )
        strong = strong and location.is_precise
        source_facts = tuple(
            TaintFact(self.abstract_location(fact.location), fact.kind, fact.origin)
            for fact in values
        )
        contaminating = self.facts_at(location) if strong else frozenset()
        relocations = tuple(
            (
                fact,
                TaintFact(
                    self.abstract_location(
                        self._relocated_location(fact.location, source_base, location)
                    ),
                    fact.kind,
                    fact.origin,
                ),
            )
            for fact in source_facts
        )
        relocated = frozenset(target for _source, target in relocations)
        retained = self.facts
        if strong:
            retained = frozenset(
                fact for fact in retained if not location.is_prefix_of(fact.location)
            )
        edges = set(self.provenance)
        for source, target in relocations:
            edges.add(
                ProvenanceEdge(
                    source.provenance_node,
                    target.provenance_node,
                    operation,
                    filename=filename,
                    line=line,
                    detail=detail,
                )
            )
        written_kinds = {fact.kind for fact in relocated}
        guarantees = {
            guarantee
            for guarantee in self.guarantees
            if not location.may_overlap(guarantee[0])
            or guarantee[1] not in written_kinds
        }
        if strong:
            guarantees.update((location, fact.kind) for fact in contaminating)
            guarantees.difference_update((location, fact.kind) for fact in relocated)
        provenance, provenance_is_top = self._extend_provenance(edges)
        uncertainties = self.uncertainties
        if provenance_is_top:
            uncertainties = uncertainties | {self._provenance_overflow_uncertainty()}
        return replace(
            self,
            facts=retained | relocated,
            guarantees=frozenset(guarantees),
            provenance=provenance,
            provenance_is_top=provenance_is_top,
            uncertainties=uncertainties,
        )

    def copy(
        self,
        source: TaintLocation,
        destination: TaintLocation,
        *,
        strong: bool,
        operation: ProvenanceOperation = ProvenanceOperation.ASSIGN,
        filename: str | None = None,
        line: int | None = None,
        detail: str | None = None,
    ) -> "TaintState":
        return self.write(
            destination,
            self.facts_at(source),
            strong=strong,
            source_base=source,
            operation=operation,
            filename=filename,
            line=line,
            detail=detail,
        )

    def kill(
        self,
        location: TaintLocation,
        kinds: Iterable[str] = ("*",),
        *,
        record_guarantee: bool = True,
    ) -> "TaintState":
        if not self.reachable:
            return self
        location = self.abstract_location(location)
        removed_kinds = frozenset(kinds)
        remove_all = "*" in removed_kinds
        retained = frozenset(
            fact
            for fact in self.facts
            if not (
                location.is_prefix_of(fact.location)
                and (remove_all or fact.kind in removed_kinds)
            )
        )
        guarantees = set(self.guarantees)
        if record_guarantee:
            concrete_kinds = (
                {
                    fact.kind
                    for fact in self.facts
                    if location.is_prefix_of(fact.location)
                }
                if remove_all
                else set(removed_kinds)
            )
            guarantees.update((location, kind) for kind in concrete_kinds)
        return replace(self, facts=retained, guarantees=frozenset(guarantees))

    def sanitize(
        self,
        source: TaintLocation,
        destination: TaintLocation,
        removed_kinds: Iterable[str],
        *,
        filename: str | None = None,
        line: int | None = None,
        sanitizer: str | None = None,
    ) -> "TaintState":
        removed = frozenset(removed_kinds)
        remove_all = "*" in removed
        incoming = self.facts_at(source)
        kept = tuple(
            fact for fact in incoming if not remove_all and fact.kind not in removed
        )
        result = self.write(
            destination,
            kept,
            strong=True,
            operation=ProvenanceOperation.SANITIZE,
            filename=filename,
            line=line,
            detail=sanitizer,
        )
        killed = {fact.kind for fact in incoming} if remove_all else set(removed)
        guarantees = set(result.guarantees)
        guarantees.update((destination, kind) for kind in killed)
        return replace(result, guarantees=frozenset(guarantees))

    def with_uncertainty(self, uncertainty: AnalysisUncertainty) -> "TaintState":
        if not self.reachable:
            return self
        return replace(self, uncertainties=self.uncertainties | {uncertainty})

    def havoc(
        self,
        locations: Iterable[TaintLocation],
        kinds: Iterable[str],
        origin: TaintOrigin,
        uncertainty: AnalysisUncertainty,
    ) -> "TaintState":
        """Conservatively contaminate locations at an unsupported boundary."""

        current = self.with_uncertainty(uncertainty)
        for location in locations:
            current = current.introduce(location, kinds, origin)
        return current

    def abstract_location(self, location: TaintLocation) -> TaintLocation:
        return location.summarize(self.max_access_path)

    def _extend_provenance(
        self, edges: Iterable[ProvenanceEdge]
    ) -> tuple[frozenset[ProvenanceEdge], bool]:
        if self.provenance_is_top:
            return frozenset(), True
        values = frozenset(edges)
        if len(values) > self.max_provenance_edges:
            return frozenset(), True
        return values, False

    def _join_provenance(
        self, other: "TaintState", limit: int
    ) -> tuple[frozenset[ProvenanceEdge], bool]:
        if self.provenance_is_top or other.provenance_is_top:
            return frozenset(), True
        values = self.provenance | other.provenance
        if len(values) > limit:
            return frozenset(), True
        return values, False

    @staticmethod
    def _normalize_facts(
        facts: Iterable[TaintFact], max_access_path: int
    ) -> frozenset[TaintFact]:
        return frozenset(
            TaintFact(fact.location.summarize(max_access_path), fact.kind, fact.origin)
            for fact in facts
        )

    @staticmethod
    def _normalize_guarantees(
        guarantees: Iterable[tuple[TaintLocation, str]], max_access_path: int
    ) -> frozenset[tuple[TaintLocation, str]]:
        return frozenset(
            (location.summarize(max_access_path), kind) for location, kind in guarantees
        )

    @staticmethod
    def _provenance_overflow_uncertainty() -> AnalysisUncertainty:
        return AnalysisUncertainty(
            code="provenance-budget-exceeded",
            message="Provenance witnesses exceeded their configured finite budget",
            level=PrecisionLevel.CONSERVATIVE,
        )

    @staticmethod
    def _relocated_location(
        fact_location: TaintLocation,
        source_base: TaintLocation | None,
        destination: TaintLocation,
    ) -> TaintLocation:
        if source_base is None or not source_base.is_prefix_of(fact_location):
            return destination
        suffix = fact_location.selectors[len(source_base.selectors) :]
        return destination.descendants(suffix)
