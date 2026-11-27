"""Formal may-taint lattice for the redesigned AST dataflow engine."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import cached_property
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
    _cached_hash: int | None = field(default=None, init=False, repr=False, compare=False)
    _cached_provenance_node: ProvenanceNode | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __hash__(self) -> int:
        cached = self._cached_hash
        if cached is None:
            cached = hash((self.location, self.kind, self.origin))
            object.__setattr__(self, "_cached_hash", cached)
        return cached

    @property
    def provenance_node(self) -> ProvenanceNode:
        cached = self._cached_provenance_node
        if cached is None:
            cached = ProvenanceNode(self.location, self.kind, self.origin)
            object.__setattr__(self, "_cached_provenance_node", cached)
        return cached


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
    def bottom(cls, *, max_provenance_edges: int = 4096, max_access_path: int = 4) -> "TaintState":
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
        if self is other:
            return self
        if (
            self.facts is other.facts
            and self.guarantees is other.guarantees
            and self.provenance is other.provenance
            and self.provenance_is_top == other.provenance_is_top
            and self.uncertainties is other.uncertainties
            and self.max_provenance_edges == other.max_provenance_edges
            and self.max_access_path == other.max_access_path
        ):
            return self
        if self.leq(other):
            return other
        if other.leq(self):
            return self
        limit = min(self.max_provenance_edges, other.max_provenance_edges)
        path_limit = min(self.max_access_path, other.max_access_path)
        provenance, provenance_is_top = self._join_provenance(other, limit)
        uncertainties = self.uncertainties | other.uncertainties
        if provenance_is_top:
            uncertainties = uncertainties | {self._provenance_overflow_uncertainty()}
        facts = self.facts | other.facts
        guarantees = self.guarantees & other.guarantees
        normalized = self.max_access_path != path_limit or other.max_access_path != path_limit
        if normalized:
            facts = self._normalize_facts(facts, path_limit)
            guarantees = self._normalize_guarantees(guarantees, path_limit)
        result = TaintState(
            facts=frozenset(facts),
            guarantees=frozenset(guarantees),
            provenance=provenance,
            provenance_is_top=provenance_is_top,
            uncertainties=uncertainties,
            max_provenance_edges=limit,
            max_access_path=path_limit,
        )
        if not normalized:
            if not self.facts and "_facts_by_root" in other.__dict__:
                object.__setattr__(result, "_facts_by_root", other.__dict__["_facts_by_root"])
            elif not other.facts and "_facts_by_root" in self.__dict__:
                object.__setattr__(result, "_facts_by_root", self.__dict__["_facts_by_root"])
            if not guarantees:
                object.__setattr__(result, "_guarantees_by_root", {})
        return result

    @cached_property
    def _facts_by_root(self):
        groups = {}
        for fact in self.facts:
            groups.setdefault(fact.location.root, set()).add(fact)
        return {root: frozenset(facts) for root, facts in groups.items()}

    @cached_property
    def _guarantees_by_root(self):
        groups = {}
        for location, kind in self.guarantees:
            groups.setdefault(location.root, set()).add((location, kind))
        return {root: frozenset(values) for root, values in groups.items()}

    def _index_root_update(self, result, root, facts, guarantees):
        fact_index = dict(self._facts_by_root)
        guarantee_index = dict(self._guarantees_by_root)
        if facts:
            fact_index[root] = frozenset(facts)
        else:
            fact_index.pop(root, None)
        if guarantees:
            guarantee_index[root] = frozenset(guarantees)
        else:
            guarantee_index.pop(root, None)
        object.__setattr__(result, "_facts_by_root", fact_index)
        object.__setattr__(result, "_guarantees_by_root", guarantee_index)
        return result

    def facts_at(self, location: TaintLocation) -> frozenset[TaintFact]:
        """Read facts that may contaminate ``location``."""

        root_facts = self._facts_by_root.get(location.root)
        if not root_facts:
            return frozenset()
        location = self.abstract_location(location)
        candidates = [
            fact
            for fact in root_facts
            if fact.location.is_prefix_of(location) or location.is_prefix_of(fact.location)
        ]
        if not candidates:
            return frozenset()
        root_guarantees = self._guarantees_by_root.get(location.root)
        if not root_guarantees:
            return frozenset(candidates)
        return frozenset(
            fact
            for fact in candidates
            if not any(
                guarantee_kind == fact.kind
                and guarantee_location.is_prefix_of(location)
                and len(guarantee_location.selectors) >= len(fact.location.selectors)
                for guarantee_location, guarantee_kind in root_guarantees
            )
        )

    def is_tainted(self, location: TaintLocation, kinds: Iterable[str] = ()) -> bool:
        expected = frozenset(kinds)
        return any(not expected or fact.kind in expected for fact in self.facts_at(location))

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
        if not additions:
            return self
        previous_facts = self._facts_by_root.get(location.root, frozenset())
        previous_guarantees = self._guarantees_by_root.get(location.root, frozenset())
        written_kinds = {fact.kind for fact in additions}
        if previous_guarantees:
            root_guarantees = frozenset(
                guarantee
                for guarantee in previous_guarantees
                if guarantee[0] != location or guarantee[1] not in written_kinds
            )
        else:
            root_guarantees = previous_guarantees
        if additions <= previous_facts and root_guarantees == previous_guarantees:
            return self
        guarantees = (
            self.guarantees
            if root_guarantees == previous_guarantees
            else (self.guarantees - previous_guarantees) | root_guarantees
        )
        result = replace(self, facts=self.facts | additions, guarantees=guarantees)
        return self._index_root_update(
            result,
            location.root,
            previous_facts | additions,
            root_guarantees,
        )

    def introduce_many(
        self,
        entries: Iterable[tuple[TaintLocation, Iterable[str], TaintOrigin]],
    ) -> "TaintState":
        """Batch-introduce multiple taint facts in a single state transition."""

        if not self.reachable:
            return self
        additions_by_root: dict[object, set[TaintFact]] = {}
        written_by_root: dict[object, dict[TaintLocation, set[str]]] = {}
        all_additions: set[TaintFact] = set()
        for raw_location, kinds, origin in entries:
            location = self.abstract_location(raw_location)
            root = location.root
            root_additions = additions_by_root.setdefault(root, set())
            loc_kinds = written_by_root.setdefault(root, {}).setdefault(location, set())
            for kind in kinds:
                fact = TaintFact(location, kind, origin)
                root_additions.add(fact)
                all_additions.add(fact)
                loc_kinds.add(kind)
        if not all_additions:
            return self
        fact_index = dict(self._facts_by_root)
        guarantee_index = dict(self._guarantees_by_root)
        facts_changed = False
        guarantees_changed = False
        removed_guarantees: set[tuple[TaintLocation, str]] = set()
        for root, root_additions in additions_by_root.items():
            prev_facts = fact_index.get(root, frozenset())
            if not root_additions <= prev_facts:
                fact_index[root] = prev_facts | root_additions
                facts_changed = True
            prev_guarantees = guarantee_index.get(root)
            if prev_guarantees:
                loc_map = written_by_root[root]
                kept = frozenset(
                    g for g in prev_guarantees if g[0] not in loc_map or g[1] not in loc_map[g[0]]
                )
                if len(kept) != len(prev_guarantees):
                    guarantees_changed = True
                    removed_guarantees.update(prev_guarantees - kept)
                    if kept:
                        guarantee_index[root] = kept
                    else:
                        guarantee_index.pop(root, None)
        if not facts_changed and not guarantees_changed:
            return self
        new_facts = self.facts | all_additions if facts_changed else self.facts
        new_guarantees = (
            self.guarantees - removed_guarantees if guarantees_changed else self.guarantees
        )
        result = replace(self, facts=new_facts, guarantees=new_guarantees)
        object.__setattr__(result, "_facts_by_root", fact_index)
        object.__setattr__(result, "_guarantees_by_root", guarantee_index)
        return result

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
        raw_values = values if isinstance(values, (tuple, list, set, frozenset)) else tuple(values)
        previous_facts = self._facts_by_root.get(location.root)
        if not raw_values and not previous_facts:
            return self
        max_path = self.max_access_path
        location = (
            location if len(location.selectors) <= max_path else self.abstract_location(location)
        )
        if source_base is not None and len(source_base.selectors) > max_path:
            source_base = self.abstract_location(source_base)
        strong = strong and location.is_precise
        contaminating = self.facts_at(location) if strong else frozenset()
        relocations: list[tuple[TaintFact, TaintFact]] = []
        relocated_set: set[TaintFact] = set()
        for fact in raw_values:
            source_fact = (
                fact
                if len(fact.location.selectors) <= max_path
                else TaintFact(self.abstract_location(fact.location), fact.kind, fact.origin)
            )
            relocated_loc = self._relocated_location(source_fact.location, source_base, location)
            if len(relocated_loc.selectors) > max_path:
                relocated_loc = self.abstract_location(relocated_loc)
            target_fact = (
                source_fact
                if relocated_loc == source_fact.location
                else TaintFact(relocated_loc, source_fact.kind, source_fact.origin)
            )
            relocations.append((source_fact, target_fact))
            relocated_set.add(target_fact)
        relocated = frozenset(relocated_set)
        previous_facts = previous_facts or frozenset()
        if strong and previous_facts:
            removed = frozenset(
                fact for fact in previous_facts if location.is_prefix_of(fact.location)
            )
        else:
            removed = frozenset()
        previous_guarantees = self._guarantees_by_root.get(location.root, frozenset())
        if previous_guarantees or (strong and contaminating):
            written_kinds = {fact.kind for fact in relocated}
            root_guarantees = {
                guarantee
                for guarantee in previous_guarantees
                if not location.may_overlap(guarantee[0]) or guarantee[1] not in written_kinds
            }
            if strong:
                root_guarantees.update((location, fact.kind) for fact in contaminating)
                root_guarantees.difference_update((location, fact.kind) for fact in relocated)
            guarantees_changed = root_guarantees != previous_guarantees
        else:
            root_guarantees = previous_guarantees
            guarantees_changed = False

        if self.provenance_is_top:
            provenance, provenance_is_top = frozenset(), True
            provenance_changed = False
        elif not relocations:
            provenance, provenance_is_top = self.provenance, False
            provenance_changed = False
        else:
            new_edges = [
                ProvenanceEdge(
                    source.provenance_node,
                    target.provenance_node,
                    operation,
                    filename=filename,
                    line=line,
                    detail=detail,
                )
                for source, target in relocations
            ]
            current_prov = self.provenance
            if all(edge in current_prov for edge in new_edges):
                provenance, provenance_is_top = current_prov, False
                provenance_changed = False
            else:
                merged = current_prov.union(new_edges)
                if len(merged) > self.max_provenance_edges:
                    provenance, provenance_is_top = frozenset(), True
                else:
                    provenance, provenance_is_top = merged, False
                provenance_changed = True

        new_root_facts = (
            (previous_facts - removed) | relocated if removed else previous_facts | relocated
        )
        facts_changed = new_root_facts != previous_facts
        uncertainties = self.uncertainties
        uncertainties_changed = False
        if provenance_is_top and not self.provenance_is_top:
            overflow = self._provenance_overflow_uncertainty()
            if overflow not in uncertainties:
                uncertainties = uncertainties | {overflow}
                uncertainties_changed = True

        if not (facts_changed or guarantees_changed or provenance_changed or uncertainties_changed):
            return self

        if facts_changed:
            new_facts = (self.facts - removed) | relocated if removed else self.facts | relocated
        else:
            new_facts = self.facts
        if guarantees_changed:
            new_guarantees = frozenset((self.guarantees - previous_guarantees) | root_guarantees)
        else:
            new_guarantees = self.guarantees
        result = replace(
            self,
            facts=new_facts,
            guarantees=new_guarantees,
            provenance=provenance,
            provenance_is_top=provenance_is_top,
            uncertainties=uncertainties,
        )

        return self._index_root_update(
            result,
            location.root,
            new_root_facts,
            root_guarantees,
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
        previous_facts = self._facts_by_root.get(location.root, frozenset())
        removed = frozenset(
            fact
            for fact in previous_facts
            if location.is_prefix_of(fact.location) and (remove_all or fact.kind in removed_kinds)
        )
        previous_guarantees = self._guarantees_by_root.get(location.root, frozenset())
        root_guarantees = set(previous_guarantees)
        if record_guarantee:
            concrete_kinds = {fact.kind for fact in removed} if remove_all else removed_kinds
            root_guarantees.update((location, kind) for kind in concrete_kinds)
        if not removed and root_guarantees == previous_guarantees:
            return self
        guarantees = (
            self.guarantees
            if root_guarantees == previous_guarantees
            else (self.guarantees - previous_guarantees) | root_guarantees
        )
        result = replace(self, facts=self.facts - removed, guarantees=frozenset(guarantees))
        return self._index_root_update(
            result,
            location.root,
            previous_facts - removed,
            root_guarantees,
        )

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
        kept = tuple(fact for fact in incoming if not remove_all and fact.kind not in removed)
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
        if not killed:
            return result
        extra_guarantees = frozenset((destination, kind) for kind in killed)
        if extra_guarantees <= result.guarantees:
            return result
        updated = replace(result, guarantees=result.guarantees | extra_guarantees)
        return result._index_root_update(
            updated,
            destination.root,
            result._facts_by_root.get(destination.root, frozenset()),
            result._guarantees_by_root.get(destination.root, frozenset()) | extra_guarantees,
        )

    def with_uncertainty(self, uncertainty: AnalysisUncertainty) -> "TaintState":
        if not self.reachable or uncertainty in self.uncertainties:
            return self
        result = replace(self, uncertainties=self.uncertainties | {uncertainty})
        if "_facts_by_root" in self.__dict__:
            object.__setattr__(result, "_facts_by_root", self.__dict__["_facts_by_root"])
        if "_guarantees_by_root" in self.__dict__:
            object.__setattr__(result, "_guarantees_by_root", self.__dict__["_guarantees_by_root"])
        return result

    def havoc(
        self,
        locations: Iterable[TaintLocation],
        kinds: Iterable[str],
        origin: TaintOrigin,
        uncertainty: AnalysisUncertainty,
    ) -> "TaintState":
        """Conservatively contaminate locations at an unsupported boundary."""

        current = self.with_uncertainty(uncertainty)
        kind_tuple = tuple(kinds)
        return current.introduce_many((location, kind_tuple, origin) for location in locations)

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
    def _normalize_facts(facts: Iterable[TaintFact], max_access_path: int) -> frozenset[TaintFact]:
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
