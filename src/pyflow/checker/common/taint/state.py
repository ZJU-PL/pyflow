"""Formal may-taint lattice for the redesigned AST dataflow engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .locations import TaintLocation
from .provenance import (
    ProvenanceEdge,
    ProvenanceNode,
    ProvenanceOperation,
    TaintOrigin,
)
from .uncertainty import AnalysisUncertainty, PrecisionLevel

_EMPTY_MAP: dict[object, frozenset] = {}
_EMPTY_FROZENSET: frozenset = frozenset()
_INTERN_MAX_SIZE = 131_072
_FACT_CACHE: dict[tuple[TaintLocation, str, TaintOrigin], "TaintFact"] = {}
_EDGE_CACHE: dict[
    tuple[ProvenanceNode, ProvenanceNode, ProvenanceOperation, str | None, int | None, str | None],
    ProvenanceEdge,
] = {}


def _intern_fact(location: TaintLocation, kind: str, origin: TaintOrigin) -> "TaintFact":
    key = (location, kind, origin)
    cached = _FACT_CACHE.get(key)
    if cached is not None:
        return cached
    if len(_FACT_CACHE) >= _INTERN_MAX_SIZE:
        _FACT_CACHE.clear()
    fact = TaintFact(location, kind, origin)
    _FACT_CACHE[key] = fact
    return fact


def _intern_edge(
    source: ProvenanceNode,
    target: ProvenanceNode,
    operation: ProvenanceOperation,
    filename: str | None,
    line: int | None,
    detail: str | None,
) -> ProvenanceEdge:
    key = (source, target, operation, filename, line, detail)
    cached = _EDGE_CACHE.get(key)
    if cached is not None:
        return cached
    if len(_EDGE_CACHE) >= _INTERN_MAX_SIZE:
        _EDGE_CACHE.clear()
    edge = ProvenanceEdge(
        source,
        target,
        operation,
        filename=filename,
        line=line,
        detail=detail,
    )
    _EDGE_CACHE[key] = edge
    return edge


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


class TaintState:
    """Immutable product lattice used at CFG program points.

    ``facts`` and ``uncertainties`` are may properties and therefore join by
    union.  ``guarantees`` are must-sanitization properties and join by
    intersection.  The explicit unreachable value supplies the lattice bottom
    without requiring a representation of universal sanitizer guarantees.

    Internally stores ``_facts_by_root`` and ``_guarantees_by_root`` with
    structural sharing of unchanged root buckets, materializing flat ``facts``
    and ``guarantees`` frozensets lazily on demand.
    """

    __slots__ = (
        "reachable",
        "_facts_by_root",
        "_guarantees_by_root",
        "provenance",
        "provenance_is_top",
        "uncertainties",
        "max_provenance_edges",
        "max_access_path",
        "_cached_facts",
        "_cached_guarantees",
        "_cached_hash",
    )

    def __init__(
        self,
        reachable: bool = True,
        facts: frozenset[TaintFact] = _EMPTY_FROZENSET,
        guarantees: frozenset[tuple[TaintLocation, str]] = _EMPTY_FROZENSET,
        provenance: frozenset[ProvenanceEdge] = _EMPTY_FROZENSET,
        provenance_is_top: bool = False,
        uncertainties: frozenset[AnalysisUncertainty] = _EMPTY_FROZENSET,
        max_provenance_edges: int = 4096,
        max_access_path: int = 4,
    ) -> None:
        facts_fs = facts if type(facts) is frozenset else frozenset(facts)
        guars_fs = guarantees if type(guarantees) is frozenset else frozenset(guarantees)
        if facts_fs:
            fgroups: dict[object, set[TaintFact]] = {}
            for fact in facts_fs:
                fgroups.setdefault(fact.location.root, set()).add(fact)
            facts_by_root: dict[object, frozenset[TaintFact]] = {
                root: frozenset(values) for root, values in fgroups.items()
            }
        else:
            facts_by_root = _EMPTY_MAP
        if guars_fs:
            ggroups: dict[object, set[tuple[TaintLocation, str]]] = {}
            for location, kind in guars_fs:
                ggroups.setdefault(location.root, set()).add((location, kind))
            guarantees_by_root: dict[object, frozenset[tuple[TaintLocation, str]]] = {
                root: frozenset(values) for root, values in ggroups.items()
            }
        else:
            guarantees_by_root = _EMPTY_MAP
        object.__setattr__(self, "reachable", reachable)
        object.__setattr__(self, "_facts_by_root", facts_by_root)
        object.__setattr__(self, "_guarantees_by_root", guarantees_by_root)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "provenance_is_top", provenance_is_top)
        object.__setattr__(self, "uncertainties", uncertainties)
        object.__setattr__(self, "max_provenance_edges", max_provenance_edges)
        object.__setattr__(self, "max_access_path", max_access_path)
        object.__setattr__(self, "_cached_facts", facts_fs)
        object.__setattr__(self, "_cached_guarantees", guars_fs)
        object.__setattr__(self, "_cached_hash", None)

    @classmethod
    def _from_indexed(
        cls,
        *,
        reachable: bool = True,
        facts_by_root: dict[object, frozenset[TaintFact]],
        guarantees_by_root: dict[object, frozenset[tuple[TaintLocation, str]]],
        provenance: frozenset[ProvenanceEdge],
        provenance_is_top: bool,
        uncertainties: frozenset[AnalysisUncertainty],
        max_provenance_edges: int,
        max_access_path: int,
    ) -> "TaintState":
        obj = cls.__new__(cls)
        object.__setattr__(obj, "reachable", reachable)
        object.__setattr__(obj, "_facts_by_root", facts_by_root or _EMPTY_MAP)
        object.__setattr__(obj, "_guarantees_by_root", guarantees_by_root or _EMPTY_MAP)
        object.__setattr__(obj, "provenance", provenance)
        object.__setattr__(obj, "provenance_is_top", provenance_is_top)
        object.__setattr__(obj, "uncertainties", uncertainties)
        object.__setattr__(obj, "max_provenance_edges", max_provenance_edges)
        object.__setattr__(obj, "max_access_path", max_access_path)
        object.__setattr__(obj, "_cached_facts", _EMPTY_FROZENSET if not facts_by_root else None)
        object.__setattr__(
            obj, "_cached_guarantees", _EMPTY_FROZENSET if not guarantees_by_root else None
        )
        object.__setattr__(obj, "_cached_hash", None)
        return obj

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"cannot assign to field {name!r}")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"cannot delete field {name!r}")

    @property
    def facts(self) -> frozenset[TaintFact]:
        cached = self._cached_facts
        if cached is None:
            fbr = self._facts_by_root
            if not fbr:
                cached = _EMPTY_FROZENSET
            elif len(fbr) == 1:
                cached = next(iter(fbr.values()))
            else:
                cached = _EMPTY_FROZENSET.union(*fbr.values())
            object.__setattr__(self, "_cached_facts", cached)
        return cached

    @property
    def guarantees(self) -> frozenset[tuple[TaintLocation, str]]:
        cached = self._cached_guarantees
        if cached is None:
            gbr = self._guarantees_by_root
            if not gbr:
                cached = _EMPTY_FROZENSET
            elif len(gbr) == 1:
                cached = next(iter(gbr.values()))
            else:
                cached = _EMPTY_FROZENSET.union(*gbr.values())
            object.__setattr__(self, "_cached_guarantees", cached)
        return cached

    @staticmethod
    def _maps_equal(left: dict[object, frozenset], right: dict[object, frozenset]) -> bool:
        if left is right:
            return True
        if len(left) != len(right):
            return False
        for key, lval in left.items():
            rval = right.get(key)
            if rval is None:
                return False
            if lval is not rval and lval != rval:
                return False
        return True

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, TaintState):
            return NotImplemented
        if (
            self.reachable != other.reachable
            or self.provenance_is_top != other.provenance_is_top
            or self.max_provenance_edges != other.max_provenance_edges
            or self.max_access_path != other.max_access_path
        ):
            return False
        return (
            self._maps_equal(self._facts_by_root, other._facts_by_root)
            and self._maps_equal(self._guarantees_by_root, other._guarantees_by_root)
            and (self.provenance is other.provenance or self.provenance == other.provenance)
            and (
                self.uncertainties is other.uncertainties
                or self.uncertainties == other.uncertainties
            )
        )

    def __hash__(self) -> int:
        cached = self._cached_hash
        if cached is None:
            cached = hash(
                (
                    self.reachable,
                    self.facts,
                    self.guarantees,
                    self.provenance,
                    self.provenance_is_top,
                    self.uncertainties,
                    self.max_provenance_edges,
                    self.max_access_path,
                )
            )
            object.__setattr__(self, "_cached_hash", cached)
        return cached

    def __repr__(self) -> str:
        return (
            f"TaintState(reachable={self.reachable!r}, facts={self.facts!r}, "
            f"guarantees={self.guarantees!r}, provenance={self.provenance!r}, "
            f"provenance_is_top={self.provenance_is_top!r}, "
            f"uncertainties={self.uncertainties!r}, "
            f"max_provenance_edges={self.max_provenance_edges!r}, "
            f"max_access_path={self.max_access_path!r})"
        )

    @classmethod
    def bottom(cls, *, max_provenance_edges: int = 4096, max_access_path: int = 4) -> "TaintState":
        return cls._from_indexed(
            reachable=False,
            facts_by_root=_EMPTY_MAP,
            guarantees_by_root=_EMPTY_MAP,
            provenance=_EMPTY_FROZENSET,
            provenance_is_top=False,
            uncertainties=_EMPTY_FROZENSET,
            max_provenance_edges=max_provenance_edges,
            max_access_path=max_access_path,
        )

    def leq(self, other: "TaintState") -> bool:
        """The lattice order: ``other`` is at least as conservative as self."""

        if not self.reachable:
            return True
        if not other.reachable:
            return False
        if self is other:
            return True
        sf = self._facts_by_root
        of = other._facts_by_root
        if sf is not of:
            if len(sf) > len(of):
                return False
            for root, lfacts in sf.items():
                rfacts = of.get(root)
                if rfacts is None:
                    return False
                if lfacts is not rfacts and not (lfacts <= rfacts):
                    return False
        sg = self._guarantees_by_root
        og = other._guarantees_by_root
        if sg is not og:
            if len(sg) < len(og):
                return False
            for root, rguars in og.items():
                lguars = sg.get(root)
                if lguars is None:
                    return False
                if lguars is not rguars and not (lguars >= rguars):
                    return False
        if not other.provenance_is_top:
            if self.provenance_is_top:
                return False
            if self.provenance is not other.provenance and not (
                self.provenance <= other.provenance
            ):
                return False
        if self.uncertainties is not other.uncertainties and not (
            self.uncertainties <= other.uncertainties
        ):
            return False
        return True

    def join(self, other: "TaintState") -> "TaintState":
        if not self.reachable:
            return other
        if not other.reachable:
            return self
        if self is other:
            return self

        sf = self._facts_by_root
        of = other._facts_by_root
        if sf is of:
            merged_facts = sf
            facts_le_other = True
            facts_le_self = True
        elif not sf:
            merged_facts = of
            facts_le_other = True
            facts_le_self = not of
        elif not of:
            merged_facts = sf
            facts_le_other = False
            facts_le_self = True
        else:
            merged_facts = {}
            facts_le_other = True
            facts_le_self = True
            for root, lf in sf.items():
                rf = of.get(root)
                if rf is None:
                    merged_facts[root] = lf
                    facts_le_other = False
                elif lf is rf:
                    merged_facts[root] = lf
                elif len(lf) <= len(rf) and lf <= rf:
                    merged_facts[root] = rf
                    if len(lf) < len(rf):
                        facts_le_self = False
                elif len(rf) < len(lf) and rf <= lf:
                    merged_facts[root] = lf
                    facts_le_other = False
                else:
                    merged_facts[root] = lf | rf
                    facts_le_other = False
                    facts_le_self = False
            for root, rf in of.items():
                if root not in sf:
                    merged_facts[root] = rf
                    facts_le_self = False
            if facts_le_other:
                merged_facts = of
            elif facts_le_self:
                merged_facts = sf

        sg = self._guarantees_by_root
        og = other._guarantees_by_root
        if sg is og:
            merged_guars = sg
            guars_le_other = True
            guars_le_self = True
        elif not sg:
            merged_guars = _EMPTY_MAP
            guars_le_other = not og
            guars_le_self = True
        elif not og:
            merged_guars = _EMPTY_MAP
            guars_le_other = True
            guars_le_self = False
        else:
            merged_guars = {}
            guars_le_other = True
            guars_le_self = True
            for root, lg in sg.items():
                rg = og.get(root)
                if rg is None:
                    guars_le_self = False
                elif lg is rg:
                    merged_guars[root] = lg
                else:
                    inter = lg & rg
                    if inter:
                        merged_guars[root] = inter
                    if len(inter) < len(rg):
                        guars_le_other = False
                    if len(inter) < len(lg):
                        guars_le_self = False
            if guars_le_other:
                for root in og:
                    if root not in sg:
                        guars_le_other = False
                        break
            if guars_le_other:
                merged_guars = og
            elif guars_le_self:
                merged_guars = sg

        can_return_other = facts_le_other and guars_le_other
        can_return_self = facts_le_self and guars_le_self

        if self.uncertainties is other.uncertainties:
            unc_le_other = True
            unc_le_self = True
        else:
            unc_le_other = (
                len(self.uncertainties) <= len(other.uncertainties)
                and self.uncertainties <= other.uncertainties
            )
            unc_le_self = (
                len(other.uncertainties) <= len(self.uncertainties)
                and other.uncertainties <= self.uncertainties
            )

        can_return_other = can_return_other and unc_le_other
        can_return_self = can_return_self and unc_le_self

        prov_le_other = False
        prov_le_self = False
        if self.provenance_is_top and other.provenance_is_top:
            prov_le_other = True
            prov_le_self = True
        elif other.provenance_is_top:
            prov_le_other = True
        elif self.provenance_is_top:
            prov_le_self = True
        elif self.provenance is other.provenance:
            prov_le_other = True
            prov_le_self = True
        else:
            if can_return_other:
                prov_le_other = (
                    len(self.provenance) <= len(other.provenance)
                    and self.provenance <= other.provenance
                )
            if can_return_self and not prov_le_other:
                prov_le_self = (
                    len(other.provenance) <= len(self.provenance)
                    and other.provenance <= self.provenance
                )

        if can_return_other and prov_le_other:
            return other
        if can_return_self and prov_le_self:
            return self

        limit = min(self.max_provenance_edges, other.max_provenance_edges)
        path_limit = min(self.max_access_path, other.max_access_path)
        if self.provenance_is_top or other.provenance_is_top:
            provenance, provenance_is_top = _EMPTY_FROZENSET, True
        elif prov_le_other:
            if len(other.provenance) > limit:
                provenance, provenance_is_top = _EMPTY_FROZENSET, True
            else:
                provenance, provenance_is_top = other.provenance, False
        elif prov_le_self:
            if len(self.provenance) > limit:
                provenance, provenance_is_top = _EMPTY_FROZENSET, True
            else:
                provenance, provenance_is_top = self.provenance, False
        else:
            provenance, provenance_is_top = self._join_provenance(other, limit)

        if unc_le_other:
            uncertainties = other.uncertainties
        elif unc_le_self:
            uncertainties = self.uncertainties
        else:
            uncertainties = self.uncertainties | other.uncertainties
        if provenance_is_top:
            overflow = self._provenance_overflow_uncertainty()
            if overflow not in uncertainties:
                uncertainties = uncertainties | {overflow}

        if self.max_access_path != path_limit or other.max_access_path != path_limit:
            merged_facts = self._normalize_facts_by_root(merged_facts, path_limit)
            merged_guars = self._normalize_guarantees_by_root(merged_guars, path_limit)

        return TaintState._from_indexed(
            reachable=True,
            facts_by_root=merged_facts,
            guarantees_by_root=merged_guars,
            provenance=provenance,
            provenance_is_top=provenance_is_top,
            uncertainties=uncertainties,
            max_provenance_edges=limit,
            max_access_path=path_limit,
        )

    def facts_at(self, location: TaintLocation) -> frozenset[TaintFact]:
        """Read facts that may contaminate ``location``."""

        root_facts = self._facts_by_root.get(location.root)
        if not root_facts:
            return _EMPTY_FROZENSET
        if len(location.selectors) > self.max_access_path:
            location = self.abstract_location(location)
        root_guarantees = self._guarantees_by_root.get(location.root)
        if not location.selectors:
            if not root_guarantees:
                return root_facts
            candidates = root_facts
        else:
            candidates = [
                fact
                for fact in root_facts
                if fact.location.is_prefix_of(location) or location.is_prefix_of(fact.location)
            ]
            if not candidates:
                return _EMPTY_FROZENSET
            if not root_guarantees:
                return frozenset(candidates)
        loc_len = len(location.selectors)
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
        additions = frozenset(_intern_fact(location, kind, origin) for kind in kinds)
        if not additions:
            return self
        root = location.root
        previous_facts = self._facts_by_root.get(root, _EMPTY_FROZENSET)
        previous_guarantees = self._guarantees_by_root.get(root, _EMPTY_FROZENSET)
        if previous_guarantees:
            written_kinds = {fact.kind for fact in additions}
            root_guarantees = frozenset(
                guarantee
                for guarantee in previous_guarantees
                if guarantee[0] != location or guarantee[1] not in written_kinds
            )
            guarantees_changed = len(root_guarantees) != len(previous_guarantees)
        else:
            root_guarantees = previous_guarantees
            guarantees_changed = False
        facts_changed = not (additions <= previous_facts)
        if not facts_changed and not guarantees_changed:
            return self
        if facts_changed:
            fact_index = dict(self._facts_by_root)
            fact_index[root] = previous_facts | additions
        else:
            fact_index = self._facts_by_root
        if guarantees_changed:
            guarantee_index = dict(self._guarantees_by_root)
            if root_guarantees:
                guarantee_index[root] = root_guarantees
            else:
                guarantee_index.pop(root, None)
        else:
            guarantee_index = self._guarantees_by_root
        return TaintState._from_indexed(
            reachable=True,
            facts_by_root=fact_index,
            guarantees_by_root=guarantee_index,
            provenance=self.provenance,
            provenance_is_top=self.provenance_is_top,
            uncertainties=self.uncertainties,
            max_provenance_edges=self.max_provenance_edges,
            max_access_path=self.max_access_path,
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
        has_any = False
        for raw_location, kinds, origin in entries:
            location = self.abstract_location(raw_location)
            root = location.root
            root_additions = additions_by_root.setdefault(root, set())
            loc_kinds = written_by_root.setdefault(root, {}).setdefault(location, set())
            for kind in kinds:
                root_additions.add(_intern_fact(location, kind, origin))
                loc_kinds.add(kind)
                has_any = True
        if not has_any:
            return self
        fact_index: dict[object, frozenset[TaintFact]] | None = None
        guarantee_index: dict[object, frozenset[tuple[TaintLocation, str]]] | None = None
        for root, root_additions in additions_by_root.items():
            prev_facts = self._facts_by_root.get(root, _EMPTY_FROZENSET)
            if not (root_additions <= prev_facts):
                if fact_index is None:
                    fact_index = dict(self._facts_by_root)
                fact_index[root] = prev_facts | root_additions
            prev_guarantees = self._guarantees_by_root.get(root)
            if prev_guarantees:
                loc_map = written_by_root[root]
                kept = frozenset(
                    g for g in prev_guarantees if g[0] not in loc_map or g[1] not in loc_map[g[0]]
                )
                if len(kept) != len(prev_guarantees):
                    if guarantee_index is None:
                        guarantee_index = dict(self._guarantees_by_root)
                    if kept:
                        guarantee_index[root] = kept
                    else:
                        guarantee_index.pop(root, None)
        if fact_index is None and guarantee_index is None:
            return self
        return TaintState._from_indexed(
            reachable=True,
            facts_by_root=fact_index if fact_index is not None else self._facts_by_root,
            guarantees_by_root=(
                guarantee_index if guarantee_index is not None else self._guarantees_by_root
            ),
            provenance=self.provenance,
            provenance_is_top=self.provenance_is_top,
            uncertainties=self.uncertainties,
            max_provenance_edges=self.max_provenance_edges,
            max_access_path=self.max_access_path,
        )

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
        root = location.root
        previous_facts = self._facts_by_root.get(root)
        if not raw_values and not previous_facts:
            return self
        max_path = self.max_access_path
        if len(location.selectors) > max_path:
            location = self.abstract_location(location)
        if source_base is not None and len(source_base.selectors) > max_path:
            source_base = self.abstract_location(source_base)
        strong = strong and location.is_precise
        contaminating = self.facts_at(location) if strong else _EMPTY_FROZENSET
        track_prov = not self.provenance_is_top
        relocations: list[tuple[TaintFact, TaintFact]] | None = [] if track_prov else None
        relocated_set: set[TaintFact] = set()
        add_relocated = relocated_set.add
        intern_fact = _intern_fact
        loc_sels = location.selectors
        if raw_values:
            if source_base is None:
                for fact in raw_values:
                    fact_loc = fact.location
                    if track_prov and len(fact_loc.selectors) > max_path:
                        source_fact = intern_fact(
                            fact_loc.summarize(max_path), fact.kind, fact.origin
                        )
                    else:
                        source_fact = fact
                    target_fact = (
                        source_fact
                        if location == source_fact.location
                        else intern_fact(location, source_fact.kind, source_fact.origin)
                    )
                    if relocations is not None:
                        relocations.append((source_fact, target_fact))
                    add_relocated(target_fact)
            elif not source_base.selectors:
                sb_root = source_base.root
                for fact in raw_values:
                    fact_loc = fact.location
                    fact_sels = fact_loc.selectors
                    if len(fact_sels) > max_path:
                        fact_loc = fact_loc.summarize(max_path)
                        fact_sels = fact_loc.selectors
                        source_fact = intern_fact(fact_loc, fact.kind, fact.origin)
                    else:
                        source_fact = fact
                    if fact_loc.root == sb_root and fact_sels:
                        if not loc_sels:
                            relocated_loc = TaintLocation(root, fact_sels)
                        else:
                            combined = (*loc_sels, *fact_sels)
                            relocated_loc = TaintLocation(root, combined)
                            if len(combined) > max_path:
                                relocated_loc = relocated_loc.summarize(max_path)
                    else:
                        relocated_loc = location
                    target_fact = (
                        source_fact
                        if relocated_loc == fact_loc
                        else intern_fact(relocated_loc, source_fact.kind, source_fact.origin)
                    )
                    if relocations is not None:
                        relocations.append((source_fact, target_fact))
                    add_relocated(target_fact)
            else:
                sb_len = len(source_base.selectors)
                for fact in raw_values:
                    fact_loc = fact.location
                    if len(fact_loc.selectors) > max_path:
                        fact_loc = fact_loc.summarize(max_path)
                        source_fact = intern_fact(fact_loc, fact.kind, fact.origin)
                    else:
                        source_fact = fact
                    if source_base.is_prefix_of(fact_loc):
                        suffix = fact_loc.selectors[sb_len:]
                        relocated_loc = location.descendants(suffix) if suffix else location
                        if len(relocated_loc.selectors) > max_path:
                            relocated_loc = relocated_loc.summarize(max_path)
                    else:
                        relocated_loc = location
                    target_fact = (
                        source_fact
                        if relocated_loc == fact_loc
                        else intern_fact(relocated_loc, source_fact.kind, source_fact.origin)
                    )
                    if relocations is not None:
                        relocations.append((source_fact, target_fact))
                    add_relocated(target_fact)
        relocated = frozenset(relocated_set) if relocated_set else _EMPTY_FROZENSET
        previous_facts = previous_facts or _EMPTY_FROZENSET
        if strong and previous_facts:
            if not loc_sels:
                new_root_facts = relocated
            else:
                removed = frozenset(
                    fact for fact in previous_facts if location.is_prefix_of(fact.location)
                )
                new_root_facts = (
                    (previous_facts - removed) | relocated
                    if removed
                    else previous_facts | relocated
                )
        else:
            new_root_facts = previous_facts | relocated if relocated else previous_facts
        facts_changed = new_root_facts is not previous_facts and new_root_facts != previous_facts

        previous_guarantees = self._guarantees_by_root.get(root, _EMPTY_FROZENSET)
        if previous_guarantees or (strong and contaminating):
            written_kinds = {fact.kind for fact in relocated}
            root_guarantees_mut = {
                guarantee
                for guarantee in previous_guarantees
                if not location.may_overlap(guarantee[0]) or guarantee[1] not in written_kinds
            }
            if strong:
                root_guarantees_mut.update((location, fact.kind) for fact in contaminating)
                root_guarantees_mut.difference_update((location, fact.kind) for fact in relocated)
            root_guarantees = (
                frozenset(root_guarantees_mut) if root_guarantees_mut else _EMPTY_FROZENSET
            )
            guarantees_changed = root_guarantees != previous_guarantees
        else:
            root_guarantees = previous_guarantees
            guarantees_changed = False

        if self.provenance_is_top:
            provenance, provenance_is_top = _EMPTY_FROZENSET, True
            provenance_changed = False
        elif not relocations:
            provenance, provenance_is_top = self.provenance, False
            provenance_changed = False
        else:
            new_edges = [
                _intern_edge(
                    source.provenance_node,
                    target.provenance_node,
                    operation,
                    filename,
                    line,
                    detail,
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
                    provenance, provenance_is_top = _EMPTY_FROZENSET, True
                else:
                    provenance, provenance_is_top = merged, False
                provenance_changed = True

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
            fact_index = dict(self._facts_by_root)
            if new_root_facts:
                fact_index[root] = new_root_facts
            else:
                fact_index.pop(root, None)
        else:
            fact_index = self._facts_by_root

        if guarantees_changed:
            guarantee_index = dict(self._guarantees_by_root)
            if root_guarantees:
                guarantee_index[root] = root_guarantees
            else:
                guarantee_index.pop(root, None)
        else:
            guarantee_index = self._guarantees_by_root

        return TaintState._from_indexed(
            reachable=True,
            facts_by_root=fact_index,
            guarantees_by_root=guarantee_index,
            provenance=provenance,
            provenance_is_top=provenance_is_top,
            uncertainties=uncertainties,
            max_provenance_edges=self.max_provenance_edges,
            max_access_path=self.max_access_path,
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
        root = location.root
        previous_facts = self._facts_by_root.get(root, _EMPTY_FROZENSET)
        removed = frozenset(
            fact
            for fact in previous_facts
            if location.is_prefix_of(fact.location) and (remove_all or fact.kind in removed_kinds)
        )
        previous_guarantees = self._guarantees_by_root.get(root, _EMPTY_FROZENSET)
        root_guarantees_mut = set(previous_guarantees)
        if record_guarantee:
            concrete_kinds = {fact.kind for fact in removed} if remove_all else removed_kinds
            root_guarantees_mut.update((location, kind) for kind in concrete_kinds)
        root_guarantees = (
            frozenset(root_guarantees_mut) if root_guarantees_mut else _EMPTY_FROZENSET
        )
        guarantees_changed = root_guarantees != previous_guarantees
        if not removed and not guarantees_changed:
            return self
        if removed:
            fact_index = dict(self._facts_by_root)
            remaining = previous_facts - removed
            if remaining:
                fact_index[root] = remaining
            else:
                fact_index.pop(root, None)
        else:
            fact_index = self._facts_by_root
        if guarantees_changed:
            guarantee_index = dict(self._guarantees_by_root)
            if root_guarantees:
                guarantee_index[root] = root_guarantees
            else:
                guarantee_index.pop(root, None)
        else:
            guarantee_index = self._guarantees_by_root
        return TaintState._from_indexed(
            reachable=True,
            facts_by_root=fact_index,
            guarantees_by_root=guarantee_index,
            provenance=self.provenance,
            provenance_is_top=self.provenance_is_top,
            uncertainties=self.uncertainties,
            max_provenance_edges=self.max_provenance_edges,
            max_access_path=self.max_access_path,
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
        dest_root = destination.root
        prev_dest_guars = result._guarantees_by_root.get(dest_root, _EMPTY_FROZENSET)
        if extra_guarantees <= prev_dest_guars:
            return result
        guarantee_index = dict(result._guarantees_by_root)
        guarantee_index[dest_root] = prev_dest_guars | extra_guarantees
        return TaintState._from_indexed(
            reachable=result.reachable,
            facts_by_root=result._facts_by_root,
            guarantees_by_root=guarantee_index,
            provenance=result.provenance,
            provenance_is_top=result.provenance_is_top,
            uncertainties=result.uncertainties,
            max_provenance_edges=result.max_provenance_edges,
            max_access_path=result.max_access_path,
        )

    def with_uncertainty(self, uncertainty: AnalysisUncertainty) -> "TaintState":
        if not self.reachable or uncertainty in self.uncertainties:
            return self
        return TaintState._from_indexed(
            reachable=True,
            facts_by_root=self._facts_by_root,
            guarantees_by_root=self._guarantees_by_root,
            provenance=self.provenance,
            provenance_is_top=self.provenance_is_top,
            uncertainties=self.uncertainties | {uncertainty},
            max_provenance_edges=self.max_provenance_edges,
            max_access_path=self.max_access_path,
        )

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
            return _EMPTY_FROZENSET, True
        values = frozenset(edges)
        if len(values) > self.max_provenance_edges:
            return _EMPTY_FROZENSET, True
        return values, False

    def _join_provenance(
        self, other: "TaintState", limit: int
    ) -> tuple[frozenset[ProvenanceEdge], bool]:
        if self.provenance_is_top or other.provenance_is_top:
            return _EMPTY_FROZENSET, True
        values = self.provenance | other.provenance
        if len(values) > limit:
            return _EMPTY_FROZENSET, True
        return values, False

    @staticmethod
    def _normalize_facts(facts: Iterable[TaintFact], max_access_path: int) -> frozenset[TaintFact]:
        return frozenset(
            _intern_fact(fact.location.summarize(max_access_path), fact.kind, fact.origin)
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
    def _normalize_facts_by_root(
        facts_by_root: dict[object, frozenset[TaintFact]], max_access_path: int
    ) -> dict[object, frozenset[TaintFact]]:
        if not facts_by_root:
            return _EMPTY_MAP
        normalized: dict[object, frozenset[TaintFact]] = {}
        for root, rfacts in facts_by_root.items():
            if all(len(fact.location.selectors) <= max_access_path for fact in rfacts):
                normalized[root] = rfacts
            else:
                normalized[root] = frozenset(
                    (
                        fact
                        if len(fact.location.selectors) <= max_access_path
                        else _intern_fact(
                            fact.location.summarize(max_access_path), fact.kind, fact.origin
                        )
                    )
                    for fact in rfacts
                )
        return normalized

    @staticmethod
    def _normalize_guarantees_by_root(
        guarantees_by_root: dict[object, frozenset[tuple[TaintLocation, str]]],
        max_access_path: int,
    ) -> dict[object, frozenset[tuple[TaintLocation, str]]]:
        if not guarantees_by_root:
            return _EMPTY_MAP
        normalized: dict[object, frozenset[tuple[TaintLocation, str]]] = {}
        for root, rguars in guarantees_by_root.items():
            if all(len(loc.selectors) <= max_access_path for loc, _ in rguars):
                normalized[root] = rguars
            else:
                normalized[root] = frozenset(
                    (
                        (loc, kind)
                        if len(loc.selectors) <= max_access_path
                        else (loc.summarize(max_access_path), kind)
                    )
                    for loc, kind in rguars
                )
        return normalized

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
