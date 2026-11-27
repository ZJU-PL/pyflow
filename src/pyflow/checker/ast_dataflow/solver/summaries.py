"""Relational, outcome-sensitive summaries for interprocedural taint."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Iterable, Mapping

from pyflow.checker.common.taint import AccessSelector, AnalysisUncertainty

_WILDCARD_KINDS = frozenset({"*"})


class SummaryPortKind(str, Enum):
    PARAMETER = "parameter"
    RECEIVER = "receiver"
    GLOBAL = "global"
    SOURCE = "source"
    RETURN = "return"
    YIELD = "yield"
    RAISE = "raise"
    SINK = "sink"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class SummaryPort:
    kind: SummaryPortKind
    name: str | None = None
    index: int | None = None
    path: tuple[AccessSelector, ...] = ()

    def select(self, *path: AccessSelector | str | int) -> "SummaryPort":
        selectors = tuple(self._coerce_selector(item) for item in path)
        return SummaryPort(self.kind, self.name, self.index, (*self.path, *selectors))

    @staticmethod
    def _coerce_selector(selector: AccessSelector | str | int) -> AccessSelector:
        if isinstance(selector, AccessSelector):
            return selector
        if isinstance(selector, int):
            return AccessSelector.index(selector)
        return AccessSelector.attribute(selector)


@dataclass(frozen=True, order=True)
class SummaryRelation:
    """A dependency from one procedure port to another."""

    source: SummaryPort
    target: SummaryPort
    kinds: frozenset[str] = frozenset({"*"})
    mapped_kinds: tuple[tuple[str, str], ...] = ()
    removed_kinds: frozenset[str] = frozenset()
    guard: str | None = None

    def transform(self, incoming: Iterable[str]) -> frozenset[str]:
        if not incoming:
            return frozenset()
        remove_all = "*" in self.removed_kinds
        if remove_all:
            return frozenset()
        allow_all = self.kinds == _WILDCARD_KINDS
        if not self.mapped_kinds and not self.removed_kinds:
            if isinstance(incoming, frozenset):
                return incoming if allow_all else incoming & self.kinds
            if allow_all:
                return frozenset(incoming)
            return frozenset(kind for kind in incoming if kind in self.kinds)
        mapping = dict(self.mapped_kinds) if self.mapped_kinds else None
        removed = self.removed_kinds
        result = set()
        for kind in incoming:
            if not allow_all and kind not in self.kinds:
                continue
            if removed and kind in removed:
                continue
            result.add(mapping.get(kind, kind) if mapping is not None else kind)
        return frozenset(result)

    def transform_one(self, kind: str) -> str | None:
        if "*" in self.removed_kinds or (self.removed_kinds and kind in self.removed_kinds):
            return None
        if self.kinds != _WILDCARD_KINDS and kind not in self.kinds:
            return None
        if not self.mapped_kinds:
            return kind
        for src, dst in self.mapped_kinds:
            if src == kind:
                return dst
        return kind


@dataclass(frozen=True, order=True)
class SummarySinkEvent:
    sink_name: str
    argument_index: int | None
    port: SummaryPort
    line: int | None = None
    procedure: str | None = None
    filename: str | None = None


@dataclass(frozen=True, order=True)
class SummaryKillEffect:
    port: SummaryPort
    kinds: frozenset[str]


@dataclass(frozen=True)
class ProcedureTaintSummary:
    """Finite monotone relation across parameters, heap paths, and outcomes."""

    procedure: str
    parameters: tuple[str, ...] = ()
    seeds: frozenset[tuple[SummaryPort, str]] = frozenset()
    relations: frozenset[SummaryRelation] = frozenset()
    writes: frozenset[SummaryPort] = frozenset()
    kills: frozenset[SummaryKillEffect] = frozenset()
    sinks: frozenset[SummarySinkEvent] = frozenset()
    uncertainties: frozenset[AnalysisUncertainty] = frozenset()

    def leq(self, other: "ProcedureTaintSummary") -> bool:
        if self.procedure != other.procedure:
            return False
        return (
            self.parameters == other.parameters
            and self.seeds <= other.seeds
            and self.relations <= other.relations
            and self.writes <= other.writes
            and self.kills <= other.kills
            and self.sinks <= other.sinks
            and self.uncertainties <= other.uncertainties
        )

    def join(self, other: "ProcedureTaintSummary") -> "ProcedureTaintSummary":
        if self.procedure != other.procedure:
            raise ValueError("cannot join summaries for different procedures")
        if self.parameters and other.parameters and self.parameters != other.parameters:
            raise ValueError("cannot join summaries with different parameter lists")
        return ProcedureTaintSummary(
            procedure=self.procedure,
            parameters=self.parameters or other.parameters,
            seeds=self.seeds | other.seeds,
            relations=self.relations | other.relations,
            writes=self.writes | other.writes,
            kills=self.kills | other.kills,
            sinks=self.sinks | other.sinks,
            uncertainties=self.uncertainties | other.uncertainties,
        )

    @cached_property
    def _relations_by_source(self) -> dict[SummaryPort, tuple[SummaryRelation, ...]]:
        grouped: dict[SummaryPort, list[SummaryRelation]] = {}
        for relation in self.relations:
            grouped.setdefault(relation.source, []).append(relation)
        return {port: tuple(items) for port, items in grouped.items()}

    def propagate(
        self,
        inputs: Mapping[SummaryPort, Iterable[str]],
    ) -> dict[SummaryPort, frozenset[str]]:
        """Instantiate the summary and close its finite relation to a fixpoint."""

        values: dict[SummaryPort, set[str]] = {port: set(kinds) for port, kinds in inputs.items()}
        for port, kind in self.seeds:
            values.setdefault(port, set()).add(kind)
        if not self.relations:
            return {port: frozenset(kinds) for port, kinds in values.items()}
        by_source = self._relations_by_source
        worklist = [port for port, kinds in values.items() if kinds and port in by_source]
        in_worklist = set(worklist)
        while worklist:
            source_port = worklist.pop()
            in_worklist.discard(source_port)
            incoming = values.get(source_port)
            if not incoming:
                continue
            for relation in by_source[source_port]:
                produced = relation.transform(incoming)
                if not produced:
                    continue
                target = relation.target
                current = values.get(target)
                if current is None:
                    values[target] = set(produced)
                    if target in by_source and target not in in_worklist:
                        in_worklist.add(target)
                        worklist.append(target)
                elif not produced <= current:
                    current.update(produced)
                    if target in by_source and target not in in_worklist:
                        in_worklist.add(target)
                        worklist.append(target)
        return {port: frozenset(kinds) for port, kinds in values.items()}

    def propagate_tokens(
        self,
        inputs: Mapping[SummaryPort, Iterable[tuple[str, object]]],
    ) -> dict[SummaryPort, frozenset[tuple[str, object]]]:
        """Propagate kinds while preserving their caller-side origin token."""

        values: dict[SummaryPort, set[tuple[str, object]]] = {
            port: set(tokens) for port, tokens in inputs.items()
        }
        for port, kind in self.seeds:
            token = ("summary-seed", self.procedure, port, kind)
            values.setdefault(port, set()).add((kind, token))
        if not self.relations:
            return {port: frozenset(tokens) for port, tokens in values.items()}
        by_source = self._relations_by_source
        worklist = [port for port, tokens in values.items() if tokens and port in by_source]
        in_worklist = set(worklist)
        while worklist:
            source_port = worklist.pop()
            in_worklist.discard(source_port)
            incoming = values.get(source_port)
            if not incoming:
                continue
            for relation in by_source[source_port]:
                target = relation.target
                current = values.get(target)
                added = False
                if (
                    relation.kinds == _WILDCARD_KINDS
                    and not relation.mapped_kinds
                    and not relation.removed_kinds
                ):
                    if current is None:
                        values[target] = set(incoming)
                        added = True
                    elif not incoming <= current:
                        current.update(incoming)
                        added = True
                elif not relation.mapped_kinds and not relation.removed_kinds:
                    rel_kinds = relation.kinds
                    if current is None:
                        new_set = {item for item in incoming if item[0] in rel_kinds}
                        if new_set:
                            values[target] = new_set
                            added = True
                    else:
                        before = len(current)
                        for item in incoming:
                            if item[0] in rel_kinds:
                                current.add(item)
                        added = len(current) != before
                else:
                    for input_kind, token in incoming:
                        output_kind = relation.transform_one(input_kind)
                        if output_kind is None:
                            continue
                        pair = (output_kind, token)
                        if current is None:
                            current = {pair}
                            values[target] = current
                            added = True
                        elif pair not in current:
                            current.add(pair)
                            added = True
                if added and target in by_source and target not in in_worklist:
                    in_worklist.add(target)
                    worklist.append(target)
        return {port: frozenset(tokens) for port, tokens in values.items()}
