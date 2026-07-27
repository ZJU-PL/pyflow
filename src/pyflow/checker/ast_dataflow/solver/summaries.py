"""Relational, outcome-sensitive summaries for interprocedural taint."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from ..domain import AccessSelector, AnalysisUncertainty


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
        mapping = dict(self.mapped_kinds)
        remove_all = "*" in self.removed_kinds
        result = set()
        for kind in incoming:
            if self.kinds != frozenset({"*"}) and kind not in self.kinds:
                continue
            if remove_all or kind in self.removed_kinds:
                continue
            result.add(mapping.get(kind, kind))
        return frozenset(result)


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

    def propagate(
        self,
        inputs: Mapping[SummaryPort, Iterable[str]],
    ) -> dict[SummaryPort, frozenset[str]]:
        """Instantiate the summary and close its finite relation to a fixpoint."""

        values = {port: frozenset(kinds) for port, kinds in inputs.items()}
        for port, kind in self.seeds:
            values[port] = values.get(port, frozenset()) | {kind}
        changed = True
        while changed:
            changed = False
            for relation in self.relations:
                incoming = values.get(relation.source, frozenset())
                produced = relation.transform(incoming)
                if not produced:
                    continue
                current = values.get(relation.target, frozenset())
                joined = current | produced
                if joined != current:
                    values[relation.target] = joined
                    changed = True
        return values

    def propagate_tokens(
        self,
        inputs: Mapping[SummaryPort, Iterable[tuple[str, object]]],
    ) -> dict[SummaryPort, frozenset[tuple[str, object]]]:
        """Propagate kinds while preserving their caller-side origin token."""

        values = {port: frozenset(tokens) for port, tokens in inputs.items()}
        for port, kind in self.seeds:
            token = ("summary-seed", self.procedure, port, kind)
            values[port] = values.get(port, frozenset()) | {(kind, token)}
        changed = True
        while changed:
            changed = False
            for relation in self.relations:
                incoming = values.get(relation.source, frozenset())
                produced = frozenset(
                    (output_kind, token)
                    for input_kind, token in incoming
                    for output_kind in relation.transform({input_kind})
                )
                if not produced:
                    continue
                current = values.get(relation.target, frozenset())
                joined = current | produced
                if joined != current:
                    values[relation.target] = joined
                    changed = True
        return values
