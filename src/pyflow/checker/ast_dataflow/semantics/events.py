"""Semantic events emitted by the formal AST transfer functions."""

from __future__ import annotations

from dataclasses import dataclass

from ..domain import TaintFact


@dataclass(frozen=True)
class TaintSinkEvent:
    procedure: str
    filename: str | None
    sink_name: str
    sink_kinds: frozenset[str]
    argument_index: int | None
    line: int | None
    facts: frozenset[TaintFact]

    @property
    def source_kinds(self) -> frozenset[str]:
        return frozenset(fact.kind for fact in self.facts)
