"""Problem definitions and edge-function utilities for IFDS/IDE."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Generic, Hashable, Mapping, TypeVar

from .supergraph import NodeT, ProcT, Supergraph


FactT = TypeVar("FactT", bound=Hashable)
ValueT = TypeVar("ValueT")


class EdgeFunction(Generic[ValueT], ABC):
    """A transfer function attached to an exploded-graph edge."""

    @abstractmethod
    def compute(self, value: ValueT) -> ValueT:
        raise NotImplementedError

    def __call__(self, value: ValueT) -> ValueT:
        return self.compute(value)

    def compose(self, previous: "EdgeFunction[ValueT]") -> "EdgeFunction[ValueT]":
        if isinstance(self, IdentityEdgeFunction):
            return previous
        if isinstance(previous, IdentityEdgeFunction):
            return self
        if isinstance(previous, JoinedEdgeFunction):
            return self.compose(previous.left).join(
                self.compose(previous.right),
                previous.join_values,
            )
        return ComposedEdgeFunction.from_functions(self, previous)

    def is_idempotent(self) -> bool:
        """Return whether repeated self-composition is semantically stable."""
        return False

    def join(
        self,
        other: "EdgeFunction[ValueT]",
        join_values: Callable[[ValueT, ValueT], ValueT],
    ) -> "EdgeFunction[ValueT]":
        if self == other:
            return self
        if isinstance(self, IdentityEdgeFunction) and isinstance(
            other, IdentityEdgeFunction
        ):
            return self
        return JoinedEdgeFunction.from_functions(self, other, join_values)


@dataclass(frozen=True)
class IdentityEdgeFunction(EdgeFunction[ValueT]):
    """Identity transfer."""

    def compute(self, value: ValueT) -> ValueT:
        return value

    def is_idempotent(self) -> bool:
        return True


@dataclass(frozen=True)
class ConstantEdgeFunction(EdgeFunction[ValueT]):
    """Constant transfer, useful for seeds and summaries."""

    constant: ValueT

    def compute(self, value: ValueT) -> ValueT:
        return self.constant

    def compose(self, previous: EdgeFunction[ValueT]) -> EdgeFunction[ValueT]:
        return self

    def is_idempotent(self) -> bool:
        return True


@dataclass(frozen=True)
class ComposedEdgeFunction(EdgeFunction[ValueT]):
    """Composition ``outer(inner(x))``."""

    outer: EdgeFunction[ValueT]
    inner: EdgeFunction[ValueT]

    @classmethod
    def from_functions(
        cls,
        outer: EdgeFunction[ValueT],
        inner: EdgeFunction[ValueT],
    ) -> EdgeFunction[ValueT]:
        terms = cls._normalize_terms((*cls._iter_terms(outer), *cls._iter_terms(inner)))
        if len(terms) == 1:
            return terms[0]

        composed: EdgeFunction[ValueT] = terms[-1]
        for term in reversed(terms[:-1]):
            composed = cls(term, composed)
        return composed

    @classmethod
    def _iter_terms(
        cls, function: EdgeFunction[ValueT]
    ) -> tuple[EdgeFunction[ValueT], ...]:
        if isinstance(function, ComposedEdgeFunction):
            return (*cls._iter_terms(function.outer), *cls._iter_terms(function.inner))
        return (function,)

    @classmethod
    def _normalize_terms(
        cls, terms: tuple[EdgeFunction[ValueT], ...]
    ) -> tuple[EdgeFunction[ValueT], ...]:
        normalized: list[EdgeFunction[ValueT]] = []
        for term in terms:
            if (
                normalized
                and normalized[-1] == term
                and term.is_idempotent()
            ):
                continue
            normalized.append(term)
        return tuple(normalized)

    def compute(self, value: ValueT) -> ValueT:
        return self.outer(self.inner(value))


@dataclass(frozen=True)
class JoinedEdgeFunction(EdgeFunction[ValueT]):
    """Pointwise join of two edge functions."""

    left: EdgeFunction[ValueT]
    right: EdgeFunction[ValueT]
    join_values: Callable[[ValueT, ValueT], ValueT]

    @classmethod
    def from_functions(
        cls,
        left: EdgeFunction[ValueT],
        right: EdgeFunction[ValueT],
        join_values: Callable[[ValueT, ValueT], ValueT],
    ) -> EdgeFunction[ValueT]:
        terms = cls._merge_terms(left, right, join_values)
        if len(terms) == 1:
            return terms[0]

        joined: EdgeFunction[ValueT] = terms[0]
        for term in terms[1:]:
            joined = cls(joined, term, join_values)
        return joined

    @classmethod
    def _merge_terms(
        cls,
        left: EdgeFunction[ValueT],
        right: EdgeFunction[ValueT],
        join_values: Callable[[ValueT, ValueT], ValueT],
    ) -> tuple[EdgeFunction[ValueT], ...]:
        merged: list[EdgeFunction[ValueT]] = []
        for term in cls._iter_terms(left, join_values):
            if term not in merged:
                merged.append(term)
        for term in cls._iter_terms(right, join_values):
            if term not in merged:
                merged.append(term)
        return tuple(merged)

    @classmethod
    def _iter_terms(
        cls,
        function: EdgeFunction[ValueT],
        join_values: Callable[[ValueT, ValueT], ValueT],
    ) -> tuple[EdgeFunction[ValueT], ...]:
        if isinstance(function, JoinedEdgeFunction) and function.join_values == join_values:
            return cls._merge_terms(function.left, function.right, join_values)
        return (function,)

    def compute(self, value: ValueT) -> ValueT:
        return self.join_values(self.left(value), self.right(value))

    def compose(self, previous: EdgeFunction[ValueT]) -> EdgeFunction[ValueT]:
        return self.left.compose(previous).join(
            self.right.compose(previous),
            self.join_values,
        )


@dataclass(frozen=True)
class FactTransition(Generic[FactT]):
    """IFDS transition to a new fact."""

    fact: FactT


@dataclass(frozen=True)
class ValueTransition(Generic[FactT, ValueT]):
    """IDE transition to a new fact with an edge function."""

    fact: FactT
    edge_function: EdgeFunction[ValueT]


class IFDSProblem(Generic[ProcT, NodeT, FactT], ABC):
    """Abstract IFDS problem over a :class:`Supergraph`."""

    @property
    @abstractmethod
    def supergraph(self) -> Supergraph[ProcT, NodeT]:
        raise NotImplementedError

    @property
    @abstractmethod
    def zero_fact(self) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def initial_seeds(self) -> Mapping[NodeT, frozenset[FactT]]:
        raise NotImplementedError

    def normal_flow(self, node: NodeT, successor: NodeT, fact: FactT):
        return ()

    def call_flow(self, call_node: NodeT, callee: ProcT, fact: FactT):
        return ()

    def return_flow(
        self,
        call_node: NodeT,
        callee: ProcT,
        exit_node: NodeT,
        return_site: NodeT,
        call_fact: FactT,
        exit_fact: FactT,
    ):
        return ()

    def call_to_return_flow(self, call_node: NodeT, return_site: NodeT, fact: FactT):
        return ()


class IDEProblem(Generic[ProcT, NodeT, FactT, ValueT], ABC):
    """Abstract IDE problem over a :class:`Supergraph`."""

    @property
    @abstractmethod
    def supergraph(self) -> Supergraph[ProcT, NodeT]:
        raise NotImplementedError

    @property
    @abstractmethod
    def zero_fact(self) -> FactT:
        raise NotImplementedError

    @property
    @abstractmethod
    def bottom_value(self) -> ValueT:
        raise NotImplementedError

    @abstractmethod
    def join_values(self, left: ValueT, right: ValueT) -> ValueT:
        raise NotImplementedError

    @abstractmethod
    def initial_seed_values(self) -> Mapping[tuple[NodeT, FactT], ValueT]:
        raise NotImplementedError

    def normal_flow(
        self, node: NodeT, successor: NodeT, fact: FactT
    ) -> tuple[ValueTransition[FactT, ValueT], ...]:
        return ()

    def call_flow(
        self, call_node: NodeT, callee: ProcT, fact: FactT
    ) -> tuple[ValueTransition[FactT, ValueT], ...]:
        return ()

    def return_flow(
        self,
        call_node: NodeT,
        callee: ProcT,
        exit_node: NodeT,
        return_site: NodeT,
        call_fact: FactT,
        exit_fact: FactT,
    ) -> tuple[ValueTransition[FactT, ValueT], ...]:
        return ()

    def call_to_return_flow(
        self, call_node: NodeT, return_site: NodeT, fact: FactT
    ) -> tuple[ValueTransition[FactT, ValueT], ...]:
        return ()


class ZeroFact:
    """The ⊥ element — carries no dataflow information and is NOT a domain fact.

    In IFDS theory, ⊥ is distinct from every fact d ∈ D.  Using a dedicated
    sentinel rather than a string constant or ``None`` makes the distinction
    explicit, prevents accidental collisions with domain facts, and enables
    type-checkable ``fact is ZERO`` guards.

    ``ZeroFact`` is a singleton: ``ZeroFact()`` always returns the same object.
    """

    _instance: "ZeroFact | None" = None

    def __new__(cls) -> "ZeroFact":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __hash__(self) -> int:
        return 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ZeroFact) or other is self

    def __repr__(self) -> str:
        return "⊥"


ZERO = ZeroFact()


@dataclass(frozen=True)
class IdentityFlow(Generic[FactT]):
    """Pass-through combinator for IFDS flow functions.

    ``{fact} → {ZERO}`` when *fact* is the zero fact, otherwise
    ``{fact} → {fact}``.
    """

    zero: FactT

    def __call__(self, fact: FactT) -> tuple[FactT, ...]:
        if fact == self.zero or fact is self.zero:
            return (self.zero,)
        return (fact,)


@dataclass(frozen=True)
class KillFlow(Generic[FactT]):
    """Kill combinator: ``{fact} → ∅`` for strong updates."""

    def __call__(self, fact: FactT) -> tuple[FactT, ...]:
        return ()


@dataclass(frozen=True)
class GenFlow(Generic[FactT]):
    """Generate combinator: ``{⊥} → {generated}``, otherwise ``{fact, generated}``."""

    generated: FactT
    zero: FactT

    def __call__(self, fact: FactT) -> tuple[FactT, ...]:
        if fact == self.zero or fact is self.zero:
            return (self.generated,)
        return (fact, self.generated)
