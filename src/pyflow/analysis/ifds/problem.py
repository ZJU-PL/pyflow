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
        return ComposedEdgeFunction(self, previous)

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
        return JoinedEdgeFunction(self, other, join_values)


@dataclass(frozen=True)
class IdentityEdgeFunction(EdgeFunction[ValueT]):
    """Identity transfer."""

    def compute(self, value: ValueT) -> ValueT:
        return value


@dataclass(frozen=True)
class ConstantEdgeFunction(EdgeFunction[ValueT]):
    """Constant transfer, useful for seeds and summaries."""

    constant: ValueT

    def compute(self, value: ValueT) -> ValueT:
        return self.constant

    def compose(self, previous: EdgeFunction[ValueT]) -> EdgeFunction[ValueT]:
        return self


@dataclass(frozen=True)
class ComposedEdgeFunction(EdgeFunction[ValueT]):
    """Composition ``outer(inner(x))``."""

    outer: EdgeFunction[ValueT]
    inner: EdgeFunction[ValueT]

    def compute(self, value: ValueT) -> ValueT:
        return self.outer(self.inner(value))


@dataclass(frozen=True)
class JoinedEdgeFunction(EdgeFunction[ValueT]):
    """Pointwise join of two edge functions."""

    left: EdgeFunction[ValueT]
    right: EdgeFunction[ValueT]
    join_values: Callable[[ValueT, ValueT], ValueT]

    def compute(self, value: ValueT) -> ValueT:
        return self.join_values(self.left(value), self.right(value))


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
