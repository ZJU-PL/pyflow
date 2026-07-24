"""Typed call-graph edges shared by pointer and call analyses."""

from typing import Dict, Set, Optional, TypeVar, Generic, Tuple
from enum import Enum


__all__ = ["CallKind", "CallEdge"]

CallSite = TypeVar("CallSite")
Method = TypeVar('Method')


class CallKind(Enum):
    """Kinds of callable targets represented in a call graph."""

    INSTANCE = 1
    STATIC = 2
    FUNCTION = 3
    CLASS = 4
    MODULE = 5
    OTHER = 6


class CallEdge(Generic[CallSite, Method]):
    """A hashable edge from a call site to one possible callee."""

    kind: CallKind
    callsite: CallSite
    callee: Method

    def __init__(self, kind: CallKind, callsite: CallSite, callee: Method):
        self.kind = kind
        self.callsite = callsite
        self.callee = callee

    def get_kind(self) -> CallKind:
        """Return the dispatch kind of this edge."""
        return self.kind

    def get_callsite(self) -> CallSite:
        """Return the source call site."""
        return self.callsite

    def get_callee(self) -> Method:
        """Return the possible target callable or scope."""
        return self.callee

    def __eq__(self, other):
        if other is None or not type(self) != type(other):
            return False
        return (self.kind, self.callsite, self.callee) == (other.kind, other.callsite, other.callee)

    def __hash__(self):
        return hash((self.kind, self.callsite, self.callee))
