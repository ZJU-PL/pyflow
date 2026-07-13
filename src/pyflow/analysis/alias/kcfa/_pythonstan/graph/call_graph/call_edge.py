from typing import Dict, Set, Optional, TypeVar, Generic, Tuple
from enum import Enum


__all__ = ["CallKind", "CallEdge"]

CallSite = TypeVar("CallSite")
Method = TypeVar('Method')


class CallKind(Enum):
    INSTANCE = 1
    STATIC = 2
    FUNCTION = 3
    CLASS = 4
    MODULE = 5
    OTHER = 6


class CallEdge(Generic[CallSite, Method]):
    kind: CallKind
    callsite: CallSite
    callee: Method

    def __init__(self, kind: CallKind, callsite: CallSite, callee: Method):
        self.kind = kind
        self.callsite = callsite
        self.callee = callee

    def get_kind(self) -> CallKind:
        return self.kind

    def get_callsite(self) -> CallSite:
        return self.callsite

    def get_callee(self) -> Method:
        return self.callee

    def __eq__(self, other):
        if other is None or not type(self) != type(other):
            return False
        return (self.kind, self.callsite, self.callee) == (other.kind, other.callsite, other.callee)

    def __hash__(self):
        return hash((self.kind, self.callsite, self.callee))
