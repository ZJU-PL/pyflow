"""Generic mutable call-graph storage and query operations."""

from typing import Dict, Set, Optional, TypeVar, Generic
from abc import ABC, abstractmethod

from .call_edge import CallEdge


__all__ = ["AbstractCallGraph"]

CallSite = TypeVar("CallSite")
Method = TypeVar('Method')


class AbstractCallGraph(Generic[CallSite, Method], ABC):
    """Index call edges by call site, callee, and containing scope.

    Subclasses choose concrete representations while this base provides edge
    insertion, reverse indexes, and common reachability queries.
    """

    callsite_to_edges: Dict[CallSite, Set[CallEdge[CallSite, Method]]]
    callee_to_edges: Dict[Method, Set[CallEdge[CallSite, Method]]]
    callsite_to_container: Dict[CallSite, Method]
    callsites_in: Dict[Method, Set[CallSite]]
    entry_scopes: Set[Method]
    reachable_scopes: Set[Method]
    edges: Set[CallEdge[CallSite, Method]]

    @abstractmethod
    def __init__(self):
        self.callsite_to_edges = {}
        self.callee_to_edges = {}
        self.callsite_to_container = {}
        self.callsites_in = {}
        self.entry_scopes = {*()}
        self.reachable_scopes = {*()}
        self.edges = {*()}
    
    def add_edge(self, edge: CallEdge[CallSite, Method]):
        """Insert an edge and update all reverse and reachability indexes."""
        if edge.get_callsite() not in self.callsite_to_edges:
            self.callsite_to_edges[edge.get_callsite()] = {*()}
        if edge.get_callee() not in self.callee_to_edges:
            self.callee_to_edges[edge.get_callee()] = {*()}
        if edge.get_callee() not in self.callsites_in:
            self.callsites_in[edge.get_callee()] = {*()}
        self.callsite_to_edges[edge.get_callsite()].add(edge)
        self.callee_to_edges[edge.get_callee()].add(edge)
        self.callsite_to_container[edge.get_callsite()] = edge.get_callee()
        self.callsites_in[edge.get_callee()].add(edge.get_callsite())
        self.reachable_scopes.add(edge.get_callee())
        self.edges.add(edge)

    def get_callers_of(self, callee: Method) -> Set[CallSite]:
        """Return call sites that may target ``callee``."""
        return {e.get_callsite() for e in self.callee_to_edges.get(callee, {*()})}

    def get_callees_of(self, callsite: CallSite) -> Set[Method]:
        """Return possible callees for ``callsite``."""
        return {e.get_callee() for e in self.callsite_to_edges.get(callsite, {*()})}

    def get_callees_of_scope(self, caller: Method) -> Set[Method]:
        """Return callees reached from call sites contained in ``caller``."""
        ret = {*()}
        for callsite in self.callsites_in.get(caller, {*()}):
            ret.update(self.get_callees_of(callsite))
        return ret

    def get_container_of(self, callsite: CallSite) -> Optional[Method]:
        """Return the scope associated with ``callsite``, if recorded."""
        return self.callsite_to_container.get(callsite, None)

    def get_callsites_in(self, scope: Method) -> Set[CallSite]:
        """Return call sites recorded for ``scope``."""
        return self.callsites_in.get(scope, {*()})

    def edges_out_of(self, callsite: CallSite) -> Set[CallEdge[CallSite, Method]]:
        return self.callsite_to_edges.get(callsite, {*()})

    def edges_in_to(self, callee: CallSite) -> Set[CallEdge[CallSite, Method]]:
        return self.callee_to_edges.get(callee, {*()})

    def get_edges(self) -> Set[CallEdge[CallSite, Method]]:
        return self.edges
    
    def get_number_of_edges(self) -> int:
        return len(self.edges)
    
    def get_nodes(self) -> Set[Method]:
        return self.reachable_scopes
