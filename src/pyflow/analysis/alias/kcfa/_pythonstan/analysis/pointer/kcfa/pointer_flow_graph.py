"""Pointer-flow graph nodes, edges, and propagation operations.

The graph records inclusion relationships between context-qualified variables.
Special nodes filter flow for inheritance, descriptor, and MRO semantics before
new points-to facts are placed on the solver worklist.
"""

from dataclasses import dataclass
from typing import Dict, FrozenSet, Tuple, Set, Optional, Iterable, Any, TYPE_CHECKING, List, Callable
from enum import Enum
from abc import ABC, abstractmethod

from .context import Ctx
from .object import InstanceObject, ClassObject
from .points_to_set import PointsToSet
if TYPE_CHECKING:
    from .object import AbstractObject, AllocSite
    from .variable import Variable, FieldAccess    
    from .heap_model import Field
    from pyflow.analysis.alias.kcfa._pythonstan.world.scope_manager import ScopeManager
    from .constraints import ConstraintManager
    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRModule, IRStatement
    from .variable import VariableFactory, VariableKind
    from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph import AbstractCallGraph, CallEdge
    from .context import CallSite, AbstractContext, Scope

__all__ = [
    "PointerFlowGraph", "PointerFlowEdge", "PointerFlowNode", "NormalNode",
    "GuardNode", "SelectorNode", "ClassBindingNode", "InstanceBindingNode",
    "PointerFlowKind",
]


class PointerFlowKind(Enum):
    """Kinds of points-to flow in pointer flow graph."""
    
    NORMAL = "normal"
    INHERIT = "inherit"
    INSTANCE = "instance"


@dataclass(frozen=True)
class PointerFlowEdge:
    """A directed, typed points-to flow between two graph nodes.

    ``INHERIT`` edges rebind methods and class-owned objects to a subclass;
    ``INSTANCE`` edges bind class members to an instance; normal edges preserve
    the incoming points-to set unchanged.
    """

    source: 'PointerFlowNode'
    target: 'PointerFlowNode'
    kind: PointerFlowKind
    
    def __post_init__(self):
        assert isinstance(self.source, PointerFlowNode)
        assert isinstance(self.target, PointerFlowNode)
        assert self.source != self.target, f"source and target cannot be the same: {self.source} -> {self.target}"
        if self.kind == PointerFlowKind.INHERIT:
            assert isinstance(self.target, NormalNode) and isinstance(self.target.var.content.obj, ClassObject)
        if self.kind == PointerFlowKind.INSTANCE:
            assert isinstance(self.target, NormalNode) and isinstance(self.target.var.content.obj, InstanceObject)
    
    def flow_through(self, pts: 'PointsToSet') -> 'PointsToSet':
        if self.kind == PointerFlowKind.INHERIT:
            return pts.inherit_to(self.target.var.content.obj)
        elif self.kind == PointerFlowKind.INSTANCE:
            return pts.deliver_into(self.target.var.content.obj)
        else:
            return pts


class PointerFlowNode(ABC):
    """Base class for nodes that may transform incoming points-to facts."""

    @abstractmethod
    def flow_through(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        pass


@dataclass(frozen=True)
class NormalNode(PointerFlowNode):
    """A context-qualified variable node that accepts all incoming objects."""
    var: Ctx[Any]
    
    def __post_init__(self):
        assert isinstance(self.var, Ctx), f"var must be a Ctx, but got {type(self.var)}"
    
    def flow_through(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        return pts


@dataclass(frozen=True)
class ClassBindingNode(PointerFlowNode):
    """Rebind inherited method objects to the class being looked up."""

    class_obj: ClassObject
    lookup_key: Any

    def flow_through(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        return pts.inherit_to(self.class_obj)


@dataclass(frozen=True)
class InstanceBindingNode(PointerFlowNode):
    """Bind method objects to an instance without inventing a heap field."""

    instance_obj: InstanceObject
    lookup_key: Any

    def flow_through(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        return pts.deliver_into(self.instance_obj)
    

class GuardNode(PointerFlowNode):
    """Filter incoming objects with a caller-provided guard function."""
    
    def __init__(self, guard: 'Callable[[PointerFlowEdge, PointsToSet], PointsToSet]'):
        self.guard = guard
    
    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return self is other

    def flow_through(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        return self.guard(edge, pts)
    

class SelectorNode(PointerFlowNode):
    """Monotonically merge priority candidates.

    Priority cannot safely be inferred from the first non-empty points-to set:
    an earlier candidate may become non-empty later, after lower-priority facts
    have already escaped into the union-only solver.  Definite precedence is
    therefore resolved structurally by the caller; this node conservatively
    merges all remaining ``may exist`` candidates and is independent of
    worklist order.
    """
    edges: Dict[PointerFlowEdge, int]
    least_index: int
    
    def __init__(self, least_index: int = -1):
        self.edges = {}
        self.least_index = least_index
    
    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return self is other
    
    def add_edge(self, edge: PointerFlowEdge, index: int):
        self.edges[edge] = index
    
    def flow_through(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        """Pass every candidate selected by the caller's presence analysis."""
        assert edge in self.edges, f"edge {edge} not found in selector node"
        return pts


class PointerFlowGraph:
    """Store and evaluate points-to inclusion edges.

    The graph owns no points-to sets itself.  :meth:`propagate` transforms a
    delta along outgoing edges and returns the target/delta pairs that the
    solver should enqueue.
    """
    # TODO maybe object can be grouped by age, and too old objects should not be propagated.
    
    succs: Dict[PointerFlowNode, Set[PointerFlowEdge]]
    preds: Dict[PointerFlowNode, Set[PointerFlowEdge]]
    nodes: Set[PointerFlowNode]    
    edges: Set[PointerFlowEdge]
    
    def __init__(self, debug_monitor=None):
        """Initialize pointer flow graph.
        
        Args:
            debug_monitor: Optional DebugMonitor instance for tracking
        """
        self.succs = {}
        self.preds = {}
        self.nodes = set()
        self.edges = set()
        self._edge_ids: Dict[PointerFlowEdge, str] = {}
        
        # Debug monitoring
        self._debug_monitor = debug_monitor
        self._edge_activation_counts: Dict[PointerFlowEdge, int] = {}
        self._edge_object_flow: Dict[PointerFlowEdge, int] = {}
    
    def propagate(self, node: PointerFlowNode, pts: 'PointsToSet') -> 'List[Tuple[PointerFlowNode, PointsToSet]]':
        """Propagate a points-to delta through every live outgoing edge."""
        assert isinstance(node, PointerFlowNode), f"node must be a PFNode, but got {type(node)}"
        result = []
        for succ_edge in self.succs.get(node, frozenset()):
            succ_pts = succ_edge.flow_through(pts)
            if succ_pts.is_empty():
                continue
            succ_pts = succ_edge.target.flow_through(succ_edge, succ_pts)
            if succ_pts.is_empty():
                continue
            
            # Track edge activation
            num_objects = len(succ_pts)
            self._edge_activation_counts[succ_edge] = self._edge_activation_counts.get(succ_edge, 0) + 1
            self._edge_object_flow[succ_edge] = self._edge_object_flow.get(succ_edge, 0) + num_objects
            
            # Debug monitoring
            if self._debug_monitor and self._debug_monitor.enabled and self._debug_monitor.track_pfg:
                edge_id = self._edge_ids[succ_edge]
                self._debug_monitor.record_pfg_edge_activated(edge_id, num_objects)
            
            result.append([succ_edge.target, succ_pts])
        return result

    def add_edge(self, edge: PointerFlowEdge) -> bool:
        """Add ``edge`` and return whether it was new to the graph."""
        if edge not in self.edges:
            self.succs.setdefault(edge.source, {*()}).add(edge)
            self.preds.setdefault(edge.target, {*()}).add(edge)
            self.nodes.add(edge.source)
            self.nodes.add(edge.target)
            self.edges.add(edge)
            self._edge_ids[edge] = f"pfg-edge-{len(self._edge_ids)}"
            return True
        else:
            return False
    
    def flow_through_edge(self, edge: PointerFlowEdge, pts: 'PointsToSet') -> 'PointsToSet':
        """Apply both edge-level and target-node flow transformations."""
        return edge.target.flow_through(edge, edge.flow_through(pts))

    def get_succs(self, var: PointerFlowNode) -> Set[PointerFlowEdge]:
        """Return outgoing edges for ``var``."""
        return self.succs.get(var, {*()})
    
    def get_preds(self, var: PointerFlowNode) -> Set[PointerFlowEdge]:
        """Return incoming edges for ``var``."""
        return self.preds.get(var, {*()})
    
    def get_nodes(self) -> Set[PointerFlowNode]:
        """Return all nodes currently present in the graph."""
        return self.nodes
    
    def get_edges(self) -> Set[PointerFlowEdge]:
        """Return all edges currently present in the graph."""
        return self.edges
    
    def get_edge_statistics(self) -> Dict[str, Any]:
        """Get PFG edge activation statistics.
        
        Returns:
            Dictionary with edge statistics:
            - total_edges: Total number of edges
            - activated_edges: Number of edges that activated at least once
            - dead_edges: Number of edges that never activated
            - total_activations: Sum of all activation counts
            - total_object_flow: Total objects flowed through all edges
            - most_active_edges: Top edges by activation count
            - least_active_edges: Edges with low activation
        """
        activated = [e for e, count in self._edge_activation_counts.items() if count > 0]
        dead = [e for e in self.edges if e not in self._edge_activation_counts]
        
        # Sort by activation count
        sorted_by_count = sorted(
            self._edge_activation_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Sort by object flow
        sorted_by_flow = sorted(
            self._edge_object_flow.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            "total_edges": len(self.edges),
            "activated_edges": len(activated),
            "dead_edges": len(dead),
            "activation_rate": len(activated) / len(self.edges) if self.edges else 0.0,
            "total_activations": sum(self._edge_activation_counts.values()),
            "total_object_flow": sum(self._edge_object_flow.values()),
            "avg_activations_per_edge": (
                sum(self._edge_activation_counts.values()) / len(activated) 
                if activated else 0.0
            ),
            "avg_object_flow_per_edge": (
                sum(self._edge_object_flow.values()) / len(activated)
                if activated else 0.0
            ),
            "most_active_edges": [
                {
                    "edge_id": self._edge_ids[e],
                    "kind": e.kind.value,
                    "count": count
                }
                for e, count in sorted_by_count[:10]
            ],
            "highest_flow_edges": [
                {
                    "edge_id": self._edge_ids[e],
                    "kind": e.kind.value,
                    "objects": flow
                }
                for e, flow in sorted_by_flow[:10]
            ]
        }
