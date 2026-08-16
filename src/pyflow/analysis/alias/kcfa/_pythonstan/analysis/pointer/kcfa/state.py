"""Analysis state for pointer analysis.

This module defines the state maintained during pointer analysis including
the environment (variable points-to sets) and heap (object field points-to sets).
"""

from calendar import c
from dataclasses import dataclass
from typing import Dict, FrozenSet, Tuple, Set, Optional, Iterable, Any, List, TYPE_CHECKING, Union, Deque
from collections import defaultdict, deque
from itertools import product
from queue import Queue

from pyflow.analysis.alias.kcfa._pythonstan.utils.common import Box
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRModule, IRStatement
from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph import AbstractCallGraph, CallEdge
from .object import *
from .variable import VariableFactory, VariableKind, FieldAccess, Variable
from .context import CallSite, Ctx, AbstractContext, Scope
from .constraints import ConstraintManager, Constraint, InheritanceConstraint
from .heap_model import HeapModel, Field, FieldKind
from .pointer_flow_graph import PointerFlowGraph, NormalNode, SelectorNode, PointerFlowEdge, PointerFlowNode, PointerFlowKind
from .points_to_set import PointsToSet

if TYPE_CHECKING:
    from pyflow.analysis.alias.kcfa._pythonstan.world.scope_manager import ScopeManager

__all__ = ["PointerAnalysisState"]


@dataclass(frozen=True)
class AttributePresence:
    """Abstract presence and value information for an object attribute."""

    may_exist: bool
    must_exist: bool
    points_to: PointsToSet


# TODO to be done 
class PointerCallGraph(AbstractCallGraph[Ctx[CallSite], Scope]):
    """Call graph with a context-insensitive edge index for fast deduplication."""

    def __init__(self):
        super().__init__()
        self.plain_edges = set()
    
    def add_edge(self, edge: CallEdge[Ctx[IRStatement], Scope]):
        super().add_edge(edge)
        self.plain_edges.add((edge.callsite.content, edge.callee.stmt))
    
    def has_edge(self, edge: CallEdge[Ctx[IRStatement], Scope]):
        return (edge.callsite.content, edge.callee.stmt) in self.plain_edges
    
    def num_plain_edges(self):
        return len(self.plain_edges)


class Worklist:
    """Deterministic worklist using list-based storage.
    
    Uses a list for deterministic ordering and a dict for fast lookup.
    Items are processed in FIFO order for better determinism.
    """
        
    items_list: Deque[Dict[str, Any]]
    items_dict: Dict[PointerFlowNode, Dict[str, Any]]  # Maps node to index in list

    def __init__(self):
        self.items_list = deque()
        self.items_dict = {}
        self._next_index = 0

    def add(self, content: Tuple[Scope, PointerFlowNode, PointsToSet]):
        scope, node, pts = content
        assert isinstance(node, PointerFlowNode), f"node must be a PFNode, but got {type(node)}"
        if isinstance(node, NormalNode):
            assert isinstance(node.var, Ctx), f"node.var must be a Ctx, but got {type(node.var)}"

        worklist_item: Tuple[Scope, PointerFlowNode, Box[PointsToSet]] = (scope, node, Box(pts))
        
        # Check if node already in worklist
        if node in self.items_dict:
            item = self.items_dict[node]
            # Merge points-to sets
            item[2].val = item[2].val.union(pts)
        else:
            # Add new item
            self.items_list.append(worklist_item)
            self.items_dict[node] = worklist_item
    
    def pop(self) -> Tuple[Scope, PointerFlowNode, PointsToSet]:
        """Pop from the front (FIFO) for deterministic processing."""
        if not self.items_list:
            raise IndexError("pop from empty worklist")
        
        scope, node, pts = self.items_list.popleft()
        del self.items_dict[node]
        
        return scope, node, pts.val
    
    def empty(self) -> bool:
        return len(self.items_list) == 0
    
    def __len__(self) -> int:
        return len(self.items_list)
    

class PointerAnalysisState:
    """Unified analysis state container.
    
    Maintains the environment (variable points-to information), heap (object
    field points-to information), call graph, and constraint manager.
    """

    MAX_BASE_COMBINATIONS = 64
    
    def __init__(self, debug_monitor=None):
        """Initialize empty analysis state.
        
        Args:
            debug_monitor: Optional DebugMonitor instance for tracking
        """
        self._env: Dict['Variable', PointsToSet] = {}
        self._heap = HeapModel()
        self._call_graph: 'PointerCallGraph' = PointerCallGraph()
        self._constraints: ConstraintManager = ConstraintManager()
        self._call_edges = []  # List of CallEdge objects tracked during analysis
        self._pointer_flow_graph: PointerFlowGraph = PointerFlowGraph()
        self._field_accesses: Dict[Tuple['AbstractObject', 'Field'], FieldAccess] = {}
        self._field_presence: Dict[Tuple['AbstractObject', 'Field'], Tuple[bool, bool]] = {}
        self._effective_base_sequences = defaultdict(set)
        self._opaque_effective_base_positions = set()
        self._class_inheritance_lookups = defaultdict(set)
        self._pending_class_bindings = defaultdict(list)
        self._variable_factory: VariableFactory = VariableFactory()
        self._worklist: Worklist = Worklist()
        self._static_constraints: List[Tuple['Scope', 'AbstractContext', 'Constraint']] = []
        self._constraint_definitions = []
        self._constraint_definition_set = set()
        self._internal_scope = {}
        self.obj_scope = {}
        self.class_hierarchy = None
        self._semantic_events = []
        
        # Debug monitoring
        self._debug_monitor = debug_monitor

        # Note: scope_manager is set lazily when needed
        self._scope_manager = None

    @property
    def semantic_events(self):
        """Return the ordered semantic operations observed during solving."""
        return tuple(self._semantic_events)

    def record_semantic_event(self, event) -> None:
        """Record a load/store/call event for downstream semantic analyses."""
        self._semantic_events.append(event)

    @property
    def constraint_definitions(self):
        """Return every source constraint with its defining scope/context."""
        return tuple(self._constraint_definitions)

    def record_constraint_definition(self, scope, context, constraint) -> None:
        key = (scope, context, constraint)
        if key in self._constraint_definition_set:
            return
        self._constraint_definition_set.add(key)
        self._constraint_definitions.append(key)
    
    def set_internal_scope(self, obj, scope):
        self._internal_scope[obj] = scope
    
    def get_internal_scope(self, obj) -> Scope:
        return self._internal_scope.get(obj, None)
    
    def get_points_to(self, var: Union['Ctx[Any]', 'PointerFlowNode']) -> PointsToSet:
        """Get points-to set for variable.
        
        Args:
            var: Variable to query
        
        Returns:
            Points-to set for variable (empty if not found)
        """
        return self._env.get(var, PointsToSet.empty())
    
    def set_points_to(self, var: Union['Ctx[Any]', 'PointerFlowNode'], pts: PointsToSet) -> bool:
        """Set points-to set for variable.
        
        Performs union with existing points-to set.
        
        Args:
            var: Variable to update
            pts: Points-to set to add
        
        Returns:
            True if points-to set changed
        """
        old_pts = self._env.get(var, PointsToSet.empty())
        new_pts = old_pts.union(pts)
        
        if new_pts != old_pts:
            self._env[var] = new_pts
            
            # Debug monitoring
            if self._debug_monitor and self._debug_monitor.enabled:
                diff = new_pts - old_pts
                added_objs = [str(obj) for obj in diff]
                self._debug_monitor.record_points_to_update(
                    variable_str=str(var),
                    old_size=len(old_pts),
                    new_size=len(new_pts),
                    added_objects=added_objs
                )
            
            return True
        return False

    def has_field(self, scope: 'Scope', context: 'AbstractContext', obj: 'AbstractObject', field: 'Field') -> Optional['FieldAccess']:
        """Check if the field access exists in the object.
        
        Args:
            obj: Object to query
            field: Field to query
        
        Returns:
            Points-to set for field (empty if not found)
        """
        # TODO here is just a trivial mock and did not consider the complex features such as inheritance and MRO.

        field_access = self._field_accesses.get((obj, field), None)
        return field_access

    def mark_field_presence(
        self,
        obj: 'AbstractObject',
        field: 'Field',
        *,
        must_exist: bool = False,
    ) -> None:
        """Record a monotone may/must-exist fact for ``obj.field``."""
        _, old_must = self._field_presence.get((obj, field), (False, False))
        self._field_presence[(obj, field)] = (True, old_must or must_exist)

    def get_attribute_presence(
        self,
        obj: 'AbstractObject',
        field: 'Field',
    ) -> AttributePresence:
        may_exist, must_exist = self._field_presence.get((obj, field), (False, False))
        field_access = self._field_accesses.get((obj, field))
        points_to = (
            self.get_points_to(Ctx(obj.context, None, field_access))
            if field_access is not None
            else PointsToSet.empty()
        )
        if not points_to.is_empty():
            may_exist = True
        return AttributePresence(may_exist, must_exist, points_to)

    def refresh_class_inheritance(
        self,
        owner: 'ClassObject',
        field: 'Field',
        selector: 'SelectorNode',
    ) -> None:
        """Add field flows for every currently known concrete base tuple."""
        sequence_options = []
        for position, base_var in enumerate(owner.base_variables):
            base_ctx = self.get_variable(
                owner.container_scope,
                owner.container_scope.context,
                base_var,
            )
            options = {
                (obj,) for obj in self.get_points_to(base_ctx)
                if isinstance(obj, ClassObject)
            }
            options.update(
                self._effective_base_sequences.get((owner, position), set())
            )
            if not options:
                return
            sequence_options.append(tuple(options))

        combination_count = 1
        for options in sequence_options:
            combination_count *= len(options)

        if combination_count > self.MAX_BASE_COMBINATIONS:
            index = 0
            for options in sequence_options:
                for sequence in options:
                    for base_obj in sequence:
                        self._add_inherited_field_candidate(
                            base_obj, field, selector, index
                        )
                        index += 1
            return

        from .class_hierarchy import MROError, compute_c3_mro_for_bases

        for selected_sequences in product(*sequence_options):
            concrete_bases = tuple(
                base_obj
                for sequence in selected_sequences
                for base_obj in sequence
            )
            if self.class_hierarchy is None:
                mro_bases = list(concrete_bases)
            else:
                try:
                    mro_bases = compute_c3_mro_for_bases(
                        list(concrete_bases), self.class_hierarchy
                    )
                except MROError:
                    continue
                if all(len(options) == 1 for options in sequence_options):
                    bases_list = list(concrete_bases)
                    if self.class_hierarchy.has_class(owner):
                        self.class_hierarchy.update_bases(owner, bases_list)
                    else:
                        self.class_hierarchy.add_class(owner, bases_list)

            for index, base_obj in enumerate(mro_bases):
                self._add_inherited_field_candidate(
                    base_obj, field, selector, index
                )
                if self.get_attribute_presence(base_obj, field).must_exist:
                    break

    def register_class_inheritance_lookup(
        self,
        owner: 'ClassObject',
        field: 'Field',
        selector: 'SelectorNode',
    ) -> None:
        """Remember a lookup that depends on the owner's effective bases."""
        self._class_inheritance_lookups[owner].add((field, selector))

    def record_effective_base_sequence(
        self,
        owner: 'ClassObject',
        position: int,
        sequence: Tuple['ClassObject', ...],
    ) -> bool:
        """Record one monotone ``__mro_entries__`` expansion alternative."""
        key = (owner, position)
        if sequence in self._effective_base_sequences[key]:
            return False
        self._effective_base_sequences[key].add(sequence)

        self._update_singleton_class_hierarchy(owner)

        if position < len(owner.effective_base_variables):
            effective_var = owner.effective_base_variables[position]
            effective_ctx = self.get_variable(
                owner.container_scope,
                owner.container_scope.context,
                effective_var,
            )
            if sequence:
                self._worklist.add((
                    owner.container_scope,
                    NormalNode(effective_ctx),
                    PointsToSet.from_objects(sequence),
                ))

        for field, selector in self._class_inheritance_lookups.get(owner, ()):
            self.refresh_class_inheritance(owner, field, selector)
        self.release_class_binding_if_feasible(owner)
        return True

    def record_opaque_effective_base(
        self,
        owner: 'ClassObject',
        position: int,
        base_obj: 'AbstractObject',
    ) -> None:
        """Record a valid builtin/opaque type outside the user hierarchy."""
        self._opaque_effective_base_positions.add((owner, position))
        if position < len(owner.effective_base_variables):
            effective_ctx = self.get_variable(
                owner.container_scope,
                owner.container_scope.context,
                owner.effective_base_variables[position],
            )
            self._worklist.add((
                owner.container_scope,
                NormalNode(effective_ctx),
                PointsToSet.singleton(base_obj),
            ))
        self.release_class_binding_if_feasible(owner)

    def defer_class_binding(
        self,
        owner: 'ClassObject',
        scope: 'Scope',
        target: 'Ctx[Variable]',
    ) -> None:
        """Delay publishing a class name until some base tuple is feasible."""
        binding = (scope, target)
        if binding not in self._pending_class_bindings[owner]:
            self._pending_class_bindings[owner].append(binding)

    def release_class_binding_if_feasible(
        self,
        owner: 'ClassObject',
    ) -> bool:
        """Publish a deferred class object after effective-base validation."""
        if self.class_base_validity(owner) is not True:
            return False
        bindings = self._pending_class_bindings.pop(owner, ())
        for scope, target in bindings:
            self._worklist.add((
                scope,
                NormalNode(target),
                PointsToSet.singleton(owner),
            ))
        return bool(bindings)

    def _update_singleton_class_hierarchy(
        self,
        owner: 'ClassObject',
    ) -> None:
        """Publish hierarchy edges once every base position is unambiguous."""
        if self.class_hierarchy is None:
            return
        selected = []
        for position in range(len(owner.base_variables)):
            options = self._effective_base_sequences.get((owner, position), set())
            if len(options) != 1:
                return
            selected.extend(next(iter(options)))
        bases = list(selected)
        if self.class_hierarchy.has_class(owner):
            self.class_hierarchy.update_bases(owner, bases)
        else:
            self.class_hierarchy.add_class(owner, bases)

    def class_base_validity(
        self,
        owner: 'ClassObject',
    ) -> Optional[bool]:
        """Return True/False for feasible/invalid, or None while unresolved."""
        if not owner.base_variables:
            return True
        sequence_options = []
        has_opaque_base = False
        for position in range(len(owner.base_variables)):
            options = tuple(
                self._effective_base_sequences.get((owner, position), set())
            )
            if not options:
                if (owner, position) not in self._opaque_effective_base_positions:
                    return None
                has_opaque_base = True
                options = ((),)
            sequence_options.append(options)

        count = 1
        for options in sequence_options:
            count *= len(options)
        if (
            has_opaque_base
            or count > self.MAX_BASE_COMBINATIONS
            or self.class_hierarchy is None
        ):
            return True

        from .class_hierarchy import MROError, compute_c3_mro_for_bases

        for selected_sequences in product(*sequence_options):
            concrete_bases = [
                base_obj
                for sequence in selected_sequences
                for base_obj in sequence
            ]
            try:
                compute_c3_mro_for_bases(
                    concrete_bases, self.class_hierarchy
                )
                return True
            except MROError:
                continue
        return False

    def _add_inherited_field_candidate(
        self,
        base_obj: 'ClassObject',
        field: 'Field',
        selector: 'SelectorNode',
        index: int,
    ) -> None:
        base_scope = self.get_internal_scope(base_obj)
        if base_scope is None:
            return
        base_field = self.get_field(
            base_scope, base_obj.context, base_obj, field
        )
        edge = PointerFlowEdge(
            NormalNode(base_field), selector, PointerFlowKind.NORMAL
        )
        selector.add_edge(edge, index)
        self._add_points_flow_edge(edge)

    def get_field(self, scope: 'Scope', context: 'AbstractContext', obj: 'AbstractObject', field: 'Field') -> 'Ctx[FieldAccess]':
        """Get field access for object field.
        
        Handles container-specific field resolution:
        - TupleObject: Supports position(i) fields for precise tracking
        - DictObject: Supports key(k) fields for precise tracking
        - ListObject/SetObject: Uses elem() field for all elements
        
        Args:
            obj: Object to query
            field: Field to query
        
        Returns:
            Contextualized field access for the specified field
        """

        # Summary objects: connect summary field to all concrete counterparts
        if is_summary_object(obj):
            field_access = self._field_accesses.get((obj, field), None)
            if field_access is None:
                field_access = self._variable_factory.make_field_access(obj, field)
                self.set_field(scope, context, obj, field, field_access)
            summary_cfield: Ctx[FieldAccess] = Ctx(obj.context, None, field_access)
            # Bidirectionally connect summary field with each concrete matching object
            for concrete in self._heap.objects.values():
                if summarize_object(concrete) == obj:
                    concrete_field = self.get_field(scope, context, concrete, field)
                    self._add_points_flow_edge(PointerFlowEdge(NormalNode(summary_cfield), NormalNode(concrete_field), PointerFlowKind.NORMAL))
                    self._add_points_flow_edge(PointerFlowEdge(NormalNode(concrete_field), NormalNode(summary_cfield), PointerFlowKind.NORMAL))
            return summary_cfield

        field_access = self._field_accesses.get((obj, field), None)
        exists = True
        if field_access is None:
            field_access = self._variable_factory.make_field_access(obj, field)
            self.set_field(scope, context, obj, field, field_access)
            exists = False
        
        cfield: Ctx[FieldAccess] = Ctx(obj.context, None, field_access)

        if not exists:
            if isinstance(obj, ModuleObject):
                if field.name is None:
                    return cfield
                
                internal_scope = self.get_internal_scope(obj)
                var = self._variable_factory.make_variable(field.name, VariableKind.GLOBAL)
                cvar = self.get_variable(internal_scope, internal_scope.context, var)
                self._add_var_points_flow(cvar, cfield)
            
            elif isinstance(obj, InstanceObject):
                # print(f"get field {field.name} for instance {obj}")
                cls_obj = obj.class_obj
                assert isinstance(cls_obj, ClassObject), f"cls_obj must be a ClassObject, but got {type(cls_obj)}"
                cls_scope = self.get_internal_scope(cls_obj)
                cls_field = self.get_field(cls_scope, cls_scope.context, cls_obj, field)
                assert cls_field != cfield, f"cls_field {cls_field} and cfield {cfield} should not be the same"
                if cls_field != cfield:
                    edge = PointerFlowEdge(NormalNode(cls_field), NormalNode(cfield), PointerFlowKind.INSTANCE)
                    self._add_points_flow_edge(edge)
            
            elif isinstance(obj, ClassObject):
                bases = obj.base_variables
                scope = obj.container_scope

                if len(bases) > 0:
                    selector = SelectorNode()
                    self.register_class_inheritance_lookup(obj, field, selector)
                    inherit_edge = PointerFlowEdge(selector, NormalNode(cfield), PointerFlowKind.INHERIT)
                    self._add_points_flow_edge(inherit_edge)

                    for idx, base_var in enumerate(bases):
                        # Contextualize the base variable for constraint indexing
                        base_ctx_var = self.get_variable(scope, scope.context, base_var)
                        inherit_constraint = InheritanceConstraint(
                            base=base_var,
                            field=field,
                            target=selector,
                            index=idx,
                            owner=obj,
                        )
                        self._constraints.add(scope, base_ctx_var, inherit_constraint)
                        # Debug logging
                        import logging
                        logger = logging.getLogger(__name__)
                        # Check if debug_inheritance is enabled (access through solver if possible)
                        # For now, log at debug level
                        logger.debug(f"[INHERIT] Created InheritanceConstraint for {obj.alloc_site.stmt.name}.{field} from base {base_var.name}")
                        
                    self.refresh_class_inheritance(obj, field, selector)
            
            # Handle SuperObject - resolve fields via parent class MRO
            if isinstance(obj, SuperObject):
                """
                SuperObject field resolution via PFG + InheritanceConstraint:
                
                1. Identify parent classes to search (skip current_class in MRO)
                2. Create SelectorNode to aggregate results from parents
                3. Add PFG edge: selector -> cfield (parent fields flow to result)
                4. For each parent class, add InheritanceConstraint (lazy resolution)
                5. Methods flow through PFG and get bound to instance_obj if present
                
                This reuses the same mechanism as ClassObject inheritance but starts
                from parent classes instead of the class itself.
                """
                if obj.current_class:
                    # Get base classes from the current class
                    # These are the parent classes super() will search
                    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRClass
                    if isinstance(obj.current_class.alloc_site.stmt, IRClass):
                        bases = (
                            obj.current_class.effective_base_variables
                            or obj.current_class.base_variables
                        )
                        current_scope = obj.current_class.container_scope
                        
                        if len(bases) > 0:
                            # Create SelectorNode to collect parent class fields
                            selector = SelectorNode()
                            
                            if obj.instance_obj is not None:
                                # Bind parent methods into the instance, then flow to super field
                                instance_field = self.get_field(scope, context, obj.instance_obj, field)
                                inherit_edge = PointerFlowEdge(selector, NormalNode(instance_field), PointerFlowKind.INSTANCE)
                                self._add_points_flow_edge(inherit_edge)
                                self._add_points_flow_edge(
                                    PointerFlowEdge(NormalNode(instance_field), NormalNode(cfield), PointerFlowKind.NORMAL)
                                )
                            else:
                                # No instance: flow parent fields directly to super field
                                inherit_edge = PointerFlowEdge(selector, NormalNode(cfield), PointerFlowKind.NORMAL)
                                self._add_points_flow_edge(inherit_edge)
                            
                            # Add InheritanceConstraint for each parent class
                            # These constraints apply lazily when parent points-to sets are known
                            for idx, base_var in enumerate(bases):
                                # Contextualize the base variable for constraint indexing
                                base_ctx_var = self.get_variable(current_scope, current_scope.context, base_var)
                                inherit_constraint = InheritanceConstraint(
                                    base=base_var,
                                    field=field,
                                    target=selector,
                                    index=idx
                                )
                                self._constraints.add(current_scope, base_ctx_var, inherit_constraint)
                                
                                # Immediate resolution if base already known
                                if base_ctx_var:
                                    base_pts = self.get_points_to(base_ctx_var)
                                    if len(base_pts) > 0:
                                        for base_obj in base_pts:
                                            if isinstance(base_obj, ClassObject):
                                                base_internal_scope = self.get_internal_scope(base_obj)
                                                if base_internal_scope:
                                                    base_field_access = self.get_field(base_internal_scope, base_obj.context, base_obj, field)
                                                    base_edge = PointerFlowEdge(NormalNode(base_field_access), selector, PointerFlowKind.NORMAL)
                                                    selector.add_edge(base_edge, idx)
                                                    self._add_points_flow_edge(base_edge)

        return cfield
    
    def _get_builtin_methods_for_type(self, builtin_type: str) -> Set[str]:
        """Get the set of known methods for a builtin type.
        
        Args:
            builtin_type: Type name (e.g., "list", "dict", "set")
        
        Returns:
            Set of method names
        """
        methods = {
            "list": {
                "append", "extend", "insert", "remove", "pop", "clear",
                "index", "count", "sort", "reverse", "copy",
                "__getitem__", "__setitem__", "__iter__", "__len__"
            },
            "dict": {
                "get", "pop", "popitem", "clear", "update", "setdefault",
                "keys", "values", "items", "copy",
                "__getitem__", "__setitem__", "__iter__", "__len__", "__contains__"
            },
            "set": {
                "add", "remove", "discard", "pop", "clear", "copy",
                "union", "intersection", "difference", "symmetric_difference",
                "update", "intersection_update", "difference_update",
                "__iter__", "__len__", "__contains__"
            },
            "tuple": {
                "count", "index",
                "__getitem__", "__iter__", "__len__"
            },
            "str": {
                "upper", "lower", "strip", "split", "join", "replace",
                "startswith", "endswith", "find", "index", "format",
                "__getitem__", "__iter__", "__len__", "__contains__"
            },
        }
        return methods.get(builtin_type, set())

    
    def set_field(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        obj: 'AbstractObject',
        field: 'Field',
        field_access: 'FieldAccess'
    ) -> None:
        """Set field access for object field.
        
        Performs union with existing points-to set.
        
        Args:
            obj: Object to update
            field: Field to update
        
        Returns:
            Field access for object field
        """
        assert isinstance(field_access, FieldAccess), f"field_access must be a FieldAccess, but got {type(field_access)}"
        self._field_accesses[(obj, field)] = field_access
    
    @property
    def scope_manager(self) -> 'ScopeManager':
        if self._scope_manager is None:
            from pyflow.analysis.alias.kcfa._pythonstan.world import World
            self._scope_manager = World().scope_manager
        return self._scope_manager
    
    @property
    def constraints(self) -> 'ConstraintManager':
        """Get constraint manager.
        
        Returns:
            Constraint manager
        
        Raises:
            RuntimeError: If constraints not initialized
        """
        if self._constraints is None:
            raise RuntimeError("Constraints not initialized")
        return self._constraints
    
    @property
    def pointer_flow_graph(self) -> 'PointerFlowGraph':
        """Get pointer flow graph.
        
        Returns:
            Pointer flow graph
        """
        return self._pointer_flow_graph
    
    @property
    def call_graph(self) -> 'AbstractCallGraph':
        """Get call graph.
        
        Returns:
            Call graph
        
        Raises:
            RuntimeError: If call graph not initialized
        """
        if self._call_graph is None:
            raise RuntimeError("Call graph not initialized")
        return self._call_graph

    def get_variable(self, scope: 'Scope', context: 'AbstractContext', var: 'Variable') -> 'Ctx[Variable]':
        owner_scope = scope
        owner_context = context
        var_kind = getattr(var, "kind", VariableKind.LOCAL)
        
        if var_kind == VariableKind.GLOBAL:
            owner_scope = scope.module
            owner_context = scope.module.context
        elif var_kind == VariableKind.NONLOCAL:
            from .object import FunctionObject
            func_obj = getattr(scope, "obj", None)
            if isinstance(func_obj, FunctionObject):
                captured = self._heap.get_nonlocal_vars(func_obj).get(var.name)
                if captured is not None:
                    return captured
            owner_scope = scope.parent
            owner_context = scope.parent.context
        elif var_kind == VariableKind.CELL:
            from .object import FunctionObject, GeneratorObject, CoroutineObject
            # For closure-captured variables, first try to resolve from the
            # function object's captured cell vars before falling back.
            func_obj = getattr(scope, "obj", None)
            if isinstance(func_obj, (GeneratorObject, CoroutineObject)):
                func_obj = func_obj.func_obj
            if isinstance(func_obj, FunctionObject):
                captured = self._heap.get_cell_vars(func_obj).get(var.name)
                if captured is not None:
                    return captured
                module_scope = getattr(func_obj.container_scope, "module", None) or scope.module
                if module_scope is not None:
                    module_global = self._get_variable_direct(
                        module_scope,
                        module_scope.context,
                        var.name,
                        VariableKind.GLOBAL,
                    )
                    if module_global is not None:
                        return module_global
            owner_scope = scope.parent or scope
            owner_context = owner_scope.context if owner_scope else context
        else:
            owner_scope = scope
            owner_context = context

        if var.name.startswith("$const") and scope.module and scope != scope.module:
            module_cvar = self._get_variable_direct(scope.module, scope.module.context, var.name, var_kind)
            if module_cvar is not None:
                return module_cvar
        
        cvar = self._get_variable_direct(owner_scope, owner_context, var.name, var_kind)
        if cvar is None:
            cvar = Ctx(owner_context, owner_scope, self._variable_factory.make_variable(var.name, var_kind))
            self.set_variable(owner_scope, owner_context, var, cvar)
        return cvar
    
    def set_variable(self, scope: 'Scope', context: 'AbstractContext', var: 'Variable', ctx_var: 'Ctx[Variable]'):
        self._heap.set_variable(scope, context, var, ctx_var)
        
    def get_cell_var(self, obj: FunctionObject, name: str) -> Optional[Ctx['Variable']]:
        return self._heap.get_cell_vars(obj).get(name, None)
    
    def get_nonlocal_var(self, obj: FunctionObject, name: str) -> Optional[Ctx['Variable']]:
        return self._heap.get_nonlocal_vars(obj).get(name, None)
    
    def get_global_var(self, obj: FunctionObject, name: str) -> Optional[Ctx['Variable']]:
        return self._heap.get_global_vars(obj).get(name, None)
    
    def get_cell_vars(self, obj: FunctionObject) -> Dict[str, Ctx['Variable']]:
        return self._heap.get_cell_vars(obj)
    
    def get_nonlocal_vars(self, obj: FunctionObject) -> Dict[str, Ctx['Variable']]:
        return self._heap.get_nonlocal_vars(obj)
    
    def get_global_vars(self, obj: FunctionObject) -> Dict[str, Ctx['Variable']]:
        return self._heap.get_global_vars(obj)
    
    def set_cell_vars(self, obj: FunctionObject, vars):
        self._heap.cell_vars[obj] = vars
    
    def set_nonlocal_vars(self, obj: FunctionObject, vars):
        self._heap.nonlocal_vars[obj] = vars

    def set_global_vars(self, obj: FunctionObject, vars):
        self._heap.global_vars[obj] = vars            
        
    def _get_variable_direct(self, scope: 'Scope', context: 'AbstractContext', var_name: str, var_kind: VariableKind) -> Optional['Ctx[Variable]']:
        assert isinstance(var_name, str), f"var_name must be a string, but got {type(var_name)}"
        
        var = self._variable_factory.make_variable(var_name, var_kind)
        return self._heap.get_variable(scope, context, var)
        
    def _add_var_points_flow(self, src: Ctx[Any], tgt: Ctx[Any]):
        assert isinstance(src, Ctx), f"src must be a Ctx, but got {type(src)}"
        assert isinstance(tgt, Ctx), f"tgt must be a Ctx, but got {type(tgt)}"
        if src != tgt:
            self._add_points_flow_edge(PointerFlowEdge(NormalNode(src), NormalNode(tgt), PointerFlowKind.NORMAL))
    
    def _add_points_flow_edge(self, edge: PointerFlowEdge):
        if self.pointer_flow_graph.add_edge(edge):
            src = edge.source
            tgt = edge.target            
            pts = self.pointer_flow_graph.flow_through_edge(edge, self.get_points_to(src)) - self.get_points_to(tgt)
            if not pts.is_empty():
                scope = None
                if isinstance(tgt, NormalNode):
                    scope = tgt.var.scope
                self._worklist.add((scope, tgt, pts))
    
    def get_statistics(self) -> Dict[str, int]:
        """Get state statistics.
        
        Returns:
            Dictionary with statistics:
            - num_variables: Number of variables tracked
            - num_objects: Number of unique objects
            - num_heap_locations: Number of heap locations
        """
        objects = set(self._heap.objects.values())
        for pts in self._env.values():
            objects.update(pts.objects)
        
        return {
            "num_variables": len(self._env),
            "num_objects": len(objects),
            "num_heap_locations": len(self._heap.objects),
            "num_call_edges": self._call_graph.num_plain_edges(),
        }
    
    def get_detailed_statistics(self) -> Dict[str, Any]:
        """Get detailed state statistics for debugging.
        
        Returns:
            Dictionary with detailed statistics including:
            - Points-to set size distribution
            - Variables with empty/singleton/large sets
            - Object type breakdown
            - Call graph metrics
        """
        from collections import defaultdict
        
        # Collect points-to set sizes
        pts_sizes = []
        empty_vars = []
        singleton_vars = []
        large_vars = []  # > 10 objects
        
        for var, pts in self._env.items():
            size = len(pts)
            pts_sizes.append(size)
            
            if size == 0:
                empty_vars.append(str(var))
            elif size == 1:
                singleton_vars.append(str(var))
            elif size > 10:
                large_vars.append(str(var))
        
        # Size distribution
        size_dist = defaultdict(int)
        for size in pts_sizes:
            if size == 0:
                bucket = "0"
            elif size == 1:
                bucket = "1"
            elif size <= 5:
                bucket = "2-5"
            elif size <= 10:
                bucket = "6-10"
            elif size <= 50:
                bucket = "11-50"
            else:
                bucket = "51+"
            size_dist[bucket] += 1
        
        # Object type breakdown
        obj_by_kind = defaultdict(int)
        all_objects = set()
        for pts in self._env.values():
            for obj in pts:
                all_objects.add(obj)
                obj_by_kind[obj.kind.value] += 1
        
        return {
            "num_variables": len(self._env),
            "num_heap_locations": len(self._heap.objects),
            "num_call_edges": self._call_graph.get_number_of_edges(),
            "num_pfg_nodes": len(self._pointer_flow_graph.get_nodes()),
            "num_pfg_edges": len(self._pointer_flow_graph.get_edges()),
            "points_to": {
                "avg_size": sum(pts_sizes) / len(pts_sizes) if pts_sizes else 0.0,
                "max_size": max(pts_sizes) if pts_sizes else 0,
                "min_size": min(pts_sizes) if pts_sizes else 0,
                "empty_count": len(empty_vars),
                "singleton_count": len(singleton_vars),
                "large_count": len(large_vars),
                "size_distribution": dict(size_dist),
                "empty_variables": empty_vars[:20],  # Limit output
                "singleton_variables": singleton_vars[:20],
                "large_variables": large_vars[:20]
            },
            "objects": {
                "total": len(all_objects),
                "by_kind": dict(obj_by_kind)
            }
        }
