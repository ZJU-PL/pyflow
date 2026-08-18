"""Constraint-based pointer analysis solver.

This module implements the core solver for pointer analysis using
constraint-based propagation.
"""

import ast
import logging
import random
from collections import defaultdict, deque
from fnmatch import fnmatchcase
from typing import Set, Dict, Any, TYPE_CHECKING, Optional, List, Tuple

from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRFunc, IRModule, IRClass, IRAssign, IRStoreSubscr

from .state import PointerAnalysisState, PointsToSet
from .constraints import *
from .variable import Variable, VariableKind, VariableFactory, FieldAccess
from .config import Config
from .heap_model import Field, FieldKind, attr, key, elem
from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph import AbstractCallGraph, CallEdge, CallKind
from .ir_translator import IRTranslator
from .context_selector import ContextSelector, AbstractContext
from .context import Ctx, Scope, CallSite
from .class_hierarchy import ClassHierarchyManager
from .builtin_api_handler import BuiltinSummaryManager
from .unknown_tracker import UnknownTracker, UnknownKind
from .object import *
from .solver_interface import ISolverQuery
from .pointer_flow_graph import PointerFlowGraph, PointerFlowEdge, PointerFlowNode, NormalNode, GuardNode, SelectorNode, ClassBindingNode, PointerFlowKind
from .debug_monitor import DebugMonitor
from .processor import Processor
from .events import PointerEvent, PointerEventKind
from .call_binding import bind_arguments
from .stable_key import stable_token
from .type_ref import TypeRefKind

__all__ = ["PointerSolver", "SolverQuery"]

logger = logging.getLogger(__name__)


class PointerSolver:
    """Compute a fixed point over constraints and pointer-flow edges.

    The solver consumes newly discovered constraints and points-to deltas from
    deterministic worklists.  Semantic processors handle Python-specific cases
    while this class coordinates allocation, propagation, calls, contexts, and
    statistics.
    """

    def __init__(
        self,
        state: 'PointerAnalysisState',
        config: 'Config',
        processor: 'Processor',
        variable_factory: Optional['VariableFactory'] = None,
        ir_translator: Optional['IRTranslator'] = None,
        context_selector: Optional['ContextSelector'] = None,
        class_hierarchy: Optional['ClassHierarchyManager'] = None,
        builtin_manager: Optional['BuiltinSummaryManager'] = None,
        debug_monitor: 'DebugMonitor' = None,
    ):
        """Initialize solver.
        
        Args:
            state: Analysis state
            config: Configuration
            ir_translator: IR translator for analyzing called functions
            context_selector: Context selector for call/alloc contexts
            function_registry: Map of function names to IR functions
            class_hierarchy: Class hierarchy manager for MRO
            builtin_manager: Builtin summary manager
            debug_monitor: Optional debug monitor for tracking
        """
        self.state = state
        self.config = config
        self.processor = processor
        self.ir_translator = ir_translator
        self.context_selector = context_selector
        self.class_hierarchy = class_hierarchy
        self.builtin_manager = builtin_manager
        self.variable_factory = variable_factory or VariableFactory()
        self._unknown_tracker = UnknownTracker()
        self._agenda_random = random.Random(config.worklist_seed + 2)
        self._debug_monitor = debug_monitor
        self.state.class_hierarchy = class_hierarchy
        self._frontend_complete = True
        self._semantic_complete = True
        self._incomplete_variables = defaultdict(list)
        self._incomplete_scopes = defaultdict(list)
        self._global_incomplete_reasons = []
        
        # Initialize builtin handler with state
        if self.builtin_manager:
            self.builtin_manager.set_state(state)
        self._reset()

    BUILTIN_FUNCTIONS = [
        "iter", "next", "len", "enumerate", "zip", "map", "filter",
        "range", "reversed", "sorted", "sum", "min", "max", "all", "any",
        "list", "dict", "tuple", "set", "frozenset",
        "object", "str", "int", "float", "bool", "bytes",
        "isinstance", "issubclass", "type", "hasattr", "getattr", "setattr",
        "delattr", "vars", "callable",
        "super", "print", "input", "open", "eval", "exec", "compile",
        "__import__"
    ]

    def initialize_builtins(self, scope: 'Scope', context: 'AbstractContext') -> None:
        """Initialize builtin function objects in a module-like scope."""
        for builtin_name in self.BUILTIN_FUNCTIONS:
            builtin_obj = ObjectFactory.create_builtin_function(builtin_name, context)
            builtin_var = Variable(name=builtin_name, kind=VariableKind.GLOBAL)
            ctx_var = self.state.get_variable(scope, context, builtin_var)
            self.state._worklist.add((
                scope,
                NormalNode(ctx_var),
                PointsToSet.singleton(builtin_obj),
            ))
    
    def _reset(self) -> None:
        self._iteration = 0
        self._fixpoint_complete = False
        self._complete = False
        self._analyzed_functions = set()
        self._stats: Dict[str, int] = {
            "iterations": 0,
            "constraints_applied": 0
        }
        self._modules = set()
        self._dispatched_class_factories = set()
        self._class_original_bases = {}
        self._class_namespaces = {}
        self._class_name_variables = {}
        self._class_object_variables = {}
        self._installed_class_variant_hooks = set()
        self._installed_class_owner_hooks = set()
        self._scheduled_optional_calls = set()
        self._installed_slot_descriptors = set()
        self._expanded_dynamic_code = set()
        self._widened_points_to_nodes = set()

    def mark_frontend_incomplete(self) -> None:
        self._frontend_complete = False

    def mark_semantic_incomplete(
        self,
        *,
        variables=(),
        scopes=(),
        kind: str = "semantic_incomplete",
        message: str = "semantic operation was not modeled exhaustively",
    ) -> None:
        self._semantic_complete = False
        reason = {"kind": kind, "message": message}
        variables = tuple(variables)
        scopes = tuple(scopes)
        if not variables and not scopes:
            if reason not in self._global_incomplete_reasons:
                self._global_incomplete_reasons.append(reason)
            return
        for variable in variables:
            if reason not in self._incomplete_variables[variable]:
                self._incomplete_variables[variable].append(reason)
        for scope in scopes:
            if reason not in self._incomplete_scopes[scope]:
                self._incomplete_scopes[scope].append(reason)
    
    def add_constraint(self, scope: 'Scope', context: 'AbstractContext', constraint: 'Constraint') -> None:
        self.state.record_constraint_definition(scope, context, constraint)
        self.processor.handle_new_constraint(self, scope, constraint)

        if isinstance(constraint, CopyConstraint):
            self.state._static_constraints.append((scope, context, constraint))
        elif isinstance(constraint, AllocConstraint):
            self.state._static_constraints.append((scope, context, constraint))
        else:
            if isinstance(constraint, LoadConstraint):
                base = self.state.get_variable(scope, context, constraint.base)
                self.state.constraints.add(scope, base, constraint)
                # CRITICAL: If base already has objects, apply the constraint immediately
                base_pts = self.state.get_points_to(base)
                if len(base_pts) > 0:
                    self._apply_load(scope, base, constraint, base_pts)
            elif isinstance(constraint, StoreConstraint):
                base = self.state.get_variable(scope, context, constraint.base)
                self.state.constraints.add(scope, base, constraint)
                # CRITICAL: If base already has objects, apply the constraint immediately
                base_pts = self.state.get_points_to(base)
                if len(base_pts) > 0:
                    self._apply_store(scope, base, constraint, base_pts)
            elif isinstance(constraint, CallConstraint):
                callee = self.state.get_variable(scope, context, constraint.callee)
                callee_pts = self.state.get_points_to(callee)
                if callee_pts.is_empty():
                    self.state.constraints.add(scope, callee, constraint)
                else:
                    # Lazy call activation: copy callee pts into a fresh temp var
                    # so the call constraint is triggered via normal propagation.
                    lazy_callee = self.variable_factory.make_variable(
                        f"$call_lazy@{constraint.call_site.short_id()}@{constraint.callee.name}",
                        VariableKind.TEMPORARY,
                    )
                    lazy_ctx = self.state.get_variable(scope, context, lazy_callee)
                    lazy_constraint = CallConstraint(
                        callee=lazy_callee,
                        args=constraint.args,
                        kwargs=constraint.kwargs,
                        target=constraint.target,
                        call_site=constraint.call_site,
                        starred=constraint.starred,
                    )
                    self.state.constraints.add(scope, lazy_ctx, lazy_constraint)
                    self.state._static_constraints.append((
                        scope,
                        context,
                        CopyConstraint(source=constraint.callee, target=lazy_callee),
                    ))
            elif isinstance(constraint, InheritanceConstraint):
                base = self.state.get_variable(scope, context, constraint.base)
                self.state.constraints.add(scope, base, constraint)


    def solve_to_fixpoint(self) -> None:
        logger.info("Starting constraint solving")
        max_iter = self.config.max_iterations
        
        for _ in self:
            # Update debug monitor iteration
            if self._debug_monitor:
                self._debug_monitor.set_iteration(self._iteration)
            # Log progress periodically
            log_interval = self.config.debug_log_interval if self.config.enable_debug_monitor else 1000
            if self._iteration % log_interval == 0:
                logger.info(f"Iteration {self._iteration}, worklist size {len(self.state._worklist)}, objs: {len(self.state._heap.objects)}, "
                            f"call_edges: {len(self.state.call_graph.edges)}, plain_call_edges: {self.state.call_graph.num_plain_edges()}")                
                # Record iteration snapshot
                self._log_solver_state()
            if self._iteration >= max_iter:
                logger.warning(f"Reached max iterations {max_iter}")
        
        self._stats["iterations"] = self._iteration
        self._fixpoint_complete = (
            self.state._worklist.empty()
            and not self.state._static_constraints
            and not self.state.dependencies.has_pending()
        )
        self.state._construction_inputs_sealed = self._fixpoint_complete
        if not self._fixpoint_complete:
            self._unknown_tracker.record(
                UnknownKind.SOLVER_BUDGET,
                "<solver>",
                f"fixpoint not reached after {self.config.max_iterations} iterations",
            )
        self._record_empty_callees()
        self._complete = (
            self._fixpoint_complete
            and self._frontend_complete
            and self._semantic_complete
        )
        logger.info(f"Processed {len(self._modules)} modules: {self._modules}")
        logger.info(f"Call Constraints: {len(self.state.constraints.get_by_type(CallConstraint))}")
        abs_nodes = set([node.stmt.get_qualname() for node in self.state._call_graph.get_nodes()])
        logger.info(f"Call graph: {self.state._call_graph} node: {len(self.state._call_graph.get_nodes())} edge: {self.state._call_graph.get_number_of_edges()}")
        logger.info(f"    absolute nodes: { len(abs_nodes) } absolute edges: { self.state._call_graph.num_plain_edges() }")
        logger.info(f"Pointer flow graph: {self.state._pointer_flow_graph} node: {len(self.state._pointer_flow_graph.get_nodes())} edge: {len(self.state._pointer_flow_graph.get_edges())}")                
        if self._fixpoint_complete:
            logger.info(f"Converged after {self._iteration} iterations")
        else:
            logger.warning(f"Stopped after solver budget at {self._iteration} iterations")

    def _record_empty_callees(self) -> None:
        """Make unresolved calls fail-visible after the points-to fixpoint."""
        seen = set()
        for scope, constraint in self.state.constraints.all():
            if not isinstance(constraint, CallConstraint):
                continue
            if constraint.callee.name.startswith((
                "$getattribute@",
                "$getattr@",
                "$setattr@",
                "$delattr@",
                "$descriptor_get@",
                "$descriptor_set@",
                "$descriptor_delete@",
                "$optional_method@",
                "$optional_callee@",
                "$set_name@",
                "$init_subclass@",
            )):
                # These constraints probe optional protocol hooks.  An empty
                # callee means the hook is absent, not that analysis failed.
                continue
            callee = self.state.get_variable(scope, scope.context, constraint.callee)
            if not self.state.get_points_to(callee).is_empty():
                continue
            key = (scope, constraint)
            if key in seen:
                continue
            seen.add(key)
            self._unknown_tracker.record(
                UnknownKind.CALLEE_EMPTY,
                str(constraint.call_site),
                f"call target has an empty points-to set: {constraint.callee}",
                context=str(scope.context),
            )
            affected = ()
            if constraint.target is not None:
                affected = (self.state.get_variable(
                    scope, scope.context, constraint.target
                ),)
            self.mark_semantic_incomplete(
                variables=affected,
                scopes=() if affected else (scope,),
                kind=UnknownKind.CALLEE_EMPTY.value,
                message=f"call target is unresolved: {constraint.callee}",
            )
        
    def __iter__(self):
        self._reset()
        return self
    
    def __next__(self) -> 'PointerAnalysisState':
        has_work = (
            not self.state._worklist.empty()
            or self.state._static_constraints
            or self.state.dependencies.has_pending()
        )
        if has_work and self._iteration < self.config.max_iterations:
            self._iteration += 1
            available = []
            if self.state._static_constraints:
                available.append("static")
            if self.state.dependencies.has_pending():
                available.append("dependency")
            if not self.state._worklist.empty():
                available.append("dynamic")
            selected = (
                self._agenda_random.choice(available)
                if self.config.worklist_policy == "random"
                else available[0]
            )
            if selected == "static":
                scope, ctx, constraint = self.state.pop_static_constraint()
                return self._apply_static(scope, ctx, constraint)
            if selected == "dependency":
                self.state.dependencies.run_next()
                return self.state
            scope, node, pts = self.state._worklist.pop()
            return self._apply_dynamic(scope, node, pts)
            
            
        raise StopIteration
    
    def _apply_dynamic(self, scope: 'Scope', node: 'PointerFlowNode', pts: 'PointsToSet') -> 'PointerAnalysisState':
        if isinstance(node, NormalNode):
            assert isinstance(node.var, Ctx), f"node.var must be a Ctx, but got {type(node.var)}"
        pts, diff = self._widen_points_to_if_needed(node, pts)
        if not diff.is_empty():
            if node in self._widened_points_to_nodes:
                self.state.replace_points_to(node, pts)
            else:
                self.state.set_points_to(node, diff)
            
            # apply the constraints associated with the variable
            if isinstance(node, NormalNode):
                self.processor.handle_pts(self, node.var, scope, diff)

                if node in self._widened_points_to_nodes:
                    self.state.replace_points_to(node.var, pts)
                else:
                    self.state.set_points_to(node.var, diff)
                for constraint_scope, constraint in self.state.constraints.iter_scoped_by_variable(node.var):
                    self._apply_constraint(constraint_scope, node.var, constraint, diff)
            
            for succ, succ_pts in self.state.pointer_flow_graph.propagate(node, diff):
                succ_scope = succ.var.scope if isinstance(succ, NormalNode) else None
                self.state._worklist.add((succ_scope, succ, succ_pts))
        return self.state

    def _widen_points_to_if_needed(
        self,
        node: 'PointerFlowNode',
        incoming: 'PointsToSet',
    ) -> Tuple['PointsToSet', 'PointsToSet']:
        """Apply the configured finite-height abstraction to one PFG node."""
        limit = self.config.max_points_to_size
        current = self.state.get_points_to(node)
        if limit is None:
            return current.union(incoming), incoming - current

        from .object import summarize_object

        already_widened = node in self._widened_points_to_nodes
        combined = current.union(incoming)
        if not already_widened and len(combined) <= limit:
            return combined, incoming - current

        summarized = PointsToSet.from_objects(
            (
                summarize_object(obj)
                for obj in (incoming if already_widened else combined)
            ),
            arena=self.state.arena,
        )
        if already_widened:
            new_summaries = summarized - current
            remaining = max(0, limit - len(current))
            if len(new_summaries) > remaining:
                new_summaries = PointsToSet.from_objects(
                    sorted(new_summaries, key=stable_token)[:remaining],
                    arena=self.state.arena,
                )
            widened = current.union(new_summaries)
            return widened, new_summaries

        # Context truncation normally collapses recursive alternatives below
        # the threshold.  If distinct allocation sites still exceed it, keep
        # a deterministic bounded subset and expose the loss via completeness
        # metadata instead of allowing unbounded growth.
        if len(summarized) > limit:
            summarized = PointsToSet.from_objects(
                sorted(summarized, key=stable_token)[:limit],
                arena=self.state.arena,
            )

        if not already_widened:
            self._widened_points_to_nodes.add(node)
            reason = (
                f"points-to set exceeded max_points_to_size={limit}; "
                "context alternatives were widened"
            )
            self._unknown_tracker.record(
                UnknownKind.POINTS_TO_WIDENING,
                str(node),
                reason,
            )
            if isinstance(node, NormalNode):
                self.mark_semantic_incomplete(
                    variables=(node.var,),
                    kind=UnknownKind.POINTS_TO_WIDENING.value,
                    message=reason,
                )
            else:
                self.mark_semantic_incomplete(
                    kind=UnknownKind.POINTS_TO_WIDENING.value,
                    message=reason,
                )

        return summarized, summarized - current

    def _log_solver_state(self):
        """Log periodic snapshot of solver state for debugging."""
        if not self._debug_monitor or not self._debug_monitor.enabled:
            return
        
        self._debug_monitor.record_iteration_snapshot(
            worklist_size=len(self.state._worklist),
            call_edges=self.state._call_graph.num_plain_edges(),
            pfg_edges=len(self.state.pointer_flow_graph.get_edges()),
            num_variables=len(self.state._env),
            num_objects=len(self.state._heap.objects)
        )

    def _apply_static(self, scope: 'Scope', context: 'AbstractContext', constraint: 'Constraint'):
        if isinstance(constraint, AllocConstraint):
            self._apply_alloc(scope, context, constraint)
        elif isinstance(constraint, CopyConstraint):
            self._apply_copy(scope, context, constraint)

    def _apply_constraint(self, scope: 'Scope', variable: Ctx[Any], constraint: 'Constraint', diff: 'PointsToSet') -> bool:        
        self.processor.handle_constraint(self, variable, scope, constraint, diff)
        
        # Here shoud add supports for Imports
        if isinstance(constraint, LoadConstraint):
            return self._apply_load(scope, variable, constraint, diff)
        elif isinstance(constraint, StoreConstraint):
            return self._apply_store(scope, variable, constraint, diff)
        elif isinstance(constraint, CallConstraint):
            return self._apply_call(scope, variable, constraint, diff)
        elif isinstance(constraint, InheritanceConstraint):
            return self._apply_inheritance(scope, variable, constraint, diff)

    def _apply_copy(self, scope: 'Scope', context: 'AbstractContext', c: 'CopyConstraint'):
        """Apply copy constraint: target = source."""
        src = self.state.get_variable(scope, context, c.source)
        tgt = self.state.get_variable(scope, context, c.target)
        self.state._add_var_points_flow(src, tgt)
        
    def _apply_alloc(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint'):
        """Apply allocation constraint: target = new Object."""

        target = self.state.get_variable(scope, context, c.target)

        orig_obj = self.state._heap.get_obj(scope, context, c.alloc_site)
        if orig_obj is not None:  #  and not isinstance(orig_obj, AbstractObject):
            return
        
        if self.processor.handle_allocation(self, target, scope, context, c):
            return

        if c.alloc_site.kind == AllocKind.FUNCTION:
            obj = self._alloc_function(scope, context, c)
        
        elif c.alloc_site.kind == AllocKind.METHOD:
            obj = self._alloc_method(scope, context, c)

        elif c.alloc_site.kind == AllocKind.CLASS:
            # complex class translation logic, for processing base classes
            if self.config.debug_inheritance:
                logger.info(f"[ALLOC] Allocating class: {c.target.name}")
            obj = self._alloc_class(scope, context, c)
        
        elif c.alloc_site.kind == AllocKind.MODULE:
            obj = self._alloc_module(scope, context, c)

        elif c.alloc_site.kind == AllocKind.NATIVE:
            obj = self._alloc_native_module(context, c)
        
        elif c.alloc_site.kind == AllocKind.CONSTANT and self.config.index_sensitive:
            obj = self._alloc_constant(scope, context, c)
        
        elif c.alloc_site.kind == AllocKind.OBJECT and False:
            # logic for instance allocation is located in _apply_call
            obj = None 
        elif not self.config.index_sensitive:
            obj = AbstractObject(alloc_site=c.alloc_site, context=context)
                
        else:
            obj = AbstractObject(alloc_site=c.alloc_site, context=context)

        if obj is not None:
            self.state._heap.set_obj(scope, context, c.alloc_site, obj)
            pts = PointsToSet.singleton(obj)
            target = self.state.get_variable(scope, context, c.target)
            
            if self.config.debug_inheritance and c.alloc_site.kind == AllocKind.CLASS:
                logger.info(f"[ALLOC] Adding class object to variable: {c.target.name} = {obj.alloc_site.stmt.name if hasattr(obj.alloc_site.stmt, 'name') else obj}")
                logger.info(f"  Target variable: {target}")
            
            # Debug monitoring: record object allocation
            if self._debug_monitor and self._debug_monitor.enabled and self._debug_monitor.track_object_flow:
                obj_id = f"{c.alloc_site.kind.value}:{stable_token(obj)}"
                location = str(c.alloc_site)
                self._debug_monitor.record_object_allocated(
                    obj_id=obj_id,
                    obj_kind=c.alloc_site.kind.value,
                    location=location,
                    target_var=str(c.target)
                )
            self.state.obj_scope[obj] = scope
            if isinstance(obj, ClassObject) and (
                obj.base_variables or obj.metaclass_variables
            ):
                self.state.defer_class_binding(obj, scope, target)
                self.state.release_class_binding_if_feasible(obj)
            else:
                self.handle_new_points_to(target, scope, pts)

    @staticmethod
    def _native_import_path(stmt) -> str:
        module = getattr(stmt, "module", None)
        name = getattr(stmt, "name", "")
        if module is None:
            return name
        return module or name

    def _alloc_native_module(
        self,
        context: 'AbstractContext',
        c: 'AllocConstraint',
    ) -> 'NativeModuleObject':
        return NativeModuleObject(
            context=context,
            alloc_site=c.alloc_site,
            access_path=self._native_import_path(c.alloc_site.stmt),
        )
    
    def handle_new_points_to(self, target: 'Ctx[Any]', scope: 'Scope', pts: 'PointsToSet') -> None:
        if not self.processor.handle_new_points_to(self, target, scope, pts):
            self.state._worklist.add((scope, NormalNode(target), pts))
    
    def _alloc_constant(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'ConstantObject':
        stmt: 'IRAssign' = c.alloc_site.stmt
        assert isinstance(stmt, IRAssign), f"alloc_site.stmt must be an IRAssign, but got {type(stmt)}"
        obj = ConstantObject(self.context_selector.empty_context(), c.alloc_site, stmt.get_rval().value)
        return obj

    def _infer_free_vars(self, ir_func: 'IRFunc') -> Set[str]:
        ir = self.state.scope_manager.get_ir(ir_func, "ir")
        if ir is None:
            return set()
        loads = set()
        stores = set()
        for stmt in ir:
            loads.update(stmt.get_loads())
            stores.update(stmt.get_stores())
            if isinstance(stmt, IRStoreSubscr):
                subslice = stmt.get_slice()
                if isinstance(subslice, ast.Name):
                    loads.add(subslice.id)
        free_vars = loads - stores - ir_func.get_arg_names()
        free_vars.difference_update(ir_func.get_global_vars())
        free_vars.difference_update(ir_func.get_nonlocal_vars())
        return {name for name in free_vars if name and name.isidentifier()}

    def _function_binders(self, ir_func: 'IRFunc') -> Set[str]:
        binders = set(ir_func.get_arg_names())
        ir = self.state.scope_manager.get_ir(ir_func, "ir") or ()
        for stmt in ir:
            binders.update(stmt.get_stores())
        binders.difference_update(ir_func.get_global_vars())
        binders.difference_update(ir_func.get_nonlocal_vars())
        return {name for name in binders if name and name.isidentifier()}

    def _resolve_outer_var_kind(self, scope: 'Scope', var_name: str) -> VariableKind:
        stmt = getattr(scope, "stmt", None)
        if isinstance(stmt, IRModule):
            return VariableKind.GLOBAL
        if isinstance(stmt, IRFunc):
            if var_name in stmt.get_global_vars():
                return VariableKind.GLOBAL
            if var_name in stmt.get_nonlocal_vars():
                return VariableKind.NONLOCAL
            if var_name in stmt.get_cell_vars():
                return VariableKind.CELL
            if var_name in stmt.arg_names:
                return VariableKind.LOCAL
        return VariableKind.LOCAL
    
    def _resolve_nonlocal_binding(
        self,
        scope: 'Scope',
        var_name: str,
    ) -> Optional['Ctx[Variable]']:
        """Resolve ``nonlocal`` to the nearest enclosing function binding."""
        current = scope
        visited = set()
        while current is not None and current not in visited:
            visited.add(current)
            if isinstance(current.stmt, IRFunc):
                func_obj = getattr(current, "obj", None)
                if isinstance(func_obj, FunctionObject):
                    captured = self.state.get_nonlocal_var(func_obj, var_name)
                    if captured is not None:
                        return captured
                for kind in (VariableKind.CELL, VariableKind.LOCAL, VariableKind.PARAMETER):
                    binding = self.state._get_variable_direct(
                        current, current.context, var_name, kind
                    )
                    if binding is not None:
                        return binding
                if (
                    var_name in current.stmt.get_cell_vars()
                    or var_name in current.stmt.arg_names
                ):
                    kind = (
                        VariableKind.CELL
                        if var_name in current.stmt.get_cell_vars()
                        else VariableKind.LOCAL
                    )
                    return self.state.get_variable(
                        current,
                        current.context,
                        self.variable_factory.make_variable(var_name, kind),
                    )
            parent = current.parent
            if parent is current:
                break
            current = parent
        return None
    
    def _alloc_method(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'MethodObject':
        ir_func = c.alloc_site.stmt
        assert isinstance(ir_func, IRFunc), f"AllocSite to be allocated as function {c.alloc_site} should be IRFunc, {type(ir_func)} got!"

        lexical_scope = scope.parent if isinstance(scope.stmt, IRClass) else scope
        obj = MethodObject(
            context,
            c.alloc_site,
            lexical_scope,
            c.alloc_site.stmt,
            scope.obj,
            None,
        )
        
        # process cell vars into the closure
        cell_vars = {}
        cell_var_names = set(ir_func.get_cell_vars())
        if not cell_var_names:
            cell_var_names = self._infer_free_vars(ir_func)
        cell_var_names.difference_update(self._function_binders(ir_func))
        closure_scope = scope.parent or scope
        for var_name in cell_var_names:
            var_kind = self._resolve_outer_var_kind(closure_scope, var_name)
            var = self.variable_factory.make_variable(var_name, var_kind)
            cell_vars[var_name] = self.state.get_variable(closure_scope, context, var)
        self.state.set_cell_vars(obj, cell_vars)
        
        # collect global vars into the closure
        global_vars = {}
        for var_name in ir_func.get_global_vars():
            var = self.variable_factory.make_variable(var_name, VariableKind.GLOBAL)
            global_vars[var_name] = self.state.get_variable(scope.parent, context, var)
        self.state.set_global_vars(obj, global_vars)
            
        # collect nonlocal vars into the closure
        nonlocal_vars = {}
        for var_name in ir_func.get_nonlocal_vars():
            binding = self._resolve_nonlocal_binding(scope, var_name)
            if binding is not None:
                nonlocal_vars[var_name] = binding
        self.state.set_nonlocal_vars(obj, nonlocal_vars)
        return obj

    def _alloc_function(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'FunctionObject':
        ir_func = c.alloc_site.stmt
        # logger.info(f"alloc function {c}")
        assert isinstance(ir_func, IRFunc), f"AllocSite to be allocated as function {c.alloc_site} should be IRFunc, {type(ir_func)} got!"

        lexical_scope = scope.parent if isinstance(scope.stmt, IRClass) else scope
        obj = FunctionObject(
            context,
            c.alloc_site,
            lexical_scope,
            c.alloc_site.stmt,
        )
        
        # process cell vars into the closure
        cell_vars = {}
        cell_var_names = set(ir_func.get_cell_vars())
        if not cell_var_names:
            cell_var_names = self._infer_free_vars(ir_func)
        cell_var_names.difference_update(self._function_binders(ir_func))
        for var_name in cell_var_names:
            var_kind = self._resolve_outer_var_kind(scope, var_name)
            var = self.variable_factory.make_variable(var_name, var_kind)
            cell_vars[var_name] = self.state.get_variable(scope, context, var)
        self.state.set_cell_vars(obj, cell_vars)
        
        # collect global vars into the closure
        global_vars = {}
        for var_name in ir_func.get_global_vars():
            var = self.variable_factory.make_variable(var_name, VariableKind.GLOBAL)
            global_vars[var_name] = self.state.get_variable(scope, context, var)
        self.state.set_global_vars(obj, global_vars)
            
        # collect nonlocal vars into the closure
        nonlocal_vars = {}
        for var_name in ir_func.get_nonlocal_vars():
            binding = self._resolve_nonlocal_binding(scope, var_name)
            if binding is not None:
                nonlocal_vars[var_name] = binding
        self.state.set_nonlocal_vars(obj, nonlocal_vars)
        return obj
    
    def _alloc_class(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'ClassObject':
        ir_cls = c.alloc_site.stmt
        # logger.info(f"alloc class {c}")
        assert isinstance(ir_cls, IRClass), f"AllocSite to be allocated as class {c.alloc_site} should be IRClass, {type(ir_cls)} got!"

        base_variables = self.ir_translator.get_class_base_variables(ir_cls)
        effective_base_variables = tuple(
            Variable(
                name=f"$effective_base@{stable_token(ir_cls)}@{index}",
                kind=VariableKind.TEMPORARY,
            )
            for index in range(len(base_variables))
        )
        obj = ClassObject(
            context=context,
            alloc_site=c.alloc_site,
            container_scope=scope,
            ir=c.alloc_site.stmt,
            base_variables=base_variables,
            metaclass_variables=(
                self.ir_translator.get_class_metaclass_variables(ir_cls)
            ),
            class_keyword_variables=(
                self.ir_translator.get_class_keyword_variables(ir_cls)
            ),
            effective_base_variables=effective_base_variables,
        )
        if self.class_hierarchy is not None:
            self.class_hierarchy.add_class(obj)
        
        cls_context = self.context_selector.select_alloc_context(context, obj)
        
        # process cell vars into the closure
        cell_vars = {}
        for var_name in ir_cls.get_cell_vars():
            var = self.variable_factory.make_variable(var_name, VariableKind.CELL)
            cell_vars[var_name] = self.state.get_variable(scope, context, var)
        self.state.set_cell_vars(obj, cell_vars)
        
        # collect global vars into the closure
        global_vars = {}
        for var_name in ir_cls.get_global_vars():
            var = self.variable_factory.make_variable(var_name, VariableKind.GLOBAL)
            global_vars[var_name] = self.state.get_variable(scope, context, var)
        self.state.set_global_vars(obj, global_vars)
            
        # collect nonlocal vars into the closure
        nonlocal_vars = {}
        for var_name in ir_cls.get_nonlocal_vars():
            var = self.variable_factory.make_variable(var_name, VariableKind.NONLOCAL)
            nonlocal_vars[var_name] = self.state.get_variable(scope, context, var)
        self.state.set_nonlocal_vars(obj, nonlocal_vars)

        # resolve the content of module
        ctx_scope = Scope.new(obj, scope.module, cls_context, ir_cls, scope)
        self.state.set_internal_scope(obj, ctx_scope)

        # inner_var = self.state.get_variable(ctx_scope, context, self.variable_factory.make_variable("$class", VariableKind.LOCAL))
        # self.state._worklist.add((scope, NormalNode(inner_var), PointsToSet.singleton(obj)))

        # translate the IRs in the imported module        
        for constraint in self.ir_translator.translate_class(ir_cls):
            self.add_constraint(ctx_scope, cls_context, constraint)
        
        for inner_var in self.ir_translator.get_class_used_variables(ir_cls):
            field = attr(inner_var.name)
            ctx_field = self.state.get_field(scope, context, obj, field)
            self.state.mark_field_presence(
                obj,
                field,
                must_exist=inner_var.name in ir_cls.get_definitely_declared_names(),
            )
            ctx_inner_var = self.state.get_variable(ctx_scope, cls_context, inner_var)
            self.state._add_var_points_flow(ctx_inner_var, ctx_field)
            if self.config.debug_inheritance:
                logger.info(f"[CLASS] Storing field {obj.alloc_site.stmt.name}.{inner_var.name}: {ctx_inner_var} -> {ctx_field}")

        self._install_class_base_resolution(scope, context, obj)
        self._install_class_namespace(scope, context, obj, ctx_scope, cls_context)
        self._install_class_slots(scope, context, obj)
        self.state.refresh_class_variants(obj)

        meta_sources = tuple(
            self.state.get_variable(scope, context, meta_var)
            for meta_var in obj.metaclass_variables
        )
        if meta_sources:
            self.state.dependencies.subscribe(
                ("class-variant-metaclass", obj),
                meta_sources,
                lambda: self._refresh_class_construction(
                    scope, context, obj, c.target
                ),
            )

        effective_sources = tuple(
            self.state.get_variable(scope, context, base_var)
            for base_var in obj.effective_base_variables
        )
        if effective_sources:
            self.state.dependencies.subscribe(
                ("class-construction-bases", obj),
                effective_sources,
                lambda: self._refresh_class_construction(
                    scope, context, obj, c.target
                ),
            )

        self._refresh_class_construction(scope, context, obj, c.target)

        return obj

    def _install_class_slots(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
    ) -> None:
        class_scope = self.state.get_internal_scope(class_obj)
        slot_var = next((
            variable
            for variable in self.ir_translator.get_class_used_variables(
                class_obj.ir
            )
            if variable.name == "__slots__"
        ), None)
        if class_scope is None or slot_var is None:
            return
        slot_ctx = self.state.get_variable(
            class_scope, class_obj.context, slot_var
        )

        def resolve_slots() -> None:
            for slot_obj in self.state.get_points_to(slot_ctx):
                if (
                    isinstance(slot_obj, ConstantObject)
                    and isinstance(slot_obj.value, str)
                ):
                    self._publish_class_slots(
                        scope, context, class_obj, (slot_obj.value,)
                    )
                    continue
                if not isinstance(slot_obj, (TupleObject, ListObject)):
                    continue
                statement = slot_obj.alloc_site.stmt
                value_ast = (
                    statement.get_rval()
                    if isinstance(statement, IRAssign)
                    else None
                )
                if not isinstance(value_ast, (ast.Tuple, ast.List)):
                    continue
                if not value_ast.elts:
                    self._publish_class_slots(
                        scope, context, class_obj, ()
                    )
                    continue
                element_fields = tuple(
                    self.state.raw_field(
                        class_scope,
                        class_obj.context,
                        slot_obj,
                        key(index) if self.config.index_sensitive else elem(),
                    )
                    for index in range(len(value_ast.elts))
                )

                def resolve_elements(
                    element_fields=element_fields,
                    slot_obj=slot_obj,
                ) -> None:
                    names = []
                    for element_field in element_fields:
                        element_pts = self.state.get_points_to(element_field)
                        if element_pts.is_empty():
                            return
                        constants = {
                            obj.value
                            for obj in element_pts
                            if isinstance(obj, ConstantObject)
                            and isinstance(obj.value, str)
                        }
                        if len(constants) != len(element_pts):
                            return
                        names.extend(constants)
                    self._publish_class_slots(
                        scope, context, class_obj, names
                    )

                self.state.dependencies.subscribe(
                    ("class-slot-elements", class_obj, slot_obj),
                    element_fields,
                    resolve_elements,
                )
                resolve_elements()

        self.state.dependencies.subscribe(
            ("class-slots", class_obj), (slot_ctx,), resolve_slots
        )
        resolve_slots()

    def _publish_class_slots(
        self, scope, context, class_obj, slot_names
    ) -> None:
        self.state.record_class_slots(class_obj, slot_names)
        for slot_name in slot_names:
            if slot_name in {"__dict__", "__weakref__"}:
                continue
            descriptor_key = (class_obj, slot_name)
            if descriptor_key in self._installed_slot_descriptors:
                continue
            self._installed_slot_descriptors.add(descriptor_key)
            descriptor = SlotDescriptorObject(
                context=class_obj.context,
                alloc_site=AllocSite(
                    f"<slot:{class_obj.ir.get_qualname()}.{slot_name}>",
                    AllocKind.OBJECT,
                ),
                owner=class_obj,
                slot_name=slot_name,
            )
            field = attr(slot_name)
            field_ctx = self.state.raw_field(
                scope, context, class_obj, field
            )
            self.state.mark_field_presence(
                class_obj, field, must_exist=True
            )
            self.state.obj_scope[descriptor] = scope
            self.handle_new_points_to(
                field_ctx, scope, PointsToSet.singleton(descriptor)
            )

    def _refresh_class_construction(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
        result_var: 'Variable',
    ) -> None:
        """Publish type variants or invoke arbitrary callable metaclasses."""
        before = self.state.class_variants(class_obj)
        self.state.refresh_class_variants(class_obj)
        if self.state.class_variants(class_obj) != before:
            self.state.dependencies.notify_growth(
                ("class-variants", class_obj)
            )
        self.state.release_class_binding_if_feasible(class_obj)
        for variant in self.state.class_variants(class_obj):
            self._install_class_variant_hooks(
                scope, context, class_obj, result_var, variant
            )
            if not self.state.classes.variant_has_custom_metaclass_new(variant):
                self._install_class_owner_hooks(scope, context, class_obj)
        for meta_var in class_obj.metaclass_variables:
            meta_ctx = self.state.get_variable(scope, context, meta_var)
            for meta_obj in self.state.get_points_to(meta_ctx):
                type_ref = self.state._type_ref(meta_obj)
                if type_ref.kind is not TypeRefKind.OPAQUE:
                    continue
                key_ = (class_obj, meta_obj, result_var)
                if key_ in self._dispatched_class_factories:
                    continue
                self._dispatched_class_factories.add(key_)
                self._dispatch_class_factory(
                    scope, context, class_obj, result_var, meta_obj
                )

    def _install_class_variant_hooks(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
        result_var: 'Variable',
        variant,
    ) -> None:
        hook_key = (class_obj, variant)
        if hook_key in self._installed_class_variant_hooks:
            return
        self._installed_class_variant_hooks.add(hook_key)
        metaclass = variant.metaclass
        if (
            metaclass.kind is not TypeRefKind.USER
            or not isinstance(metaclass.target, ClassObject)
        ):
            return

        meta_obj = metaclass.target
        token = stable_token(class_obj.ir)
        name_var = self._class_name_variable(scope, context, class_obj)
        bases_var = self._original_bases_variable(
            scope, context, class_obj
        )
        synthetic_namespace = self._class_namespaces[class_obj]
        prepare_result = Variable(
            name=f"$prepared_namespace@{token}@{stable_token(meta_obj)}",
            kind=VariableKind.TEMPORARY,
        )
        prepared_ctx = self.state.get_variable(
            scope, context, prepare_result
        )
        if self._variant_has_custom_metaclass_method(
            variant, "__prepare__"
        ):
            self._install_optional_object_method_call(
                scope,
                context,
                owner=meta_obj,
                field=attr("__prepare__"),
                key_=("class-prepare", class_obj, variant),
                args_factory=lambda _callee: (name_var, bases_var),
                kwargs=class_obj.class_keyword_variables,
                target=prepare_result,
                call_site=CallSite(
                    statement=class_obj.ir,
                    scope_name=class_obj.ir.get_qualname(),
                    index=10,
                ),
            )
        else:
            synthetic_ctx = self.state.get_variable(
                scope, context, synthetic_namespace
            )
            self.state._add_var_points_flow(synthetic_ctx, prepared_ctx)
        self.state.dependencies.subscribe(
            ("prepared-namespace-result", class_obj, variant),
            (prepared_ctx,),
            lambda: self._populate_class_namespace_objects(
                scope,
                context,
                class_obj,
                self.state.get_points_to(prepared_ctx),
            ),
        )

        if self.state.classes.variant_has_custom_metaclass_new(variant):
            meta_var = self._class_object_variable(
                scope, context, meta_obj, "metaclass"
            )
            self._install_optional_object_method_call(
                scope,
                context,
                owner=meta_obj,
                field=attr("__new__"),
                key_=("class-metaclass-new", class_obj, variant),
                args_factory=lambda _callee: (
                    meta_var, name_var, bases_var, prepare_result
                ),
                kwargs=class_obj.class_keyword_variables,
                target=result_var,
                call_site=CallSite(
                    statement=class_obj.ir,
                    scope_name=class_obj.ir.get_qualname(),
                    index=11,
                ),
            )
            result_ctx = self.state.get_variable(
                scope, context, result_var
            )

            def install_type_new_hooks() -> None:
                if class_obj in self.state.get_points_to(result_ctx):
                    self._install_class_owner_hooks(
                        scope, context, class_obj
                    )

            self.state.dependencies.subscribe(
                ("type-new-owner-hooks", class_obj, variant),
                (result_ctx,),
                install_type_new_hooks,
            )

        created_class_var = self._class_object_variable(
            scope, context, class_obj, "created_class"
        )
        self._install_optional_object_method_call(
            scope,
            context,
            owner=meta_obj,
            field=attr("__init__"),
            key_=("class-metaclass-init", class_obj, variant),
            args_factory=lambda _callee: (
                created_class_var, name_var, bases_var, prepare_result
            ),
            kwargs=class_obj.class_keyword_variables,
            target=None,
            call_site=CallSite(
                statement=class_obj.ir,
                scope_name=class_obj.ir.get_qualname(),
                index=12,
            ),
        )

    def _variant_has_custom_metaclass_method(
        self, variant, method_name: str
    ) -> bool:
        metaclass = variant.metaclass
        if (
            metaclass.kind is not TypeRefKind.USER
            or not isinstance(metaclass.target, ClassObject)
        ):
            return False
        for type_ref in self.state.types.mro(metaclass):
            if (
                type_ref.kind is TypeRefKind.USER
                and isinstance(type_ref.target, ClassObject)
                and method_name
                in type_ref.target.ir.get_definitely_declared_names()
            ):
                return True
        return False

    def _install_class_owner_hooks(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
    ) -> None:
        if class_obj in self._installed_class_owner_hooks:
            return
        self._installed_class_owner_hooks.add(class_obj)
        owner_var = self._class_object_variable(
            scope, context, class_obj, "class_hook_owner"
        )
        for index, inner_var in enumerate(
            self.ir_translator.get_class_used_variables(class_obj.ir)
        ):
            method_var = Variable(
                name=(
                    f"$set_name@{stable_token(class_obj.ir)}@"
                    f"{stable_token(inner_var)}"
                ),
                kind=VariableKind.TEMPORARY,
            )
            self.add_constraint(
                self.state.get_internal_scope(class_obj),
                class_obj.context,
                LoadConstraint(
                    base=inner_var,
                    field=attr("__set_name__"),
                    target=method_var,
                ),
            )
            name_var = self._constant_string_variable(
                scope,
                context,
                f"$set_name_field@{stable_token(class_obj.ir)}@{index}",
                inner_var.name,
            )
            method_ctx = self.state.get_variable(
                self.state.get_internal_scope(class_obj),
                class_obj.context,
                method_var,
            )
            self._schedule_optional_call(
                scope,
                context,
                method_ctx,
                ("set-name", class_obj, inner_var),
                lambda _callee, owner_var=owner_var, name_var=name_var: (
                    owner_var, name_var
                ),
                (),
                None,
                CallSite(
                    statement=class_obj.ir,
                    scope_name=class_obj.ir.get_qualname(),
                    index=20 + index,
                ),
            )

        if not class_obj.base_variables:
            return
        init_subclass_var = Variable(
            name=f"$init_subclass@{stable_token(class_obj.ir)}",
            kind=VariableKind.TEMPORARY,
        )
        init_subclass_ctx = self.state.get_variable(
            scope, context, init_subclass_var
        )
        selector = SelectorNode()
        binding = ClassBindingNode(
            class_obj, ("init-subclass", class_obj)
        )
        self.state._add_points_flow_edge(PointerFlowEdge(
            selector, binding, PointerFlowKind.NORMAL
        ))
        self.state._add_points_flow_edge(PointerFlowEdge(
            binding, NormalNode(init_subclass_ctx), PointerFlowKind.NORMAL
        ))
        self.state.register_class_inheritance_lookup(
            class_obj, attr("__init_subclass__"), selector
        )
        self.state.refresh_class_inheritance(
            class_obj, attr("__init_subclass__"), selector
        )
        effective_sources = tuple(
            self.state.get_variable(scope, context, base_var)
            for base_var in class_obj.effective_base_variables
        )
        if effective_sources:
            self.state.dependencies.subscribe(
                ("init-subclass-bases", class_obj),
                effective_sources,
                lambda: self.state.refresh_class_inheritance(
                    class_obj, attr("__init_subclass__"), selector
                ),
            )
        self._schedule_optional_call(
            scope,
            context,
            init_subclass_ctx,
            ("init-subclass", class_obj),
            lambda callee: (
                ()
                if (
                    isinstance(callee, MethodObject)
                    and callee.ir.is_class_method
                )
                else (owner_var,)
            ),
            class_obj.class_keyword_variables,
            None,
            CallSite(
                statement=class_obj.ir,
                scope_name=class_obj.ir.get_qualname(),
                index=30,
            ),
        )

    def _install_optional_object_method_call(
        self,
        scope,
        context,
        *,
        owner,
        field,
        key_,
        args_factory,
        kwargs,
        target,
        call_site,
    ) -> None:
        method_var = Variable(
            name=f"$optional_method@{stable_token(key_)}",
            kind=VariableKind.TEMPORARY,
        )
        method_ctx = self.state.get_variable(scope, context, method_var)
        if not self.processor.handle_field_read(
            self, scope, context, owner, field, method_var
        ):
            owner_scope = self.state.get_internal_scope(owner) or scope
            raw = self.state.raw_field(
                owner_scope, owner.context, owner, field
            )
            self.state._add_var_points_flow(raw, method_ctx)
        self._schedule_optional_call(
            scope,
            context,
            method_ctx,
            key_,
            args_factory,
            kwargs,
            target,
            call_site,
        )

    def _schedule_optional_call(
        self,
        scope,
        context,
        callee_ctx,
        key_,
        args_factory,
        kwargs,
        target,
        call_site,
    ) -> None:
        def schedule() -> None:
            for callee in self.state.get_points_to(callee_ctx):
                fact = (key_, callee)
                if fact in self._scheduled_optional_calls:
                    continue
                self._scheduled_optional_calls.add(fact)
                isolated = Variable(
                    name=(
                        f"$optional_callee@{stable_token(key_)}@"
                        f"{stable_token(callee)}"
                    ),
                    kind=VariableKind.TEMPORARY,
                )
                isolated_ctx = self.state.get_variable(
                    scope, context, isolated
                )
                self.handle_new_points_to(
                    isolated_ctx, scope, PointsToSet.singleton(callee)
                )
                self.add_constraint(
                    scope,
                    context,
                    CallConstraint(
                        callee=isolated,
                        args=tuple(args_factory(callee)),
                        kwargs=tuple(kwargs),
                        target=target,
                        call_site=call_site,
                    ),
                )

        self.state.dependencies.subscribe(
            ("optional-call", key_), (callee_ctx,), schedule
        )

    def _class_object_variable(
        self, scope, context, class_obj, prefix
    ) -> 'Variable':
        key_ = (scope, context, class_obj, prefix)
        existing = self._class_object_variables.get(key_)
        if existing is not None:
            return existing
        variable = Variable(
            name=f"${prefix}@{stable_token(class_obj)}",
            kind=VariableKind.TEMPORARY,
        )
        ctx_var = self.state.get_variable(scope, context, variable)
        self.handle_new_points_to(
            ctx_var, scope, PointsToSet.singleton(class_obj)
        )
        self._class_object_variables[key_] = variable
        return variable

    def _constant_string_variable(
        self, scope, context, variable_name, value
    ) -> 'Variable':
        variable = Variable(
            name=variable_name, kind=VariableKind.TEMPORARY
        )
        assign = IRAssign(ast.Assign(
            targets=[ast.Name(id=variable_name, ctx=ast.Store())],
            value=ast.Constant(value),
        ))
        self.add_constraint(
            scope,
            context,
            AllocConstraint(
                target=variable,
                alloc_site=AllocSite.from_ir_node(
                    assign, AllocKind.CONSTANT
                ),
            ),
        )
        return variable

    def _populate_class_namespace_objects(
        self, scope, context, class_obj, namespace_points
    ) -> None:
        class_scope = self.state.get_internal_scope(class_obj)
        if class_scope is None:
            return
        for namespace_obj in namespace_points:
            if not isinstance(namespace_obj, DictObject):
                self.mark_semantic_incomplete(
                    scopes=(class_scope,),
                    message=(
                        "custom prepared namespace writes are modeled as "
                        "raw mapping entries; __setitem__ effects are unknown"
                    ),
                )
            for inner_var in self.ir_translator.get_class_used_variables(
                class_obj.ir
            ):
                inner_ctx = self.state.get_variable(
                    class_scope, class_obj.context, inner_var
                )
                field_ctx = self.state.raw_field(
                    scope,
                    context,
                    namespace_obj,
                    key(inner_var.name),
                )
                self.state._add_var_points_flow(inner_ctx, field_ctx)

    def _dispatch_class_factory(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
        result_var: 'Variable',
        metaclass_obj: 'AbstractObject',
    ) -> None:
        token = stable_token(class_obj.ir)
        callee_var = Variable(
            name=f"$class_factory@{token}@{stable_token(metaclass_obj)}",
            kind=VariableKind.TEMPORARY,
        )
        callee_ctx = self.state.get_variable(scope, context, callee_var)
        self.handle_new_points_to(
            callee_ctx, scope, PointsToSet.singleton(metaclass_obj)
        )
        self.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=callee_var,
                args=(
                    self._class_name_variable(scope, context, class_obj),
                    self._original_bases_variable(scope, context, class_obj),
                    self._class_namespaces[class_obj],
                ),
                kwargs=class_obj.class_keyword_variables,
                target=result_var,
                call_site=CallSite(
                    statement=class_obj.ir,
                    scope_name=(
                        class_obj.container_scope.stmt.get_qualname()
                        if hasattr(
                            class_obj.container_scope.stmt, "get_qualname"
                        )
                        else str(class_obj.container_scope.stmt)
                    ),
                ),
            ),
        )

    def _class_name_variable(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
    ) -> 'Variable':
        existing = self._class_name_variables.get(class_obj)
        if existing is not None:
            return existing
        name = f"$class_name@{stable_token(class_obj.ir)}"
        variable = Variable(name=name, kind=VariableKind.TEMPORARY)
        assign = IRAssign(ast.Assign(
            targets=[ast.Name(id=name, ctx=ast.Store())],
            value=ast.Constant(class_obj.ir.name),
        ))
        self.add_constraint(
            scope,
            context,
            AllocConstraint(
                target=variable,
                alloc_site=AllocSite.from_ir_node(
                    assign, AllocKind.CONSTANT
                ),
            ),
        )
        self._class_name_variables[class_obj] = variable
        return variable

    def _original_bases_variable(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
    ) -> 'Variable':
        existing = self._class_original_bases.get(class_obj)
        if existing is not None:
            return existing
        tuple_name = f"$original_bases@{stable_token(class_obj.ir)}"
        original_bases = Variable(
            name=tuple_name,
            kind=VariableKind.TEMPORARY,
        )
        tuple_assign = IRAssign(ast.Assign(
            targets=[ast.Name(id=tuple_name, ctx=ast.Store())],
            value=ast.Tuple(
                elts=[
                    ast.Name(id=base_var.name, ctx=ast.Load())
                    for base_var in class_obj.base_variables
                ],
                ctx=ast.Load(),
            ),
        ))
        self.add_constraint(
            scope,
            context,
            AllocConstraint(
                target=original_bases,
                alloc_site=AllocSite.from_ir_node(
                    tuple_assign, AllocKind.TUPLE
                ),
            ),
        )
        for index, base_var in enumerate(class_obj.base_variables):
            self.add_constraint(scope, context, StoreConstraint(
                base=original_bases,
                field=key(index),
                source=base_var,
            ))
            self.add_constraint(scope, context, StoreConstraint(
                base=original_bases,
                field=elem(),
                source=base_var,
            ))
        self._class_original_bases[class_obj] = original_bases
        return original_bases

    def _install_class_namespace(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
        class_scope: 'Scope',
        class_context: 'AbstractContext',
    ) -> None:
        token = stable_token(class_obj.ir)
        name = f"$class_namespace@{token}"
        namespace = Variable(name=name, kind=VariableKind.TEMPORARY)
        assign = IRAssign(ast.Assign(
            targets=[ast.Name(id=name, ctx=ast.Store())],
            value=ast.Dict(keys=[], values=[]),
        ))
        self.add_constraint(
            scope,
            context,
            AllocConstraint(
                target=namespace,
                alloc_site=AllocSite.from_ir_node(assign, AllocKind.DICT),
            ),
        )
        namespace_ctx = self.state.get_variable(scope, context, namespace)

        def populate_namespace() -> None:
            for namespace_obj in self.state.get_points_to(namespace_ctx):
                for inner_var in self.ir_translator.get_class_used_variables(
                    class_obj.ir
                ):
                    inner_ctx = self.state.get_variable(
                        class_scope, class_context, inner_var
                    )
                    namespace_field = self.state.raw_field(
                        scope,
                        context,
                        namespace_obj,
                        key(inner_var.name),
                    )
                    self.state._add_var_points_flow(
                        inner_ctx, namespace_field
                    )

        self.state.dependencies.subscribe(
            ("class-namespace", class_obj),
            (namespace_ctx,),
            populate_namespace,
        )
        self._class_namespaces[class_obj] = namespace

    def _install_class_base_resolution(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        class_obj: 'ClassObject',
    ) -> None:
        """Install PEP 560 effective-base expansion for a new class."""
        original_bases = self._original_bases_variable(
            scope, context, class_obj
        )
        for index, base_var in enumerate(class_obj.base_variables):
            self.add_constraint(
                scope,
                context,
                BaseResolutionConstraint(
                    base=base_var,
                    owner=class_obj,
                    position=index,
                    original_bases=original_bases,
                ),
            )

    def _alloc_module(self, scope: 'Scope', context: 'AbstractContext', c: 'AllocConstraint') -> 'ModuleObject':
        assert c.alloc_site.kind == AllocKind.MODULE, "AllocSite kind in module allocation should be Module"
        assert c.alloc_site.stmt is not None, "AllocSite should have IRImport as stmt"

        module_ir = self.state.scope_manager.module_graph.get_succ_module(scope.module.stmt, c.alloc_site.stmt)
                
        if module_ir is None:
            self._unknown_tracker.record(
                UnknownKind.CALLEE_NON_CALLABLE,
                str(c.alloc_site),
                f"Attempting to import unknown module: {c.alloc_site.stmt}",
                context=str(context)
            )
            
            if self.config.verbose:
                logger.warning(f"[UNKNOWN] Module not found at {c.alloc_site}")
            
            unknown_obj = AbstractObject(c.alloc_site, scope.context)
            return unknown_obj

        self._modules.add(module_ir)
        module_obj = ModuleObject(context, c.alloc_site, module_ir)

        # resolve the content of module
        module_ctx = context
        # module_ctx = self.context_selector.select_alloc_context(context, module_obj)
        ctx_scope = Scope.new(module_obj, None, module_ctx, module_ir, None)

        self.state.set_internal_scope(module_obj, ctx_scope)
        self.initialize_builtins(ctx_scope, module_ctx)

        # translate the IRs in the imported module        
        for constraint in self.ir_translator.translate_module(module_ir, c.alloc_site.stmt):
            self.add_constraint(ctx_scope, module_ctx, constraint)
        
        return module_obj

    def _apply_inheritance(self, scope: 'Scope', variable: 'Ctx', c: 'InheritanceConstraint', pts: 'PointsToSet'):
        """Apply inheritance constraint: resolve field from base class.
        
        For each base class object in pts, get the field and create PFG edge
        to the selector node. This allows parent class fields to flow to
        the inheritance target (used by ClassObject and SuperObject).
        """
        from .object import ClassObject
        if isinstance(c.owner, ClassObject) and c.field is not None:
            self.state.refresh_class_inheritance(c.owner, c.field, c.target)
            return True
        for base_obj in pts:
            # For class inheritance, use the base class's internal scope
            if isinstance(base_obj, ClassObject):
                base_internal_scope = self.state.get_internal_scope(base_obj)
                field_access = self.state.get_field(base_internal_scope, base_obj.context, base_obj, c.field)
                if self.config.debug_inheritance:
                    logger.info(f"[INHERIT] Applying inheritance: {base_obj.alloc_site.stmt.name if hasattr(base_obj.alloc_site.stmt, 'name') else base_obj}.{c.field} -> selector")
                    logger.info(f"  Base internal scope: {base_internal_scope.stmt.get_qualname() if hasattr(base_internal_scope.stmt, 'get_qualname') else base_internal_scope.stmt}")
                    logger.info(f"  Field access: {field_access}")
                    logger.info(f"  Field pts: {self.state.get_points_to(field_access)}")
            else:
                field_access = self.state.get_field(scope, scope.context, base_obj, c.field)
            edge = PointerFlowEdge(NormalNode(field_access), c.target, PointerFlowKind.NORMAL)
            # Register the edge with the selector node with its inheritance index
            c.target.add_edge(edge, c.index)
            self.state._add_points_flow_edge(edge)
    
    def _apply_load(self, scope: 'Scope', variable: 'Ctx', c: 'LoadConstraint', pts: 'PointsToSet'):
        """Apply load constraint: target = base.field or target = base[index]."""
        context = scope.context
        target_var = self.state.get_variable(scope, context, c.target)
        
        for base_obj in pts:
            self.state.record_semantic_event(
                PointerEvent(PointerEventKind.LOAD, scope, context, c, base_obj)
            )

            if isinstance(base_obj, NativeObject):
                if c.field is None:
                    child_name = "*"
                elif c.field.kind in (FieldKind.ATTRIBUTE, FieldKind.KEY):
                    child_name = c.field.name or "*"
                else:
                    child_name = "*"
                child = base_obj.child(child_name)
                self.state._worklist.add(
                    (scope, NormalNode(target_var), PointsToSet.singleton(child))
                )
                continue

            # Special handling for module imports: from module import name
            # Instead of using field access, directly copy from module's variable
            if isinstance(base_obj, ModuleObject) and c.field and c.field.kind == FieldKind.ATTRIBUTE:
                # Get the module's internal scope
                module_scope = self.state.get_internal_scope(base_obj)
                if module_scope:
                    # Create variable in module scope for the imported name
                    imported_var_name = c.field.name  # e.g., "foo" from module.foo
                    imported_var = Variable(
                        name=imported_var_name,
                        kind=VariableKind.GLOBAL
                    )
                    # Get the contextualized variable from module scope
                    module_var = self.state.get_variable(module_scope, module_scope.context, imported_var)
                    # Direct copy: module.var -> local.var (bypass field mechanism)
                    self.state._add_var_points_flow(module_var, target_var)
                    continue
            
            # Special handling for builtin methods on container objects
            if c.field and c.field.kind == FieldKind.ATTRIBUTE and c.field.name:
                builtin_type = None
                if isinstance(base_obj, ListObject):
                    builtin_type = "list"
                elif isinstance(base_obj, DictObject):
                    builtin_type = "dict"
                elif isinstance(base_obj, TupleObject):
                    builtin_type = "tuple"
                elif isinstance(base_obj, SetObject):
                    builtin_type = "set"
                elif isinstance(base_obj, BuiltinInstanceObject):
                    builtin_type = base_obj.builtin_type

                if builtin_type:
                    builtin_methods = self.state._get_builtin_methods_for_type(builtin_type)
                    if c.field.name in builtin_methods:
                        method_alloc = AllocSite(
                            stmt=f"<builtin_method:{c.field.name}>",
                            kind=AllocKind.BUILTIN,
                        )
                        method_obj = BuiltinMethodObject(
                            context=context,
                            alloc_site=method_alloc,
                            method_name=c.field.name,
                            receiver=base_obj,
                            receiver_var=c.base,
                        )
                        self.state._worklist.add((scope, NormalNode(target_var), PointsToSet.singleton(method_obj)))
                        continue

                if self.processor.handle_field_read(
                    self,
                    scope,
                    context,
                    base_obj,
                    c.field,
                    target_var,
                ):
                    continue
            
            field_access = self.state.raw_field(scope, context, base_obj, c.field)
            self.state._add_var_points_flow(field_access, target_var)
    
    def _apply_store(self, scope: 'Scope', variable: 'Ctx', c: 'StoreConstraint', pts: 'PointsToSet'):
        """Apply store constraint: base.field = source or base[index] = source."""
        context = scope.context
        source_var = self.state.get_variable(scope, context, c.source)

        for base_obj in pts:
            self.state.record_semantic_event(
                PointerEvent(PointerEventKind.STORE, scope, context, c, base_obj)
            )
            field_access = self.state.raw_field(scope, context, base_obj, c.field)
            self.state._add_var_points_flow(source_var, field_access)
    
    def _apply_call(self, scope: 'Scope', variable: 'Ctx', c: 'CallConstraint', pts: 'PointsToSet') -> bool:
        """Apply call constraint: target = callee(args...)."""
        context = scope.context
        # logger.info(f"Applying call constraint: {c.call_site} -> {pts}")
        
        # Debug monitoring: record call constraint processing
        if self._debug_monitor and self._debug_monitor.enabled:
            self._debug_monitor.record_call_constraint_processed(
                call_site=str(c.call_site),
                callee_var=str(variable),
                callee_pts_size=len(pts)
            )
        
        # Check for empty callee
        if len(pts) == 0:
            if self._debug_monitor and self._debug_monitor.enabled:
                self._debug_monitor.record_call_failed(
                    call_site=str(c.call_site),
                    reason="empty_callee",
                    details="Callee points-to set is empty"
                )
            return False
         
        changed = False
        for callee_obj in pts:
            self.state.record_semantic_event(
                PointerEvent(PointerEventKind.CALL, scope, context, c, callee_obj)
            )
            self._apply_configured_return_effects(scope, context, c, callee_obj)
            # logger.info(f"Handling function call: {c.call_site} -> {callee_obj.alloc_site.stmt}\n    {type(callee_obj)} {type(callee_obj.alloc_site.stmt)}")
            if isinstance(callee_obj, NativeObject):
                changed = self._handle_native_call(scope, context, c, callee_obj)
            elif self.processor.handle_call(self, variable, scope, c, callee_obj):
                changed = True
            else:
                self._unknown_tracker.record(
                    UnknownKind.CALLEE_NON_CALLABLE,
                    str(c.call_site),
                    f"Attempting to call non-callable: {callee_obj.kind.value}",
                    context=str(callee_obj)
                )
                
                # Debug monitoring: record non-callable
                if self._debug_monitor and self._debug_monitor.enabled:
                    self._debug_monitor.record_call_failed(
                        call_site=str(c.call_site),
                        reason="non_callable",
                        details=f"Object kind: {callee_obj.kind.value}"
                    )
                
                if self.config.verbose:
                    logger.warning(f"[UNKNOWN] Non-callable at {c.call_site}: {callee_obj}")
                
                '''
                if c.target:
                    unknown_alloc = AllocSite(
                        file=c.call_site,
                        line=0,
                        col=0,
                        kind=AllocKind.UNKNOWN,
                        scope=scope,
                        name=f"unknown_noncallable_{c.call_site}",
                        stmt=None
                    )
                    target_var = self.state.get_variable(scope, context, c.target)
                    unknown_obj = AbstractObject(unknown_alloc, scope.context)
                    self.state._worklist.add((scope, target_var, PointsToSet.singleton(unknown_obj)))
                    changed = True
                '''
        
        return changed

    def _handle_native_call(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        callee_obj: 'NativeObject',
    ) -> bool:
        """Model an unanalyzed native call while preserving its result flow."""
        exhaustive = self._has_exhaustive_native_summary(callee_obj)
        if not exhaustive:
            affected = [
                self.state.get_variable(scope, context, argument)
                for argument in call.args
            ]
            affected.extend(
                self.state.get_variable(scope, context, argument)
                for _, argument in call.kwargs
            )
            if call.target is not None:
                affected.append(self.state.get_variable(
                    scope, context, call.target
                ))
            self.mark_semantic_incomplete(
                variables=affected,
                scopes=(scope,) if call.target is None else (),
                kind="native_effect",
                message=(
                    f"native call {callee_obj.access_path} has no exhaustive "
                    "effect summary"
                ),
            )
        if call.target is None or exhaustive:
            return True
        target = self.state.get_variable(scope, context, call.target)
        result_path = f"{callee_obj.access_path}.<return>"
        result = NativeObject(
            context=context,
            alloc_site=AllocSite(f"<native:{result_path}>", AllocKind.NATIVE),
            access_path=result_path,
        )
        self.state._worklist.add(
            (scope, NormalNode(target), PointsToSet.singleton(result))
        )
        return True

    def _has_exhaustive_native_summary(self, callee_obj: 'NativeObject') -> bool:
        return any(
            effect.get("exhaustive", False)
            and fnmatchcase(
                callee_obj.access_path,
                effect.get("access_path", ""),
            )
            for effect in self.config.native_effects or ()
        )

    def _apply_configured_return_effects(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        callee_obj: 'AbstractObject',
    ) -> None:
        access_path = self._configured_access_path(callee_obj)
        if access_path is None:
            return
        target = (
            self.state.get_variable(scope, context, call.target)
            if call.target is not None else None
        )
        for effect in self.config.native_effects or ():
            if not fnmatchcase(access_path, effect.get("access_path", "")):
                continue
            kind = effect.get("kind")
            if kind == "return_argument" and target is not None:
                for argument in self._native_effect_variables(call, effect):
                    source = self.state.get_variable(scope, context, argument)
                    self.state._add_var_points_flow(source, target)
            elif kind == "return_receiver" and target is not None:
                receiver = self._configured_receiver(callee_obj, context)
                if receiver is not None:
                    self.state._worklist.add(
                        (scope, NormalNode(target), PointsToSet.singleton(receiver))
                    )
            elif kind == "return_fresh" and target is not None:
                fresh_kind_name = str(effect.get("alloc_kind", "unknown")).upper()
                fresh_kind = getattr(AllocKind, fresh_kind_name, AllocKind.UNKNOWN)
                fresh = AbstractObject(
                    context=context,
                    alloc_site=AllocSite(call.call_site.statement, fresh_kind),
                )
                self.state._worklist.add((
                    scope, NormalNode(target), PointsToSet.singleton(fresh)
                ))

        for effect in self.config.native_effects or ():
            if not fnmatchcase(access_path, effect.get("access_path", "")):
                continue
            kind = effect.get("kind")
            if kind == "write_argument_field":
                receivers = self._effect_variables(
                    call, effect.get("arguments", ())
                )
                values = self._effect_variables(
                    call, effect.get("values", ("*",))
                )
                field_name = effect.get("field")
                field = (
                    attr(field_name)
                    if isinstance(field_name, str) and field_name != "*"
                    else unknown()
                )
                for receiver in receivers:
                    for value_var in values:
                        self.add_constraint(
                            scope,
                            context,
                            StoreConstraint(
                                base=receiver,
                                field=field,
                                source=value_var,
                            ),
                        )
            elif kind == "escape_argument":
                for argument in self._effect_variables(
                    call, effect.get("arguments", ("*",))
                ):
                    argument_ctx = self.state.get_variable(
                        scope, context, argument
                    )
                    self.state.dependencies.subscribe(
                        ("native-escape", call, effect.get("access_path"), argument_ctx),
                        (argument_ctx,),
                        lambda argument_ctx=argument_ctx: self.state.mark_escaped(
                            self.state.get_points_to(argument_ctx)
                        ),
                    )

    @staticmethod
    def _configured_access_path(callee_obj: 'AbstractObject') -> str | None:
        if isinstance(callee_obj, NativeObject):
            return callee_obj.access_path
        if isinstance(callee_obj, FunctionObject):
            module = getattr(callee_obj.container_scope, "module", None)
            filename = str(getattr(getattr(module, "stmt", None), "filename", ""))
            if "/stubs/" in filename or "\\stubs\\" in filename:
                return callee_obj.ir.get_qualname()
        return None

    @staticmethod
    def _configured_receiver(callee_obj, context):
        if isinstance(callee_obj, MethodObject) and callee_obj.instance_obj is not None:
            return callee_obj.instance_obj
        if isinstance(callee_obj, NativeObject) and "." in callee_obj.access_path:
            receiver_path = callee_obj.access_path.rsplit(".", 1)[0]
            return NativeObject(
                context=context,
                alloc_site=AllocSite(f"<native:{receiver_path}>", AllocKind.NATIVE),
                access_path=receiver_path,
            )
        return None

    @staticmethod
    def _native_effect_variables(call: 'CallConstraint', effect: dict):
        """Resolve positional, keyword, and wildcard effect selectors."""
        return PointerSolver._effect_variables(
            call, effect.get("arguments", ())
        )

    @staticmethod
    def _effect_variables(call: 'CallConstraint', selectors):
        selected = []
        keyword_map = {
            name: variable for name, variable in call.kwargs
            if name is not None
        }
        for selector in selectors:
            if selector == "*":
                selected.extend(call.args)
                selected.extend(variable for _, variable in call.kwargs)
            elif isinstance(selector, int) and 0 <= selector < len(call.args):
                selected.append(call.args[selector])
            elif isinstance(selector, str) and selector in keyword_map:
                selected.append(keyword_map[selector])
        return tuple(selected)
 
    def _handle_class_instantiation(self, scope: 'Scope', context: 'AbstractContext', call: 'CallConstraint', class_obj: 'AbstractObject') -> bool:
        """Handle class instantiation: call __new__, then __init__ conditionally."""
        # logger.info(f"Handling class instantiation: {call.call_site} -> {class_obj.alloc_site.stmt}")

        cls_scope = self.state.get_internal_scope(class_obj)
        constructor_owners = [class_obj]
        if self.class_hierarchy is not None:
            try:
                constructor_owners = self.class_hierarchy.get_mro(class_obj)
            except Exception:
                pass
        has_custom_new = any(
            isinstance(owner, ClassObject)
            and any(
                isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                and stmt.name == "__new__"
                for stmt in owner.ir.get_ast().body
            )
            for owner in constructor_owners
        )

        def special_irs(special_name):
            special_var = self.state._get_variable_direct(
                cls_scope,
                cls_scope.context,
                special_name,
                VariableKind.LOCAL,
            )
            candidate_irs = set()
            if special_var is not None:
                candidate_irs.update(
                    obj.ir
                    for obj in self.state.get_points_to(special_var)
                    if isinstance(obj, FunctionObject)
                )
            for owner in constructor_owners:
                if not isinstance(owner, ClassObject):
                    continue
                declared_ir = self.ir_translator.scope_manager.get_subscope(
                    owner.ir, special_name
                )
                if isinstance(declared_ir, IRFunc):
                    candidate_irs.add(declared_ir)
            return candidate_irs

        def bindings_for(candidate_irs):
            return [
                bind_arguments(
                    self.state,
                    scope,
                    context,
                    candidate_ir.args,
                    call,
                    leading_positional=1,
                )
                for candidate_ir in candidate_irs
            ]

        new_irs = special_irs("__new__")
        init_irs = special_irs("__init__")
        new_bindings = bindings_for(new_irs)
        init_bindings = bindings_for(init_irs)
        new_invalid = bool(new_bindings) and all(
            binding.definitely_invalid for binding in new_bindings
        )
        init_invalid = bool(init_bindings) and all(
            binding.definitely_invalid for binding in init_bindings
        )

        if new_invalid or (not has_custom_new and init_invalid):
            invalid_bindings = new_bindings if new_invalid else init_bindings
            special_name = "__new__" if new_invalid else "__init__"
            self._unknown_tracker.record(
                UnknownKind.INVALID_CALL,
                str(call.call_site),
                "; ".join(invalid_bindings[0].diagnostics)
                or f"invalid constructor {special_name} arguments",
                context=class_obj.ir.get_qualname(),
            )
            return True

        if has_custom_new and init_invalid:
            # A foreign __new__ result remains a successful class-call result,
            # but C/subclass results must not pass an invalid __init__.
            self._unknown_tracker.record(
                UnknownKind.INVALID_CALL,
                str(call.call_site),
                "; ".join(init_bindings[0].diagnostics)
                or "invalid constructor __init__ arguments",
                context=class_obj.ir.get_qualname(),
            )

        def init_may_return_none(func_ir):
            returns = []

            class ReturnCollector(ast.NodeVisitor):
                def visit_Return(self, node):
                    returns.append(node)

                def visit_FunctionDef(self, node):
                    if node is func_ir.get_ast():
                        self.generic_visit(node)

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_Lambda(self, node):
                    return None

                def visit_ClassDef(self, node):
                    return None

            ReturnCollector().visit(func_ir.get_ast())
            if not returns:
                return True
            last_stmt = func_ir.get_ast().body[-1] if func_ir.get_ast().body else None
            definitely_returns_value = (
                isinstance(last_stmt, ast.Return)
                and last_stmt.value is not None
                and all(
                    node.value is not None
                    and not (
                        isinstance(node.value, ast.Constant)
                        and node.value.value is None
                    )
                    for node in returns
                )
            )
            return not definitely_returns_value

        init_return_valid = not init_irs or any(
            init_may_return_none(func_ir) for func_ir in init_irs
        )
        if not init_return_valid:
            self._unknown_tracker.record(
                UnknownKind.INVALID_CALL,
                str(call.call_site),
                "__init__ returned a non-None value",
                context=class_obj.ir.get_qualname(),
            )

        instance_alloc = AllocSite(call.call_site.statement, AllocKind.INSTANCE)
        if self.context_selector:
            alloc_context = self.context_selector.select_alloc_context(context, instance_alloc, class_obj)
        else:
            alloc_context = context
        instance_obj = InstanceObject(alloc_context, instance_alloc, class_obj)

        contextual_args = tuple(
            (self.state.get_variable(scope, context, arg), is_starred)
            for arg, is_starred in call.iter_args()
        )
        contextual_kwargs = tuple(
            (name, self.state.get_variable(scope, context, arg))
            for name, arg in call.kwargs
        )

        instance_parent = cls_scope.parent
        assert instance_parent, f"{cls_scope} : {class_obj} has no parent"
        instance_ctx = self.context_selector.select_call_context(
            call.call_site,
            context,
            instance_obj,
            argument_source_signature(
                contextual_args,
                contextual_kwargs,
                receiver=instance_obj,
            ),
        )
        instance_scope = Scope.new(instance_obj, instance_parent.module, instance_ctx, class_obj.alloc_site.stmt, instance_parent)
        self.state.set_internal_scope(instance_obj, instance_scope)

        new_result_var = self.variable_factory.make_variable(f"$new_result@{call.call_site.short_id()}")
        ctx_new_result_var = self.state.get_variable(scope, context, new_result_var)

        # A fresh C instance is only the fallback for an unresolved/default
        # ``__new__``.  Pre-seeding it would pollute precise user-defined
        # ``__new__`` returns (which may be arbitrary objects).
        new_field = self.state.get_field(
            cls_scope, cls_scope.context, class_obj, attr("__new__")
        )
        if not has_custom_new and self.state.get_points_to(new_field).is_empty():
            self.handle_new_points_to(
                ctx_new_result_var, scope, PointsToSet.singleton(instance_obj)
            )

        # Load and call C.__new__(C, *args, **kwargs)
        cls_var = self.variable_factory.make_variable(f"$class@{call.call_site.short_id()}")
        ctx_cls_var = self.state.get_variable(scope, context, cls_var)
        self.handle_new_points_to(ctx_cls_var, scope, PointsToSet.singleton(class_obj))

        new_callee_var = self.variable_factory.make_variable(f"$new@{call.call_site.short_id()}")
        self.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=cls_var,
                field=attr("__new__"),
                target=new_callee_var,
            ),
        )
        new_args = (cls_var,) + call.args
        new_starred = (False,) + call.starred
        self.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=new_callee_var,
                args=new_args,
                kwargs=call.kwargs,
                target=new_result_var,
                call_site=call.call_site,
                starred=new_starred,
            ),
        )

        # Call __init__ only for instance-like results
        init_base_var = self.variable_factory.make_variable(f"$init_base@{call.call_site.short_id()}")
        ctx_init_base_var = self.state.get_variable(scope, context, init_base_var)

        def is_constructed_class_instance(obj):
            if not isinstance(obj, InstanceObject):
                return False
            if obj.class_obj == class_obj:
                return True
            if self.class_hierarchy is None:
                return False
            try:
                return class_obj in self.class_hierarchy.get_mro(obj.class_obj)
            except Exception:
                return False

        guard = GuardNode(
            lambda edge, pts: PointsToSet.from_objects(
                [obj for obj in pts if is_constructed_class_instance(obj)]
            )
        )
        self.state._add_points_flow_edge(
            PointerFlowEdge(NormalNode(ctx_new_result_var), guard, PointerFlowKind.NORMAL)
        )
        self.state._add_points_flow_edge(
            PointerFlowEdge(guard, NormalNode(ctx_init_base_var), PointerFlowKind.NORMAL)
        )

        if call.target:
            target_var = self.state.get_variable(scope, context, call.target)
            foreign_guard = GuardNode(
                lambda edge, pts: PointsToSet.from_objects(
                    [obj for obj in pts if not is_constructed_class_instance(obj)]
                )
            )
            self.state._add_points_flow_edge(
                PointerFlowEdge(
                    NormalNode(ctx_new_result_var),
                    foreign_guard,
                    PointerFlowKind.NORMAL,
                )
            )
            self.state._add_points_flow_edge(
                PointerFlowEdge(
                    foreign_guard,
                    NormalNode(target_var),
                    PointerFlowKind.NORMAL,
                )
            )
            if not init_invalid and init_return_valid:
                self.state._add_points_flow_edge(
                    PointerFlowEdge(
                        guard,
                        NormalNode(target_var),
                        PointerFlowKind.NORMAL,
                    )
                )

        init_callee_var = self.variable_factory.make_variable(f"$bound_init@{call.call_site.short_id()}")
        self.add_constraint(
            scope,
            context,
            LoadConstraint(
                base=init_base_var,
                field=attr("__init__"),
                target=init_callee_var,
            ),
        )
        self.add_constraint(
            scope,
            context,
            CallConstraint(
                init_callee_var,
                call.args,
                call.kwargs,
                None,
                call.call_site,
                call.starred,
            ),
        )

        return True
    
    def _handle_builtin_call(self, scope: 'Scope', context: 'AbstractContext', call: 'CallConstraint', builtin_obj: 'AbstractObject') -> bool:
        """Handle builtin call: use builtin API handler to generate constraints.
        
        This method delegates to the BuiltinAPIHandler which creates appropriate
        constraints and PFG edges for builtin operations.
        """
        if not self.builtin_manager:
            logger.debug("Cannot handle builtin call: no builtin manager")
            return False

        # Get the builtin API handler
        handler = self.builtin_manager.get_handler()
        if not handler:
            logger.debug("Builtin handler not initialized")
            return False

        builtin_name = (
            getattr(builtin_obj, "function_name", None)
            or getattr(builtin_obj, "builtin_name", None)
        )
        if builtin_name in {"exec", "eval"}:
            return self._handle_dynamic_code_builtin(
                scope, context, call, builtin_name
            )
        if builtin_name in {"getattr", "setattr", "delattr", "hasattr"} and len(call.args) >= 2:
            name_ctx = self.state.get_variable(
                scope, context, call.args[1]
            )
            self.state.dependencies.subscribe(
                ("builtin-attribute-name", call, builtin_obj),
                (name_ctx,),
                lambda: self._handle_builtin_call(
                    scope, context, call, builtin_obj
                ),
            )
        
        # Delegate to handler to generate constraints
        try:
            constraints = handler.handle_builtin_call(scope, context, call, builtin_obj)
            
            # Add all generated constraints to the solver
            for constraint in constraints:
                self.add_constraint(scope, context, constraint)
            
            return len(constraints) > 0
        finally:
            ...
        # except Exception as e:
        #     logger.warning(f"Error handling builtin call: {e}")
        #     return False

    def _handle_dynamic_code_builtin(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        builtin_name: str,
    ) -> bool:
        """Parse and lower constant-string ``exec``/``eval`` in place."""
        if not call.args:
            return False
        source_ctx = self.state.get_variable(scope, context, call.args[0])

        def expand() -> None:
            points = self.state.get_points_to(source_ctx)
            for code_obj in points:
                if not (
                    isinstance(code_obj, ConstantObject)
                    and isinstance(code_obj.value, str)
                ):
                    self.mark_semantic_incomplete(
                        variables=(
                            (self.state.get_variable(
                                scope, context, call.target
                            ),)
                            if call.target is not None else ()
                        ),
                        scopes=(scope,),
                        kind=UnknownKind.UNKNOWN_BUILTIN.value,
                        message=(
                            f"non-constant {builtin_name} source may modify "
                            "the current namespace"
                        ),
                    )
                    continue
                fact = (scope, context, call, code_obj.value)
                if fact in self._expanded_dynamic_code:
                    continue
                self._expanded_dynamic_code.add(fact)
                try:
                    if builtin_name == "eval":
                        expression = ast.parse(
                            code_obj.value, mode="eval"
                        ).body
                        if call.target is None:
                            continue
                        parsed_statements = [ast.Assign(
                            targets=[ast.Name(
                                id=call.target.name, ctx=ast.Store()
                            )],
                            value=expression,
                        )]
                    else:
                        parsed_statements = ast.parse(
                            code_obj.value, mode="exec"
                        ).body

                    from pyflow.analysis.alias.kcfa._pythonstan.analysis.transform.three_address import ThreeAddressTransformer
                    from pyflow.analysis.alias.kcfa._pythonstan.analysis.transform.ir import IRTransformer

                    token = stable_token((call.call_site, code_obj.value))
                    three_address = ThreeAddressTransformer()
                    three_address.reset(
                        v_tmpl=f"$dynamic_tmp_{token}_%d",
                        fn_tmpl=f"$dynamic_func_{token}_%d",
                        c_tmpl=f"$dynamic_const_{token}_%d",
                    )
                    lowered = three_address.visit_stmt_list(
                        parsed_statements
                    )
                    constant_statements = [
                        ast.Assign(
                            targets=[ast.Name(id=name, ctx=ast.Store())],
                            value=ast.Constant(value=value_),
                        )
                        for name, value_ in three_address.const_colle.dump()
                    ]
                    ir_transformer = IRTransformer(scope.stmt)
                    ir_transformer.process_stmts(
                        [*constant_statements, *lowered]
                    )
                    old_scope = self.ir_translator._current_scope
                    self.ir_translator._current_scope = scope.stmt
                    try:
                        for statement in ir_transformer.get_stmts():
                            for constraint in self.ir_translator._process_stmt(
                                statement
                            ):
                                self.add_constraint(
                                    scope, context, constraint
                                )
                    finally:
                        self.ir_translator._current_scope = old_scope
                except (SyntaxError, ValueError, TypeError) as error:
                    self.mark_semantic_incomplete(
                        scopes=(scope,),
                        kind=UnknownKind.TRANSLATION_ERROR.value,
                        message=(
                            f"cannot lower constant {builtin_name} source: "
                            f"{error}"
                        ),
                    )

        self.state.dependencies.subscribe(
            ("dynamic-code", scope, context, call, builtin_name),
            (source_ctx,),
            expand,
        )
        expand()
        return True


    def query(self) -> ISolverQuery:
        """Return a read-only query facade over the current fixed-point state."""
        return SolverQuery(
            self.state,
            self._stats,
            self._unknown_tracker,
            self._fixpoint_complete,
            self._frontend_complete,
            self._semantic_complete,
            self._incomplete_variables,
            self._incomplete_scopes,
            tuple(self._global_incomplete_reasons),
        )


class SolverQuery(ISolverQuery):
    """Expose points-to, alias, call-graph, and diagnostic solver results."""

    def __init__(
        self,
        state: 'PointerAnalysisState',
        stats: Dict[str, int],
        unknown_tracker: 'UnknownTracker',
        fixpoint_complete: bool,
        frontend_complete: bool,
        semantic_complete: bool,
        incomplete_variables,
        incomplete_scopes,
        global_incomplete_reasons,
    ):
        self._state = state
        self._stats = stats
        self._unknown_tracker = unknown_tracker
        self._fixpoint_complete = fixpoint_complete
        self._frontend_complete = frontend_complete
        self._semantic_complete = semantic_complete
        self._incomplete_variables = incomplete_variables
        self._incomplete_scopes = incomplete_scopes
        self._global_incomplete_reasons = global_incomplete_reasons
        self._complete = (
            fixpoint_complete and frontend_complete and semantic_complete
        )
    
    def points_to(self, var: 'Variable') -> 'PointsToSet':
        return self._state.get_points_to(var)
    
    def get_field(self, obj: 'AbstractObject', field: 'Field') -> 'PointsToSet':
        return self._state.raw_field_points_to(obj, field)
    
    def may_alias(self, v1: 'Variable', v2: 'Variable') -> bool:
        pts1 = self._state.get_points_to(v1)
        pts2 = self._state.get_points_to(v2)
        
        if not pts1.intersection(pts2).is_empty():
            return True
        # A negative answer from a partial fixed point is not sound.
        return not self._complete
    
    def call_graph(self) -> 'AbstractCallGraph':
        return self._state.call_graph
    
    def get_statistics(self) -> Dict[str, Any]:
        state_stats = self._state.get_statistics()
        unknown_stats = self._unknown_tracker.get_summary()
        return {
            **state_stats,
            **self._stats,
            "fixpoint_complete": self._fixpoint_complete,
            "frontend_complete": self._frontend_complete,
            "semantic_complete": self._semantic_complete,
            "complete": self._complete,
            **unknown_stats
        }
    
    def get_unknown_summary(self) -> Dict[str, int]:
        return self._unknown_tracker.get_summary()
    
    def get_unknown_details(self) -> List[Dict]:
        return self._unknown_tracker.get_detailed_report()

    def completeness_for(self, variables) -> Tuple[bool, Tuple[Dict, ...]]:
        """Return completeness for the dataflow region reaching variables."""
        reasons = list(self._global_incomplete_reasons)
        if not self._fixpoint_complete:
            reasons.append({
                "kind": UnknownKind.SOLVER_BUDGET.value,
                "message": "solver did not reach a fixed point",
            })
        if not self._frontend_complete:
            reasons.append({
                "kind": UnknownKind.TRANSLATION_ERROR.value,
                "message": "frontend translation was incomplete",
            })

        graph = self._state.pointer_flow_graph
        targets = set(variables)
        target_nodes = {NormalNode(target) for target in targets}

        def reaches_any_target(start_nodes) -> bool:
            queue = deque(start_nodes)
            seen = set(queue)
            while queue:
                node = queue.popleft()
                if node in target_nodes:
                    return True
                for edge in graph.succs.get(node, ()):
                    if edge.target not in seen:
                        seen.add(edge.target)
                        queue.append(edge.target)
            return False

        for incomplete_scope, scope_reasons in self._incomplete_scopes.items():
            starts = [
                node
                for node in graph.nodes
                if isinstance(node, NormalNode)
                and node.var.scope == incomplete_scope
            ]
            if (
                any(target.scope == incomplete_scope for target in targets)
                or reaches_any_target(starts)
            ):
                reasons.extend(scope_reasons)

        for source, source_reasons in self._incomplete_variables.items():
            if reaches_any_target((NormalNode(source),)):
                reasons.extend(source_reasons)

        unique = []
        for reason in reasons:
            if reason not in unique:
                unique.append(reason)
        return not unique, tuple(unique)
