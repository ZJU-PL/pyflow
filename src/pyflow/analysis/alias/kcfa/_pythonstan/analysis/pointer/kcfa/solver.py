"""Constraint-based pointer analysis solver.

This module implements the core solver for pointer analysis using
constraint-based propagation.
"""

import ast
import logging
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
from .context import Ctx, Scope
from .class_hierarchy import ClassHierarchyManager
from .builtin_api_handler import BuiltinSummaryManager
from .unknown_tracker import UnknownTracker, UnknownKind
from .object import *
from .solver_interface import ISolverQuery
from .pointer_flow_graph import PointerFlowGraph, PointerFlowEdge, PointerFlowNode, NormalNode, GuardNode, SelectorNode, PointerFlowKind
from .debug_monitor import DebugMonitor
from .processor import Processor
from .events import PointerEvent, PointerEventKind

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
        self._debug_monitor = debug_monitor
        self.state.class_hierarchy = class_hierarchy
        
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
        self._complete = False
        self._analyzed_functions = set()
        self._stats: Dict[str, int] = {
            "iterations": 0,
            "constraints_applied": 0
        }
        self._modules = set()
    
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
        self._complete = self.state._worklist.empty() and not self.state._static_constraints
        if not self._complete:
            self._unknown_tracker.record(
                UnknownKind.SOLVER_BUDGET,
                "<solver>",
                f"fixpoint not reached after {self.config.max_iterations} iterations",
            )
        self._record_empty_callees()
        logger.info(f"Processed {len(self._modules)} modules: {self._modules}")
        logger.info(f"Call Constraints: {len(self.state.constraints.get_by_type(CallConstraint))}")
        abs_nodes = set([node.stmt.get_qualname() for node in self.state._call_graph.get_nodes()])
        logger.info(f"Call graph: {self.state._call_graph} node: {len(self.state._call_graph.get_nodes())} edge: {self.state._call_graph.get_number_of_edges()}")
        logger.info(f"    absolute nodes: { len(abs_nodes) } absolute edges: { self.state._call_graph.num_plain_edges() }")
        logger.info(f"Pointer flow graph: {self.state._pointer_flow_graph} node: {len(self.state._pointer_flow_graph.get_nodes())} edge: {len(self.state._pointer_flow_graph.get_edges())}")                
        if self._complete:
            logger.info(f"Converged after {self._iteration} iterations")
        else:
            logger.warning(f"Stopped after solver budget at {self._iteration} iterations")

    def _record_empty_callees(self) -> None:
        """Make unresolved calls fail-visible after the points-to fixpoint."""
        seen = set()
        for scope, constraint in self.state.constraints.all():
            if not isinstance(constraint, CallConstraint):
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
        
    def __iter__(self):
        self._reset()
        return self
    
    def __next__(self) -> 'PointerAnalysisState':
        if ((not self.state._worklist.empty()) or self.state._static_constraints) and self._iteration < self.config.max_iterations:
            self._iteration += 1
            if self.state._static_constraints:
                scope, ctx, constraint = self.state._static_constraints.pop()
                return self._apply_static(scope, ctx, constraint)
            elif not self.state._worklist.empty():
                scope, node, pts = self.state._worklist.pop()
                return self._apply_dynamic(scope, node, pts)
            
            
        raise StopIteration
    
    def _apply_dynamic(self, scope: 'Scope', node: 'PointerFlowNode', pts: 'PointsToSet') -> 'PointerAnalysisState':
        if isinstance(node, NormalNode):
            assert isinstance(node.var, Ctx), f"node.var must be a Ctx, but got {type(node.var)}"
        diff = pts - self.state.get_points_to(node)
        if not diff.is_empty():
            self.state.set_points_to(node, diff)
            
            # apply the constraints associated with the variable
            if isinstance(node, NormalNode):
                self.processor.handle_pts(self, node.var, scope, diff)
                
                self.state.set_points_to(node.var, diff)
                for constraint_scope, constraint in self.state.constraints.iter_scoped_by_variable(node.var):
                    self._apply_constraint(constraint_scope, node.var, constraint, diff)
            
            for succ, succ_pts in self.state.pointer_flow_graph.propagate(node, diff):
                succ_scope = succ.var.scope if isinstance(succ, NormalNode) else None
                self.state._worklist.add((succ_scope, succ, succ_pts))
        return self.state

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
                obj_id = f"{c.alloc_site.kind.value}:{id(obj)}"
                location = str(c.alloc_site)
                self._debug_monitor.record_object_allocated(
                    obj_id=obj_id,
                    obj_kind=c.alloc_site.kind.value,
                    location=location,
                    target_var=str(c.target)
                )
            self.state.obj_scope[obj] = scope
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

        obj = MethodObject(context, c.alloc_site, scope, c.alloc_site.stmt, scope.obj, None)
        
        # process cell vars into the closure
        cell_vars = {}
        cell_var_names = ir_func.get_cell_vars()
        if not cell_var_names:
            cell_var_names = self._infer_free_vars(ir_func)
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

        obj = FunctionObject(context, c.alloc_site, scope, c.alloc_site.stmt)
        
        # process cell vars into the closure
        cell_vars = {}
        cell_var_names = ir_func.get_cell_vars()
        if not cell_var_names:
            cell_var_names = self._infer_free_vars(ir_func)
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

        obj = ClassObject(context, c.alloc_site, scope, c.alloc_site.stmt)
        
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
            ctx_field = self.state.get_field(scope, context, obj, attr(inner_var.name))
            ctx_inner_var = self.state.get_variable(ctx_scope, cls_context, inner_var)
            self.state._add_var_points_flow(ctx_inner_var, ctx_field)
            if self.config.debug_inheritance:
                logger.info(f"[CLASS] Storing field {obj.alloc_site.stmt.name}.{inner_var.name}: {ctx_inner_var} -> {ctx_field}")

        return obj

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
            
            # Default behavior: use field access for classes, instances, etc.
            field_access = self.state.get_field(scope, context, base_obj, c.field)
            self.state._add_var_points_flow(field_access, target_var)
    
    def _apply_store(self, scope: 'Scope', variable: 'Ctx', c: 'StoreConstraint', pts: 'PointsToSet'):
        """Apply store constraint: base.field = source or base[index] = source."""
        context = scope.context
        source_var = self.state.get_variable(scope, context, c.source)

        for base_obj in pts:
            self.state.record_semantic_event(
                PointerEvent(PointerEventKind.STORE, scope, context, c, base_obj)
            )
            field_access = self.state.get_field(scope, context, base_obj, c.field)
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
            elif callee_obj.kind == AllocKind.FUNCTION:
                changed = self._handle_function_call(scope, context, c, callee_obj)
            elif callee_obj.kind == AllocKind.CLASS:
                changed = self._handle_class_instantiation(scope, context, c, callee_obj)
            elif callee_obj.kind == AllocKind.METHOD:
                changed = self._handle_method_call(scope, context, c, callee_obj)
            elif callee_obj.kind == AllocKind.BOUND_METHOD:
                changed = self._handle_bound_method_call(c, callee_obj)
            elif callee_obj.kind == AllocKind.BUILTIN:
                changed = self._handle_builtin_call(scope, context, c, callee_obj)
            # TODO add the __callable__ magic method
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
        if call.target is None:
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

    def _apply_configured_return_effects(
        self,
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        callee_obj: 'AbstractObject',
    ) -> None:
        if call.target is None:
            return
        access_path = self._configured_access_path(callee_obj)
        if access_path is None:
            return
        target = self.state.get_variable(scope, context, call.target)
        for effect in self.config.native_effects or ():
            if not fnmatchcase(access_path, effect.get("access_path", "")):
                continue
            kind = effect.get("kind")
            if kind == "return_argument":
                for argument in self._native_effect_variables(call, effect):
                    source = self.state.get_variable(scope, context, argument)
                    self.state._add_var_points_flow(source, target)
            elif kind == "return_receiver":
                receiver = self._configured_receiver(callee_obj, context)
                if receiver is not None:
                    self.state._worklist.add(
                        (scope, NormalNode(target), PointsToSet.singleton(receiver))
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
        selected = []
        keyword_map = dict(call.kwargs)
        for selector in effect.get("arguments", ()):
            if selector == "*":
                selected.extend(call.args)
                selected.extend(keyword_map.values())
            elif isinstance(selector, int) and 0 <= selector < len(call.args):
                selected.append(call.args[selector])
            elif isinstance(selector, str) and selector in keyword_map:
                selected.append(keyword_map[selector])
        return tuple(selected)
 
    def _handle_class_instantiation(self, scope: 'Scope', context: 'AbstractContext', call: 'CallConstraint', class_obj: 'AbstractObject') -> bool:
        """Handle class instantiation: call __new__, then __init__ conditionally."""
        # logger.info(f"Handling class instantiation: {call.call_site} -> {class_obj.alloc_site.stmt}")

        instance_alloc = AllocSite(call.call_site.statement, AllocKind.INSTANCE)
        if self.context_selector:
            alloc_context = self.context_selector.select_alloc_context(context, instance_alloc, class_obj)
        else:
            alloc_context = context
        instance_obj = InstanceObject(alloc_context, instance_alloc, class_obj)

        cls_scope = self.state.get_internal_scope(class_obj)
        params = (
            [("$self", instance_obj)] +
            [self.state.get_variable(scope, context, arg) for arg in call.args] +
            [(k, self.state.get_variable(scope, context, arg)) for k, arg in call.kwargs]
        )

        instance_parent = cls_scope.parent
        assert instance_parent, f"{cls_scope} : {class_obj} has no parent"
        instance_ctx = self.context_selector.select_call_context(call.call_site, context, instance_obj, frozenset(params))
        instance_scope = Scope.new(instance_obj, instance_parent.module, instance_ctx, class_obj.alloc_site.stmt, instance_parent)
        self.state.set_internal_scope(instance_obj, instance_scope)

        # Seed __new__ result with a fresh instance as a conservative default
        new_result_var = self.variable_factory.make_variable(f"$new_result@{call.call_site.short_id()}")
        ctx_new_result_var = self.state.get_variable(scope, context, new_result_var)
        self.handle_new_points_to(ctx_new_result_var, scope, PointsToSet.singleton(instance_obj))

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
        self.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=new_callee_var,
                args=new_args,
                kwargs=call.kwargs,
                target=new_result_var,
                call_site=call.call_site,
            ),
        )

        # Flow __new__ result to call target
        if call.target:
            target_var = self.state.get_variable(scope, context, call.target)
            self.state._add_var_points_flow(ctx_new_result_var, target_var)

        # Call __init__ only for instance-like results
        init_base_var = self.variable_factory.make_variable(f"$init_base@{call.call_site.short_id()}")
        ctx_init_base_var = self.state.get_variable(scope, context, init_base_var)

        guard = GuardNode(
            lambda edge, pts: PointsToSet.from_objects(
                [obj for obj in pts if isinstance(obj, InstanceObject)]
            )
        )
        self.state._add_points_flow_edge(
            PointerFlowEdge(NormalNode(ctx_new_result_var), guard, PointerFlowKind.NORMAL)
        )
        self.state._add_points_flow_edge(
            PointerFlowEdge(guard, NormalNode(ctx_init_base_var), PointerFlowKind.NORMAL)
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
            CallConstraint(init_callee_var, call.args, call.kwargs, None, call.call_site),
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


    def query(self) -> ISolverQuery:
        """Return a read-only query facade over the current fixed-point state."""
        return SolverQuery(
            self.state, self._stats, self._unknown_tracker, self._complete
        )


class SolverQuery(ISolverQuery):
    """Expose points-to, alias, call-graph, and diagnostic solver results."""

    def __init__(
        self,
        state: 'PointerAnalysisState',
        stats: Dict[str, int],
        unknown_tracker: 'UnknownTracker',
        complete: bool,
    ):
        self._state = state
        self._stats = stats
        self._unknown_tracker = unknown_tracker
        self._complete = complete
    
    def points_to(self, var: 'Variable') -> 'PointsToSet':
        return self._state.get_points_to(var)
    
    def get_field(self, obj: 'AbstractObject', field: 'Field') -> 'PointsToSet':
        return self._state.get_field(obj, field)
    
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
            "complete": self._complete,
            **unknown_stats
        }
    
    def get_unknown_summary(self) -> Dict[str, int]:
        return self._unknown_tracker.get_summary()
    
    def get_unknown_details(self) -> List[Dict]:
        return self._unknown_tracker.get_detailed_report()
