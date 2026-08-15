"""Generator and coroutine call handling processor.

Detects generator functions (containing yield) and async functions,
returning GeneratorObject/CoroutineObject instead of normal call semantics.
"""

import logging
from typing import TYPE_CHECKING, Any, Optional, Set

from .processor import Processor
from ..points_to_set import PointsToSet
from ..constraints import (
    CallConstraint,
    StoreConstraint,
    CopyConstraint,
    argument_source_signature,
)
from ..object import (
    AllocKind,
    AllocSite,
    FunctionObject,
    MethodObject,
    GeneratorObject,
    CoroutineObject,
)
from ..context import Ctx, Scope
from ..variable import VariableKind
from ..heap_model import elem, attr
from ..unknown_tracker import UnknownKind
from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph import CallEdge, CallKind
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRFunc, IRYield

if TYPE_CHECKING:
    from ..solver import PointerSolver
    from ..constraints import Constraint
    from ..object import AbstractObject
    from ..context import AbstractContext

logger = logging.getLogger(__name__)

__all__ = ["GeneratorProcessor"]


class GeneratorProcessor(Processor):
    """Processor for generator and coroutine function calls.
    
    Detects when a generator or async function is called and returns
    the appropriate iterator/coroutine object instead of executing
    normal call semantics.
    """
    
    # Cache for generator function detection
    _generator_funcs: Set[IRFunc] = set()
    _checked_funcs: Set[IRFunc] = set()
    
    def __init__(self) -> None:
        self._generator_funcs = set()
        self._checked_funcs = set()
    
    def _is_generator_function(self, func_ir: IRFunc, solver: 'PointerSolver') -> bool:
        """Check if function is a generator (contains yield statements)."""
        if func_ir in self._checked_funcs:
            return func_ir in self._generator_funcs
        
        self._checked_funcs.add(func_ir)
        
        # Get function IR statements
        stmts = solver.state.scope_manager.get_ir(func_ir, 'ir')
        if stmts is None:
            return False
        
        # Check for yield statements
        for stmt in stmts:
            if isinstance(stmt, IRYield):
                self._generator_funcs.add(func_ir)
                return True
        
        return False
    
    def handle_call(
        self,
        solver: 'PointerSolver',
        target: 'Ctx[Any]',
        scope: 'Scope',
        constraint: 'Constraint',
        callee_obj: 'AbstractObject'
    ) -> bool:
        """Handle calls to generator/async functions.
        
        Returns True if this is a generator/async call and was handled,
        False to let other processors handle normal function calls.
        """
        if not isinstance(constraint, CallConstraint):
            return False
        
        call = constraint
        func_ir: Optional[IRFunc] = None
        func_obj: Optional[FunctionObject] = None
        
        # Extract function IR from different callable types
        if isinstance(callee_obj, (FunctionObject, MethodObject)):
            func_obj = callee_obj
            if isinstance(callee_obj.alloc_site.stmt, IRFunc):
                func_ir = callee_obj.alloc_site.stmt
        
        if func_ir is None:
            return False
        
        # Check for async function
        if func_ir.is_async:
            return self._handle_coroutine_call(
                solver, scope, scope.context, call, func_obj, func_ir
            )
        
        # Check for generator function
        if self._is_generator_function(func_ir, solver):
            return self._handle_generator_call(
                solver, scope, scope.context, call, func_obj, func_ir
            )
        
        return False
    
    def _handle_generator_call(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        func_obj: 'FunctionObject',
        func_ir: 'IRFunc'
    ) -> bool:
        """Handle calling a generator function.
        
        Creates a GeneratorObject and sets up the function body to yield
        values into the generator's elem() field.
        """
        logger.debug(f"Handling generator call: {call.call_site} -> {func_ir.name}")

        from .normal_call import NormalCallProcessor
        binding = NormalCallProcessor._validate_call(
            solver, scope, context, func_ir, call
        )
        if binding.definitely_invalid:
            return True
        
        # Create generator object allocation
        gen_alloc = AllocSite(stmt=call.stmt, kind=AllocKind.GENERATOR)
        gen_context = solver.context_selector.select_alloc_context(context, gen_alloc)
        gen_obj = GeneratorObject(
            context=gen_context,
            alloc_site=gen_alloc,
            func_obj=func_obj,
            container_scope=func_obj.container_scope
        )
        
        # Set up call context for the generator body
        contextual_args = tuple(
            (solver.state.get_variable(scope, context, arg), is_starred)
            for arg, is_starred in call.iter_args()
        )
        contextual_kwargs = tuple(
            (name, solver.state.get_variable(scope, context, arg))
            for name, arg in call.kwargs
        )
        call_context = solver.context_selector.select_call_context(
            call.call_site,
            context,
            None,
            argument_source_signature(contextual_args, contextual_kwargs),
        )
        definition_scope = func_obj.container_scope
        callee_scope = Scope.new(
            gen_obj,
            definition_scope.module,
            call_context,
            func_ir,
            definition_scope,
        )
        
        # Store generator object in heap
        solver.state._heap.set_obj(scope, context, gen_alloc, gen_obj)
        solver.state.obj_scope[gen_obj] = callee_scope
        
        # Set up $generator variable in callee scope for yield statements
        gen_var = solver.variable_factory.make_variable("$generator", VariableKind.TEMPORARY)
        ctx_gen_var = solver.state.get_variable(callee_scope, call_context, gen_var)
        solver.handle_new_points_to(ctx_gen_var, callee_scope, PointsToSet.singleton(gen_obj))
        
        # Translate function body constraints
        self._translate_function_body(solver, func_obj, func_ir, callee_scope, call_context)
        
        # Dispatch closure variables
        self._dispatch_closure(solver, func_obj, call_context, scope, callee_scope)
        
        # Match parameters (generator still receives arguments)
        self._match_parameters_simple(solver, func_obj, call, scope, callee_scope, context, call_context)
        
        # If there's a call target, point it to the generator object
        if call.target:
            target_var = solver.state.get_variable(scope, context, call.target)
            solver.handle_new_points_to(target_var, scope, PointsToSet.singleton(gen_obj))
        
        # Add call edge
        call_edge = CallEdge(
            kind=CallKind.FUNCTION,
            callsite=Ctx(context, scope, call.call_site),
            callee=callee_scope
        )
        solver.state.call_graph.add_edge(call_edge)
        
        return True
    
    def _handle_coroutine_call(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        func_obj: 'FunctionObject',
        func_ir: 'IRFunc'
    ) -> bool:
        """Handle calling an async function.
        
        Creates a CoroutineObject and sets up the function body to store
        its return value into the coroutine's $await_result field.
        """
        logger.debug(f"Handling coroutine call: {call.call_site} -> {func_ir.name}")

        from .normal_call import NormalCallProcessor
        binding = NormalCallProcessor._validate_call(
            solver, scope, context, func_ir, call
        )
        if binding.definitely_invalid:
            return True
        
        # Create coroutine object allocation
        coro_alloc = AllocSite(stmt=call.stmt, kind=AllocKind.COROUTINE)
        coro_context = solver.context_selector.select_alloc_context(context, coro_alloc)
        coro_obj = CoroutineObject(
            context=coro_context,
            alloc_site=coro_alloc,
            func_obj=func_obj,
            container_scope=func_obj.container_scope
        )
        
        # Set up call context for the coroutine body
        contextual_args = tuple(
            (solver.state.get_variable(scope, context, arg), is_starred)
            for arg, is_starred in call.iter_args()
        )
        contextual_kwargs = tuple(
            (name, solver.state.get_variable(scope, context, arg))
            for name, arg in call.kwargs
        )
        call_context = solver.context_selector.select_call_context(
            call.call_site,
            context,
            None,
            argument_source_signature(contextual_args, contextual_kwargs),
        )
        definition_scope = func_obj.container_scope
        callee_scope = Scope.new(
            coro_obj,
            definition_scope.module,
            call_context,
            func_ir,
            definition_scope,
        )
        
        # Store coroutine object in heap
        solver.state._heap.set_obj(scope, context, coro_alloc, coro_obj)
        solver.state.obj_scope[coro_obj] = callee_scope
        
        # Set up $coroutine variable in callee scope for return statements
        coro_var = solver.variable_factory.make_variable("$coroutine", VariableKind.TEMPORARY)
        ctx_coro_var = solver.state.get_variable(callee_scope, call_context, coro_var)
        solver.handle_new_points_to(ctx_coro_var, callee_scope, PointsToSet.singleton(coro_obj))
        
        # Translate function body constraints
        self._translate_function_body(solver, func_obj, func_ir, callee_scope, call_context)
        
        # Dispatch closure variables
        self._dispatch_closure(solver, func_obj, call_context, scope, callee_scope)
        
        # Match parameters
        self._match_parameters_simple(solver, func_obj, call, scope, callee_scope, context, call_context)
        
        # If there's a call target, point it to the coroutine object
        if call.target:
            target_var = solver.state.get_variable(scope, context, call.target)
            solver.handle_new_points_to(target_var, scope, PointsToSet.singleton(coro_obj))
        
        # Add call edge
        call_edge = CallEdge(
            kind=CallKind.FUNCTION,
            callsite=Ctx(context, scope, call.call_site),
            callee=callee_scope
        )
        solver.state.call_graph.add_edge(call_edge)
        
        return True
    
    def _translate_function_body(
        self,
        solver: 'PointerSolver',
        func_obj: 'FunctionObject',
        func_ir: 'IRFunc',
        callee_scope: 'Scope',
        call_context: 'AbstractContext'
    ) -> None:
        """Translate function body and add constraints."""
        old_scope = solver.ir_translator._current_scope
        solver.ir_translator._current_scope = func_ir
        
        try:
            body_constraints = solver.ir_translator.translate_function(func_ir)
        except Exception as e:
            solver.mark_semantic_incomplete()
            solver._unknown_tracker.record(
                UnknownKind.TRANSLATION_ERROR,
                func_ir.get_qualname(),
                f"Error translating generator/coroutine body: {e}",
            )
            logger.warning(f"Error translating generator/coroutine body: {e}")
            body_constraints = []
        finally:
            solver.ir_translator._current_scope = old_scope
        
        for constraint in body_constraints:
            solver.add_constraint(callee_scope, call_context, constraint)
    
    def _dispatch_closure(
        self,
        solver: 'PointerSolver',
        callee_obj: 'FunctionObject',
        call_context: 'AbstractContext',
        scope: 'Scope',
        callee_scope: 'Scope'
    ) -> None:
        """Dispatch closure variables to the callee."""
        state = solver.state
        
        cell_vars = state.get_cell_vars(callee_obj)
        for name, var in cell_vars.items():
            target_var = state.get_variable(
                callee_scope, call_context,
                solver.variable_factory.make_variable(name)
            )
            state._add_var_points_flow(var, target_var)
        
        nonlocal_vars = state.get_nonlocal_vars(callee_obj)
        for name, var in nonlocal_vars.items():
            state.set_variable(callee_scope, call_context, var.content, var)
        
        global_vars = state.get_global_vars(callee_obj)
        for name, var in global_vars.items():
            definition_module = callee_obj.container_scope.module
            var = state.get_variable(
                definition_module,
                definition_module.context,
                solver.variable_factory.make_variable(name, VariableKind.GLOBAL),
            )
            state.set_variable(callee_scope, call_context, var.content, var)
    
    def _match_parameters_simple(
        self,
        solver: 'PointerSolver',
        callee_obj: 'FunctionObject',
        call: 'CallConstraint',
        scope: 'Scope',
        callee_scope: 'Scope',
        context: 'AbstractContext',
        call_context: 'AbstractContext'
    ) -> None:
        """Match generator/coroutine parameters with normal call semantics."""
        from .normal_call import NormalCallProcessor

        NormalCallProcessor()._install_parameter_flows(
            solver,
            callee_obj,
            call,
            scope,
            callee_scope,
            context,
            call_context,
        )
