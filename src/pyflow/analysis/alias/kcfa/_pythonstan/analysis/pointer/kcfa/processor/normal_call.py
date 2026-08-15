"""Resolve ordinary Python calls encountered by the pointer solver."""

from abc import ABC, abstractmethod
import ast
import logging
from typing import TYPE_CHECKING, Any, Optional, Dict, Tuple

from .processor import Processor
from ..points_to_set import PointsToSet
from ..constraints import (
    CallConstraint,
    AllocConstraint,
    LoadConstraint,
    argument_source_signature,
)
from ..object import (
    AbstractObject,
    AllocKind,
    FunctionObject,
    MethodObject,
    ClassObject,
    InstanceObject,
    BuiltinObject,
    BuiltinFunctionObject,
    BuiltinMethodObject,
    BuiltinClassObject,
    BuiltinInstanceObject,
    AllocSite,
    TupleObject,
    DictObject,
)
from ..context import Ctx, Scope, AbstractContext
from ..variable import VariableKind, Variable
from ..unknown_tracker import UnknownKind
from ..heap_model import key, attr, elem, value
from ..call_binding import bind_arguments, mapping_key_sets
from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph import CallEdge, CallKind
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRFunc, IRAssign

if TYPE_CHECKING:
    from ..pointer_flow_graph import NormalNode
    from ..solver import PointerSolver
    from ..constraints import CallConstraint, Constraint

logger = logging.getLogger(__name__)

__all__ = ["NormalCallProcessor"]


class NormalCallProcessor(Processor):
    """Dispatch calls according to the abstract kind of the callee.

    Functions and bound methods receive argument-to-parameter flow; class calls
    create instances; builtin calls delegate to builtin summaries; and callable
    instances are resolved through their ``__call__`` attribute.
    """

    def __init__(self) -> None:
        self._default_alloc_sites: Dict[Tuple[IRFunc, str, int, AllocKind], AllocSite] = {}

    def handle_call(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', callee_obj: 'AbstractObject') -> bool:
        if isinstance(callee_obj, MethodObject):
            return self._handle_method_call(solver, scope, scope.context, constraint, callee_obj)
        if isinstance(callee_obj, FunctionObject):
            return self._handle_function_call(solver, scope, scope.context, constraint, callee_obj)
        if isinstance(callee_obj, (BuiltinObject, BuiltinFunctionObject, BuiltinMethodObject, BuiltinClassObject, BuiltinInstanceObject)) or callee_obj.kind == AllocKind.BUILTIN:
            return self._handle_builtin_call(solver, scope, scope.context, constraint, callee_obj)
        if isinstance(callee_obj, ClassObject):
            return self._handle_class_call(solver, scope, scope.context, constraint, callee_obj)
        if isinstance(callee_obj, InstanceObject):
            return self._handle_object_call(solver, scope, scope.context, constraint, callee_obj)
        return self._handle_object_call(solver, scope, scope.context, constraint, callee_obj)

    def _handle_builtin_call(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        builtin_obj: 'AbstractObject',
    ) -> bool:
        if solver._handle_builtin_call(scope, context, call, builtin_obj):
            return True
        builtin_name = getattr(builtin_obj, "name", None) or str(builtin_obj)
        solver._unknown_tracker.record(
            UnknownKind.UNKNOWN_BUILTIN,
            str(call.call_site),
            f"No precise summary for builtin call: {builtin_name}",
            context=str(context),
        )
        if call.target:
            unknown_obj = AbstractObject(
                context=context,
                alloc_site=AllocSite(call.call_site.statement, AllocKind.UNKNOWN),
            )
            target_var = solver.state.get_variable(scope, context, call.target)
            solver.handle_new_points_to(
                target_var, scope, PointsToSet.singleton(unknown_obj)
            )
        return True

    def _analyze_function_body(
        self,
        solver: 'PointerSolver',
        func_obj: 'FunctionObject',
        func_ir: IRFunc,
        callee_scope: 'Scope',
        call_context: 'AbstractContext',
        call: 'CallConstraint',
    ) -> bool:
        analysis_key = (func_obj, call_context)
        if analysis_key in solver._analyzed_functions:
            return False
        solver._analyzed_functions.add(analysis_key)

        old_scope = solver.ir_translator._current_scope
        solver.ir_translator._current_scope = func_ir
        try:
            body_constraints = solver.ir_translator.translate_function(func_ir)
        except Exception as e:
            solver.mark_semantic_incomplete()
            solver._unknown_tracker.record(
                UnknownKind.TRANSLATION_ERROR,
                str(call.call_site),
                f"Error translating function body: {str(e)}",
                context=func_ir.get_name(),
            )
            if solver.config.verbose:
                logger.warning(
                    f"[UNKNOWN] Translation error for {func_ir.get_name()}: {e}"
                )
            body_constraints = []
        finally:
            solver.ir_translator._current_scope = old_scope

        for constraint in body_constraints:
            solver.add_constraint(callee_scope, call_context, constraint)
        return bool(body_constraints)

    @staticmethod
    def _validate_call(solver, scope, context, func_ir, call, *, leading_positional=0):
        binding = bind_arguments(
            solver.state,
            scope,
            context,
            func_ir.args,
            call,
            leading_positional=leading_positional,
        )
        if binding.definitely_invalid:
            solver._unknown_tracker.record(
                UnknownKind.INVALID_CALL,
                str(call.call_site),
                "; ".join(binding.diagnostics) or "definitely invalid call",
                context=func_ir.get_qualname(),
            )
        return binding

    def _handle_class_call(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        class_obj: 'ClassObject',
    ) -> bool:
        return solver._handle_class_instantiation(scope, context, call, class_obj)

    def _handle_object_call(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        callee_obj: 'AbstractObject',
    ) -> bool:
        if call.callee.name.startswith("$call@"):
            return False
        call_var = solver.variable_factory.make_variable(f"$call@{call.call_site.short_id()}")
        ctx_call_var = solver.state.get_variable(scope, context, call_var)
        call_field = solver.state.get_field(scope, context, callee_obj, attr("__call__"))
        solver.state._add_var_points_flow(call_field, ctx_call_var)
        solver.add_constraint(
            scope,
            context,
            CallConstraint(
                callee=call_var,
                args=call.args,
                kwargs=call.kwargs,
                target=call.target,
                call_site=call.call_site,
                starred=call.starred,
            ),
        )
        return True

    def _make_default_alloc_site(
        self,
        func_ir: IRFunc,
        param_name: str,
        default_index: int,
        kind: AllocKind,
        value: Any,
    ) -> AllocSite:
        key = (func_ir, param_name, default_index, kind)
        alloc_site = self._default_alloc_sites.get(key)
        if alloc_site is None:
            default_var_name = self._default_var_name(func_ir, param_name, default_index, kind)
            const_assign = IRAssign(
                ast.Assign(
                    targets=[ast.Name(id=default_var_name, ctx=ast.Store())],
                    value=ast.Constant(value=value),
                )
            )
            alloc_site = AllocSite.from_ir_node(const_assign, kind)
            self._default_alloc_sites[key] = alloc_site
        return alloc_site

    @staticmethod
    def _default_var_name(func_ir: IRFunc, param_name: str, default_index: int, kind: AllocKind) -> str:
        return f"$default_{kind.value}_{id(func_ir)}_{param_name}_{default_index}"

    def _materialize_default(
        self,
        solver: 'PointerSolver',
        func_ir: IRFunc,
        def_scope: Scope,
        def_context: AbstractContext,
        param_name: str,
        default_index: int,
        default_expr: ast.expr,
    ) -> 'Ctx[Variable]':
        default_var_name = self._default_var_name(func_ir, param_name, default_index, AllocKind.CONSTANT)
        default_var = solver.variable_factory.make_variable(default_var_name)
        default_ctx_var = solver.state.get_variable(def_scope, def_context, default_var)

        if isinstance(default_expr, ast.Constant):
            alloc_site = self._make_default_alloc_site(
                func_ir=func_ir,
                param_name=param_name,
                default_index=default_index,
                kind=AllocKind.CONSTANT,
                value=default_expr.value,
            )
            solver.add_constraint(
                def_scope,
                def_context,
                AllocConstraint(target=default_var, alloc_site=alloc_site),
            )
            return default_ctx_var

        if isinstance(default_expr, ast.Name):
            source_var = solver.variable_factory.make_variable(default_expr.id)
            source_ctx = solver.state.get_variable(def_scope, def_context, source_var)
            solver.state._add_var_points_flow(source_ctx, default_ctx_var)
            return default_ctx_var

        if isinstance(default_expr, ast.Attribute) and isinstance(default_expr.value, ast.Name):
            base_var = solver.variable_factory.make_variable(default_expr.value.id)
            solver.add_constraint(
                def_scope,
                def_context,
                LoadConstraint(
                    base=base_var,
                    field=attr(default_expr.attr),
                    target=default_var,
                ),
            )
            return default_ctx_var

        alloc_site = self._make_default_alloc_site(
            func_ir=func_ir,
            param_name=param_name,
            default_index=default_index,
            kind=AllocKind.UNKNOWN,
            value=None,
        )
        solver.add_constraint(
            def_scope,
            def_context,
            AllocConstraint(target=default_var, alloc_site=alloc_site),
        )
        return default_ctx_var
    
    def _handle_method_call(self, solver: 'PointerSolver', scope: 'Scope', context: 'AbstractContext', call: 'CallConstraint', method_obj: 'MethodObject') -> bool:
        # logger.info(f"Handling method call: {call.call_site} -> {method_obj.alloc_site.stmt.get_qualname()}")
        
        if not isinstance(method_obj, MethodObject):
            logger.info(f"is not method object, {type(method_obj)} got!")
            return False
                
        func_ir: IRFunc = method_obj.alloc_site.stmt
        assert isinstance(func_ir, IRFunc), f"MethodObject alloc site stmt should be IRFunc, {type(func_ir)} got!"
        if func_ir.is_static_method:
            return self._handle_function_call(solver, scope, context, call, method_obj)
        
        if func_ir.is_class_method:
            holder_obj = method_obj.class_obj
        else:
            holder_obj = method_obj.instance_obj
            if holder_obj is None:
                return self._handle_function_call(solver, scope, context, call, method_obj)
        
        if not holder_obj:
            logger.info(f"No holder got in {method_obj}")
            return False
        
        self_var = solver.state.get_variable(
            scope,
            context,
            solver.variable_factory.make_variable(f"$self@{call.call_site.short_id()}")
        )
        solver.handle_new_points_to(self_var, scope, PointsToSet.singleton(holder_obj))

        binding = self._validate_call(
            solver, scope, context, func_ir, call, leading_positional=1
        )
        if binding.definitely_invalid:
            return True

        args = tuple(
            (solver.state.get_variable(scope, context, arg), is_starred)
            for arg, is_starred in call.iter_args()
        )
        kwargs = tuple(
            (name, solver.state.get_variable(scope, context, arg))
            for name, arg in call.kwargs
        )

        call_context = solver.context_selector.select_call_context(
            call.call_site,
            context,
            holder_obj,
            params=argument_source_signature(args, kwargs, receiver=holder_obj),
        )
        
        logger.debug(f"Handling function call: {call.call_site} -> {method_obj.alloc_site.stmt}")
        
        definition_scope = method_obj.container_scope
        callee_scope = Scope.new(
            method_obj,
            definition_scope.module,
            call_context,
            func_ir,
            definition_scope,
        )
        assert holder_obj

        if func_ir.is_class_method:
            call_kind = CallKind.CLASS
        else:
            call_kind = CallKind.INSTANCE
        call_edge = CallEdge(kind=call_kind, callsite=Ctx(context, scope, call.call_site), callee=callee_scope)
        # if self.state.call_graph.has_edge(edge):
        #     return False

        self._dispatch_closure(solver, method_obj, call_context, scope, callee_scope)

        self._install_parameter_flows(
            solver,
            method_obj,
            call,
            scope,
            callee_scope,
            context,
            call_context,
            self_var,
        )

        self._analyze_function_body(
            solver, method_obj, func_ir, callee_scope, call_context, call
        )

        if call.target:
            ret = solver.variable_factory.make_variable("$return", VariableKind.TEMPORARY)
            ret_var = solver.state.get_variable(callee_scope, call_context, ret)
            target_var = solver.state.get_variable(scope, context, call.target)
            solver.state._add_var_points_flow(ret_var, target_var)

        solver.state.call_graph.add_edge(call_edge)
        logger.debug(f"Adding call edge: {call_edge}")
        
        # Debug monitoring: record call edge creation
        if solver._debug_monitor and solver._debug_monitor.enabled:
            caller_name = str(scope.stmt.get_qualname() if hasattr(scope.stmt, 'get_qualname') else scope.stmt)
            callee_name = str(call_edge.callee.stmt.get_qualname() if hasattr(call_edge.callee.stmt, 'get_qualname') else call_edge.callee.stmt)
            solver._debug_monitor.record_call_edge_created(
                caller=caller_name,
                callee=callee_name,
                call_site=str(call.call_site),
                callee_type="method"
            )

        return True
    
    def _handle_function_call(self, solver: 'PointerSolver', scope: 'Scope', context: 'AbstractContext', call: 'CallConstraint', func_obj: 'AbstractObject') -> bool:
        """Handle function call: analyze function body with parameter bindings.
            1. Selects calling context
            2. Translates function body to constraints
            3. Generates parameter passing constraints
            4. Connects return value to caller
            5. Adds call edge to call graph
        """
        # logger.info(f"Handling function call: {call.call_site} -> {func_obj.alloc_site.stmt}")
        
        if not isinstance(func_obj, FunctionObject):
            logger.info(f"is not function object, {type(func_obj)} got!")
            return False
        
        func_ir: IRFunc = func_obj.alloc_site.stmt
        binding = self._validate_call(solver, scope, context, func_ir, call)
        if binding.definitely_invalid:
            return True

        args = tuple(
            (solver.state.get_variable(scope, context, arg), is_starred)
            for arg, is_starred in call.iter_args()
        )
        kwargs = tuple(
            (name, solver.state.get_variable(scope, context, arg))
            for name, arg in call.kwargs
        )
        
        call_context = solver.context_selector.select_call_context(
            call.call_site,
            context,
            None,  # No receiver ffor regular functions
            params=argument_source_signature(args, kwargs),
        )
        
        logger.debug(f"Handling function call: {call.call_site} -> {func_obj.alloc_site.stmt}")
        
        definition_scope = func_obj.container_scope
        callee_scope = Scope.new(
            func_obj,
            definition_scope.module,
            call_context,
            func_ir,
            definition_scope,
        )
        call_kind = CallKind.STATIC if func_ir.is_static_method else CallKind.FUNCTION
        call_edge = CallEdge(kind=call_kind, callsite=Ctx(context, scope, call.call_site), callee=callee_scope)
        # if self.state.call_graph.has_edge(edge):
        #     return False

        self._dispatch_closure(solver, func_obj, call_context, scope, callee_scope)
        
        self._install_parameter_flows(
            solver,
            func_obj,
            call,
            scope,
            callee_scope,
            context,
            call_context,
        )

        self._analyze_function_body(
            solver, func_obj, func_ir, callee_scope, call_context, call
        )
        
        if call.target:
            ret = solver.variable_factory.make_variable("$return", VariableKind.TEMPORARY)
            ret_var = solver.state.get_variable(callee_scope, call_context, ret)
            target_var = solver.state.get_variable(scope, context, call.target)
            if solver.config.verbose:
                logger.info(f"[RETURN] Connecting return: {ret_var} -> {target_var}")
                logger.info(f"  Callee scope: {callee_scope.stmt.get_qualname() if hasattr(callee_scope.stmt, 'get_qualname') else callee_scope.stmt}, context={call_context}")
                logger.info(f"  Caller scope (input): {scope.stmt.get_qualname() if hasattr(scope.stmt, 'get_qualname') else scope.stmt}, context={context}")
                logger.info(f"  Target var scope (result): {target_var.scope.stmt.get_qualname() if hasattr(target_var.scope.stmt, 'get_qualname') else target_var.scope.stmt}, context={target_var.context}")
                logger.info(f"  Call target var: {call.target.name}, kind={call.target.kind}")
            solver.state._add_var_points_flow(ret_var, target_var)
        
        solver.state.call_graph.add_edge(call_edge)
        logger.debug(f"Adding call edge: {call_edge}")
        
        # Debug monitoring: record call edge creation
        if solver._debug_monitor and solver._debug_monitor.enabled:
            caller_name = str(scope.stmt.get_qualname() if hasattr(scope.stmt, 'get_qualname') else scope.stmt)
            callee_name = str(call_edge.callee.stmt.get_qualname() if hasattr(call_edge.callee.stmt, 'get_qualname') else call_edge.callee.stmt)
            solver._debug_monitor.record_call_edge_created(
                caller=caller_name,
                callee=callee_name,
                call_site=str(call.call_site),
                callee_type="function"
            )

        return True

    def _dispatch_closure(self, solver: 'PointerSolver', callee_obj: 'FunctionObject', call_context: 'AbstractContext', scope: 'Scope', callee_scope: 'Scope'):
        """Dispatch closure: dispatch closure variables to the callee."""
        state = solver.state

        cell_vars = state.get_cell_vars(callee_obj)
        for name, var in cell_vars.items():
            target_var = state.get_variable(callee_scope, call_context, solver.variable_factory.make_variable(name))
            state._add_var_points_flow(var, target_var)
        
        nonlocal_vars = state.get_nonlocal_vars(callee_obj)
        for name, var in nonlocal_vars.items():
            if var is not None:
                state.set_variable(callee_scope, call_context, var.content, var)
    
        global_vars = state.get_global_vars(callee_obj)
        for name, var in global_vars.items():
            definition_module = callee_obj.container_scope.module
            captured = state.get_variable(
                definition_module,
                definition_module.context,
                solver.variable_factory.make_variable(name, VariableKind.GLOBAL),
            )
            state.set_variable(callee_scope, call_context, captured.content, captured)

    @staticmethod
    def _known_star_lengths(state, source_var: 'Ctx[Variable]'):
        lengths = set()
        points_to = state.get_points_to(source_var)
        if points_to.is_empty():
            return None
        for obj in points_to:
            stmt = getattr(obj.alloc_site, "stmt", None)
            rval = stmt.get_rval() if hasattr(stmt, "get_rval") else None
            if not isinstance(rval, (ast.List, ast.Tuple)):
                return None
            lengths.add(len(rval.elts))
        return lengths

    @staticmethod
    def _mapping_key_sets(state, source_var: 'Ctx[Variable]'):
        return mapping_key_sets(state, source_var)

    def _expanded_argument(
        self,
        solver: 'PointerSolver',
        scope: 'Scope',
        context: 'AbstractContext',
        call: 'CallConstraint',
        source: 'Variable',
        label: str,
        fields,
    ) -> 'Ctx[Variable]':
        target = solver.variable_factory.make_variable(
            f"$expand@{call.call_site.short_id()}@{label}",
            VariableKind.TEMPORARY,
        )
        for field in fields:
            solver.add_constraint(
                scope,
                context,
                LoadConstraint(base=source, field=field, target=target),
            )
        return solver.state.get_variable(scope, context, target)
    
    def _install_parameter_flows(self,
                          solver: 'PointerSolver',
                          callee_obj: 'FunctionObject',
                          call: 'CallConstraint',
                          scope: 'Scope',
                          callee_scope: 'Scope',
                          context: 'AbstractContext',
                          call_context: 'AbstractContext',                          
                          self_var: Optional['Ctx[Variable]'] = None
                          ) -> None:
        """Install flows for a call already accepted by ``bind_arguments``."""
        state = solver.state

        method_obj = callee_obj
        func_ir: IRFunc = method_obj.alloc_site.stmt
        func_name = func_ir.get_qualname()
                
        if hasattr(func_ir, 'args'):
            func_args = func_ir.args
            positional_params = []
            if hasattr(func_args, 'posonlyargs') and func_args.posonlyargs:
                positional_params.extend(func_args.posonlyargs)
            if func_args.args:
                positional_params.extend(func_args.args)

            arg_vars = []
            if self_var is not None:
                arg_vars.append(self_var)
            starred_sources = []
            raw_args = tuple(call.iter_args())
            for source_index, (source, is_starred) in enumerate(raw_args):
                source_var = state.get_variable(scope, context, source)
                if not is_starred:
                    arg_vars.append(source_var)
                    continue
                known_lengths = self._known_star_lengths(state, source_var)
                future_plain = sum(
                    not later_starred
                    for _, later_starred in raw_args[source_index + 1:]
                )
                positional_room = max(
                    0,
                    len(positional_params) - len(arg_vars) - future_plain,
                )
                if known_lengths is None:
                    expansion_count = positional_room
                else:
                    expansion_count = max(known_lengths, default=0)
                    if not func_args.vararg:
                        expansion_count = min(expansion_count, positional_room)
                for item_index in range(expansion_count):
                    fields = [key(item_index)]
                    if known_lengths is None:
                        fields.append(elem())
                    arg_vars.append(self._expanded_argument(
                        solver,
                        scope,
                        context,
                        call,
                        source,
                        f"star{source_index}:{item_index}",
                        fields,
                    ))
                starred_sources.append((source_index, source, known_lengths))

            kwarg_vars = {}
            dstar_sources = []
            for keyword_index, (name, source) in enumerate(call.kwargs):
                source_var = state.get_variable(scope, context, source)
                if name is None:
                    dstar_sources.append((keyword_index, source, source_var))
                else:
                    kwarg_vars[name] = source_var

            keyword_parameters = [*positional_params, *func_args.kwonlyargs]
            maybe_dstar_params = set()
            for param in keyword_parameters:
                param_name = param.arg
                if param_name in kwarg_vars or not dstar_sources:
                    continue
                source_key_sets = [
                    self._mapping_key_sets(state, source_var)
                    for _, _, source_var in dstar_sources
                ]
                if source_key_sets and all(
                    options is not None
                    and all(param_name not in keys for keys in options)
                    for options in source_key_sets
                ):
                    # Exact literal mappings prove this name absent.  Do not
                    # manufacture a binding merely because ``**`` syntax exists.
                    continue
                possible_presence = any(
                    options is None
                    or any(param_name in keys for keys in options)
                    for options in source_key_sets
                )
                guaranteed_presence = any(
                    options is not None
                    and bool(options)
                    and all(param_name in keys for keys in options)
                    for options in source_key_sets
                )
                if possible_presence and not guaranteed_presence:
                    maybe_dstar_params.add(param_name)
                target = solver.variable_factory.make_variable(
                    f"$dstar@{call.call_site.short_id()}@{param_name}",
                    VariableKind.TEMPORARY,
                )
                for _, source, source_var in dstar_sources:
                    fields = [key(param_name)]
                    key_sets = self._mapping_key_sets(state, source_var)
                    if key_sets is None:
                        fields.extend((elem(), value()))
                    for field in fields:
                        solver.add_constraint(
                            scope,
                            context,
                            LoadConstraint(base=source, field=field, target=target),
                        )
                kwarg_vars[param_name] = state.get_variable(scope, context, target)

            positional_defaults = {}
            if func_args.defaults:
                first_default_idx = len(positional_params) - len(func_args.defaults)
                for idx, default_expr in enumerate(func_args.defaults):
                    param = positional_params[first_default_idx + idx]
                    positional_defaults[param.arg] = (default_expr, first_default_idx + idx)

            # Track which parameters have been bound
            arg_index = 0
            consumed_kwargs = set()  # Track which keyword arguments have been matched
            
            # 1. Handle positional-only parameters (Python 3.8+)
            # These can ONLY be filled by positional arguments, not keywords
            if hasattr(func_args, 'posonlyargs') and func_args.posonlyargs:
                for param in func_args.posonlyargs:
                    param_name = param.arg
                    param_var = state.get_variable(
                        callee_scope, 
                        call_context, 
                        solver.variable_factory.make_variable(param_name)
                    )
                    
                    if arg_index < len(arg_vars):
                        # Bind positional argument to parameter
                        state._add_var_points_flow(arg_vars[arg_index], param_var)
                        arg_index += 1
                    else:
                        default_entry = positional_defaults.get(param_name)
                        if default_entry is not None:
                            default_expr, default_idx = default_entry
                            def_scope = callee_obj.container_scope
                            def_context = def_scope.context
                            default_ctx = self._materialize_default(
                                solver=solver,
                                func_ir=func_ir,
                                def_scope=def_scope,
                                def_context=def_context,
                                param_name=param_name,
                                default_index=default_idx,
                                default_expr=default_expr,
                            )
                            state._add_var_points_flow(default_ctx, param_var)
                        else:
                            solver._unknown_tracker.record(
                                UnknownKind.MISSING_ARGUMENT,
                                str(call.call_site),
                                f"Required positional-only parameter {param_name} not provided",
                                context=func_name
                            )
            
            # 2. Handle regular positional/keyword parameters
            # These can be filled by either positional OR keyword arguments
            if func_args.args:
                for param_idx, param in enumerate(func_args.args):
                    param_name = param.arg
                    param_var = state.get_variable(
                        callee_scope, 
                        call_context, 
                        solver.variable_factory.make_variable(param_name)
                    )
                    
                    # Python assigns positional arguments first.  A simultaneous
                    # keyword was rejected by the pre-call binder as a duplicate.
                    if arg_index < len(arg_vars):
                        # Bind positional argument to parameter
                        state._add_var_points_flow(arg_vars[arg_index], param_var)
                        arg_index += 1
                    elif param_name in kwarg_vars:
                        # Bind keyword argument to parameter
                        state._add_var_points_flow(kwarg_vars[param_name], param_var)
                        consumed_kwargs.add(param_name)
                        if param_name in maybe_dstar_params:
                            default_entry = positional_defaults.get(param_name)
                            if default_entry is not None:
                                default_expr, default_idx = default_entry
                                default_ctx = self._materialize_default(
                                    solver=solver,
                                    func_ir=func_ir,
                                    def_scope=callee_obj.container_scope,
                                    def_context=callee_obj.container_scope.context,
                                    param_name=param_name,
                                    default_index=default_idx,
                                    default_expr=default_expr,
                                )
                                state._add_var_points_flow(default_ctx, param_var)
                    else:
                        default_entry = positional_defaults.get(param_name)
                        if default_entry is not None:
                            default_expr, default_idx = default_entry
                            def_scope = callee_obj.container_scope
                            def_context = def_scope.context
                            default_ctx = self._materialize_default(
                                solver=solver,
                                func_ir=func_ir,
                                def_scope=def_scope,
                                def_context=def_context,
                                param_name=param_name,
                                default_index=default_idx,
                                default_expr=default_expr,
                            )
                            state._add_var_points_flow(default_ctx, param_var)
                        else:
                            # Missing required parameter - this is an error in real Python
                            solver._unknown_tracker.record(
                                UnknownKind.MISSING_ARGUMENT,
                                str(call.call_site),
                                f"Required parameter {param_name} not provided",
                                context=func_name
                            )
            
            # 3. Handle *args (vararg) - collects remaining positional arguments
            if func_args.vararg:
                vararg_name = func_args.vararg.arg
                vararg_var = state.get_variable(
                    callee_scope,
                    call_context,
                    solver.variable_factory.make_variable(vararg_name)
                )
                
                # Create a tuple object to hold the varargs
                vararg_alloc = AllocSite(f"{call.call_site}:*args", AllocKind.TUPLE)
                vararg_tuple_obj = TupleObject(call_context, vararg_alloc)
                
                # Add the tuple to the vararg parameter
                solver.handle_new_points_to(vararg_var, callee_scope, PointsToSet.singleton(vararg_tuple_obj))
                
                # All remaining positional arguments go into *args
                for i in range(arg_index, len(arg_vars)):
                    # Store each remaining argument as an element of the tuple
                    field = key(i - arg_index)
                    element_var = state.get_field(callee_scope, call_context, vararg_tuple_obj, field)
                    state._add_var_points_flow(arg_vars[i], element_var)
                for source_index, source, known_lengths in starred_sources:
                    if known_lengths is not None:
                        continue
                    expanded = self._expanded_argument(
                        solver,
                        scope,
                        context,
                        call,
                        source,
                        f"star{source_index}:rest",
                        (elem(),),
                    )
                    generic_element = state.get_field(
                        callee_scope,
                        call_context,
                        vararg_tuple_obj,
                        elem(),
                    )
                    state._add_var_points_flow(expanded, generic_element)
            elif arg_index < len(arg_vars):
                # Too many positional arguments and no *args to catch them
                solver._unknown_tracker.record(
                    UnknownKind.MISSING_ARGUMENT,
                    str(call.call_site),
                    f"Too many positional arguments: expected {arg_index}, got {len(arg_vars)}",
                    context=func_name
                )
            
            # 4. Handle keyword-only parameters
            # These MUST be provided by keyword arguments (or use defaults)
            if func_args.kwonlyargs:
                for kw_idx, param in enumerate(func_args.kwonlyargs):
                    param_name = param.arg
                    param_var = state.get_variable(
                        callee_scope,
                        call_context,
                        solver.variable_factory.make_variable(param_name)
                    )
                    
                    # Check if provided as keyword argument
                    if param_name in kwarg_vars:
                        # Bind keyword argument to parameter
                        state._add_var_points_flow(kwarg_vars[param_name], param_var)
                        consumed_kwargs.add(param_name)
                        if (
                            param_name in maybe_dstar_params
                            and func_args.kw_defaults
                            and kw_idx < len(func_args.kw_defaults)
                            and func_args.kw_defaults[kw_idx] is not None
                        ):
                            default_ctx = self._materialize_default(
                                solver=solver,
                                func_ir=func_ir,
                                def_scope=callee_obj.container_scope,
                                def_context=callee_obj.container_scope.context,
                                param_name=param_name,
                                default_index=kw_idx,
                                default_expr=func_args.kw_defaults[kw_idx],
                            )
                            state._add_var_points_flow(default_ctx, param_var)
                    elif func_args.kw_defaults and kw_idx < len(func_args.kw_defaults):
                        # Check if there's a default value
                        kw_default = func_args.kw_defaults[kw_idx]
                        if kw_default is not None:
                            # Has a default value
                            def_scope = callee_obj.container_scope
                            def_context = def_scope.context
                            default_ctx = self._materialize_default(
                                solver=solver,
                                func_ir=func_ir,
                                def_scope=def_scope,
                                def_context=def_context,
                                param_name=param_name,
                                default_index=kw_idx,
                                default_expr=kw_default,
                            )
                            state._add_var_points_flow(default_ctx, param_var)
                        else:
                            # Missing required keyword-only parameter
                            solver._unknown_tracker.record(
                                UnknownKind.MISSING_ARGUMENT,
                                str(call.call_site),
                                f"Required keyword-only parameter {param_name} not provided",
                                context=func_name
                            )
                    else:
                        # Missing required keyword-only parameter with no default
                        solver._unknown_tracker.record(
                            UnknownKind.MISSING_ARGUMENT,
                            str(call.call_site),
                            f"Required keyword-only parameter {param_name} not provided",
                            context=func_name
                        )
            
            # 5. Handle **kwargs (kwarg) - collects remaining keyword arguments
            remaining_kwargs = {k: v for k, v in kwarg_vars.items() if k not in consumed_kwargs}
            
            if func_args.kwarg:
                kwarg_name = func_args.kwarg.arg
                kwarg_var = state.get_variable(
                    callee_scope,
                    call_context,
                    solver.variable_factory.make_variable(kwarg_name)
                )
                
                # Create a dict object to hold the kwargs
                kwarg_alloc = AllocSite(f"{call.call_site}:**kwargs", AllocKind.DICT)
                kwarg_dict_obj = DictObject(call_context, kwarg_alloc)
                
                # Add the dict to the kwarg parameter
                solver.handle_new_points_to(kwarg_var, callee_scope, PointsToSet.singleton(kwarg_dict_obj))
                
                # Store all remaining keyword arguments into the **kwargs dict
                for kw_name, kw_var in remaining_kwargs.items():
                    # Use the keyword name as the dict key (field)
                    field = key(kw_name)
                    dict_value_var = state.get_field(callee_scope, call_context, kwarg_dict_obj, field)
                    state._add_var_points_flow(kw_var, dict_value_var)
                for keyword_index, source, source_var in dstar_sources:
                    fields = (elem(), value())
                    expanded = self._expanded_argument(
                        solver,
                        scope,
                        context,
                        call,
                        source,
                        f"dstar{keyword_index}:rest",
                        fields,
                    )
                    dict_value_var = state.get_field(
                        callee_scope,
                        call_context,
                        kwarg_dict_obj,
                        elem(),
                    )
                    state._add_var_points_flow(expanded, dict_value_var)
            elif remaining_kwargs:
                # Unexpected keyword arguments and no **kwargs to catch them
                extra_kw_names = ', '.join(remaining_kwargs.keys())
                solver._unknown_tracker.record(
                    UnknownKind.MISSING_ARGUMENT,
                    str(call.call_site),
                    f"Unexpected keyword arguments: {extra_kw_names}",
                    context=func_name
                )
