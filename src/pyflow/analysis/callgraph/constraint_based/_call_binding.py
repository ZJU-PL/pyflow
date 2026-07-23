"""Call argument, receiver, closure, and dependency binding."""

from __future__ import annotations

import ast
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .model import (
    AbstractValue,
    CLASS_KIND,
    COROUTINE_KIND,
    ContextKey,
    GENERATOR_KIND,
    INSTANCE_KIND,
    ScopeInfo,
    UNKNOWN_VALUE,
    instance_class_name,
    make_class,
    make_instance,
    parse_instance_name,
    make_coroutine,
    make_generator,
)


class _CallBindingMixin:
    """Shared call invocation, argument binding, and dependency support."""

    def _super_receiver_value(
        self,
        start_class: str,
        obj_values: Set[AbstractValue],
    ) -> Set[AbstractValue]:
        out: Set[AbstractValue] = set()
        for obj_value in obj_values:
            if obj_value.kind == INSTANCE_KIND:
                obj_class = instance_class_name(obj_value)
                order = self._class_lookup_order(obj_class)
                if start_class not in order:
                    continue
                idx = order.index(start_class)
                if idx + 1 >= len(order):
                    continue
                next_base = order[idx + 1]
                out.add(
                    make_instance(next_base, parse_instance_name(obj_value.name)[1])
                )
            elif obj_value.kind == CLASS_KIND:
                order = self._class_lookup_order(obj_value.name)
                if start_class not in order:
                    continue
                idx = order.index(start_class)
                if idx + 1 >= len(order):
                    continue
                out.add(make_class(order[idx + 1]))
        if out:
            return out

        order = self._class_lookup_order(start_class)
        if len(order) >= 2:
            return {make_class(order[1])}
        return set()

    def _invoke_callback_values(
        self,
        caller_scope: ScopeInfo,
        caller_context: ContextKey,
        callback_values: Set[AbstractValue],
        call_node: ast.Call,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        if not callback_values:
            return set()
        synthetic_call = ast.copy_location(
            ast.Call(func=call_node.func, args=[], keywords=[]),
            call_node,
        )
        return self._invoke_targets(
            caller_scope=caller_scope,
            caller_context=caller_context,
            target_values=callback_values,
            call_node=synthetic_call,
            env=env,
            callees=callees,
            input_changed_scope_contexts=input_changed_scope_contexts,
        )

    def _add_call_dependency(
        self,
        callee_name: str,
        callee_context: ContextKey,
        caller_scope_key: Tuple[str, ContextKey],
    ) -> None:
        if callee_name not in self.scopes:
            return
        self.call_dependents[(callee_name, callee_context)].add(caller_scope_key)

    def _suspended_value(
        self,
        kind: str,
        callee_name: str,
        callee_context: ContextKey,
    ) -> AbstractValue:
        key = (callee_name, callee_context, kind)
        cached = self._suspended_value_cache.get(key)
        if cached is not None:
            return cached
        context_label = self._context_label(callee_context)
        token = f"{callee_name}[{context_label}]"
        if kind == COROUTINE_KIND:
            value = make_coroutine(token)
            self.coroutine_sources[value.name] = (callee_name, callee_context)
        else:
            value = make_generator(token)
            self.generator_sources[value.name] = (callee_name, callee_context)
        self._suspended_value_cache[key] = value
        return value

    def _materialize_suspended_values(
        self,
        values: Iterable[AbstractValue],
        *,
        expected_kind: str,
        caller_scope: ScopeInfo,
        caller_context: ContextKey,
        env: Dict[str, Set[AbstractValue]],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        out: Set[AbstractValue] = set()
        source_map = (
            self.coroutine_sources
            if expected_kind == COROUTINE_KIND
            else self.generator_sources
        )
        caller_scope_key = (
            caller_scope.name,
            self._normalize_context_for_scope(caller_scope.name, caller_context),
        )
        for value in values:
            if value.kind != expected_kind:
                continue
            source = source_map.get(value.name)
            if source is None:
                continue
            callee_name, callee_context = source
            if (callee_name, callee_context) not in self._analyzed_scope_contexts:
                input_changed_scope_contexts.add((callee_name, callee_context))
            self._add_call_dependency(callee_name, callee_context, caller_scope_key)
            out.update(self.scope_returns[(callee_name, callee_context)])
            self._apply_callee_side_effects(callee_name, callee_context, env)
        return out

    def _invoke_with_implicit_receiver(
        self,
        callee_name: str,
        receiver_values: Set[AbstractValue],
        caller_scope: ScopeInfo,
        caller_context: ContextKey,
        call_node: ast.Call,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
        arg_values: List[Set[AbstractValue]],
        kwarg_values: Mapping[str, Set[AbstractValue]],
        star_arg_values: Optional[List[Set[AbstractValue]]] = None,
        dynamic_kwarg_values: Optional[Set[AbstractValue]] = None,
    ) -> Set[AbstractValue]:
        out: Set[AbstractValue] = set()
        caller_scope_key = (
            caller_scope.name,
            self._normalize_context_for_scope(caller_scope.name, caller_context),
        )
        callees.add(callee_name)
        self._record_callsite_callee(
            caller_scope,
            caller_context,
            call_node,
            callee_name,
        )
        if callee_name not in self.scopes:
            out.add(UNKNOWN_VALUE)
            return out
        callee_context = self._normalize_context_for_scope(
            callee_name,
            self._derive_callee_context(caller_scope.name, caller_context, call_node),
        )
        changed = self._bind_call_arguments(
            callee_name,
            callee_context,
            [receiver_values] + arg_values,
            kwarg_values,
            star_arg_values=star_arg_values,
            dynamic_kwarg_values=dynamic_kwarg_values,
        )
        if changed:
            input_changed_scope_contexts.add((callee_name, callee_context))
        if (callee_name, callee_context) not in self._analyzed_scope_contexts:
            input_changed_scope_contexts.add((callee_name, callee_context))
        function_info = self.functions.get(callee_name)
        if function_info and function_info.is_async:
            out.add(self._suspended_value(COROUTINE_KIND, callee_name, callee_context))
            return out
        if function_info and function_info.is_generator:
            out.add(self._suspended_value(GENERATOR_KIND, callee_name, callee_context))
            return out
        self._add_call_dependency(callee_name, callee_context, caller_scope_key)
        out.update(self.scope_returns[(callee_name, callee_context)])
        self._apply_callee_side_effects(callee_name, callee_context, env)
        return out

    def _invoke_named_function(
        self,
        callee_name: str,
        caller_scope: ScopeInfo,
        caller_context: ContextKey,
        call_node: ast.Call,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
        arg_values: List[Set[AbstractValue]],
        kwarg_values: Mapping[str, Set[AbstractValue]],
        star_arg_values: Optional[List[Set[AbstractValue]]] = None,
        dynamic_kwarg_values: Optional[Set[AbstractValue]] = None,
    ) -> Set[AbstractValue]:
        out: Set[AbstractValue] = set()
        caller_scope_key = (
            caller_scope.name,
            self._normalize_context_for_scope(caller_scope.name, caller_context),
        )
        callees.add(callee_name)
        self._record_callsite_callee(
            caller_scope,
            caller_context,
            call_node,
            callee_name,
        )
        raw_context = self._derive_callee_context(
            caller_scope.name, caller_context, call_node
        )
        callee_context = self._normalize_context_for_scope(callee_name, raw_context)
        callee_function_info = self.functions.get(callee_name)
        if callee_function_info and callee_function_info.closure_vars:
            active_inputs = self.scope_inputs.get((callee_name, callee_context), {})
            has_bound_closure = any(
                active_inputs.get(name) for name in callee_function_info.closure_vars
            )
            if not has_bound_closure:
                candidate_contexts = []
                for (
                    scope_key,
                    context_key,
                ), context_inputs in self.scope_inputs.items():
                    if scope_key != callee_name:
                        continue
                    if any(
                        context_inputs.get(name)
                        for name in callee_function_info.closure_vars
                    ):
                        candidate_contexts.append(context_key)
                if candidate_contexts:
                    fallback_context = sorted(candidate_contexts)[0]
                    if fallback_context != callee_context:
                        self.solver_stats.closure_context_fallbacks += 1
                    callee_context = fallback_context
        changed = self._bind_call_arguments(
            callee_name,
            callee_context,
            arg_values,
            kwarg_values,
            star_arg_values=star_arg_values,
            dynamic_kwarg_values=dynamic_kwarg_values,
        )
        if changed:
            input_changed_scope_contexts.add((callee_name, callee_context))
        if (callee_name, callee_context) not in self._analyzed_scope_contexts:
            input_changed_scope_contexts.add((callee_name, callee_context))
        if callee_function_info and callee_function_info.is_async:
            out.add(self._suspended_value(COROUTINE_KIND, callee_name, callee_context))
            return out
        if callee_function_info and callee_function_info.is_generator:
            out.add(self._suspended_value(GENERATOR_KIND, callee_name, callee_context))
            return out
        self._add_call_dependency(callee_name, callee_context, caller_scope_key)
        out.update(self.scope_returns[(callee_name, callee_context)])
        self._apply_callee_side_effects(callee_name, callee_context, env)
        return out

    def _filter_values_by_annotation(
        self,
        module_name: str,
        annotation: Optional[ast.AST],
        values: Set[AbstractValue],
    ) -> Set[AbstractValue]:
        if not self.options.use_type_hints or annotation is None or not values:
            return set(values)
        type_values = self._resolve_type_expression_values(annotation, module_name)
        if not type_values:
            return set(values)
        return {
            value for value in values if self._matches_type_values(value, type_values)
        }

    def _refine_values_with_type_filter(
        self,
        values: Set[AbstractValue],
        type_values: Set[AbstractValue],
        positive: bool,
    ) -> Set[AbstractValue]:
        if not type_values:
            return set(values)
        refined: Set[AbstractValue] = set()
        for value in values:
            matches = self._matches_type_values(value, type_values)
            if positive and matches:
                refined.add(value)
            if not positive and not matches:
                refined.add(value)
        return refined

    def _apply_callee_side_effects(
        self,
        callee_scope_name: str,
        callee_context: ContextKey,
        env: Dict[str, Set[AbstractValue]],
    ) -> bool:
        """Apply recorded global/nonlocal side effects of a callee into caller env."""
        changed = False
        scope_key = (callee_scope_name, callee_context)
        for name, values in self.scope_global_writes.get(scope_key, {}).items():
            if not values:
                # Deletes do not kill may-values in the flow-insensitive model.
                continue
            current = env.setdefault(name, set())
            changed = self._merge_value_set(current, set(values)) or changed
        for name, values in self.scope_nonlocal_writes.get(scope_key, {}).items():
            if not values:
                # Deletes do not kill may-values in the flow-insensitive model.
                continue
            current = env.setdefault(name, set())
            changed = self._merge_value_set(current, set(values)) or changed
        return changed

    def _propagate_nonlocal_write(
        self,
        name: str,
        values: Set[AbstractValue],
    ) -> None:
        """Push nonlocal writes into sibling closure bindings sharing the same cell."""
        if not values or self._active_scope_context is None:
            return

        origin = self.closure_origins.get(self._active_scope_context)
        if origin is None:
            return

        for dependent_scope_key in self.closure_dependents.get(
            (origin[0], origin[1], name), set()
        ):
            dependent_scope = self.scopes[dependent_scope_key[0]]
            param_inputs = self.scope_inputs.setdefault(
                dependent_scope_key,
                {
                    **{param: set() for param in dependent_scope.params},
                    **{
                        closure_var: set()
                        for closure_var in dependent_scope.closure_vars
                    },
                },
            )
            current = param_inputs.setdefault(name, set())
            if self._merge_value_set(current, set(values), preserve_callables=True):
                if self._active_changed_closure_scopes is not None:
                    self._active_changed_closure_scopes.add(dependent_scope_key)

    def _bind_call_arguments(
        self,
        callee_scope_name: str,
        callee_context: ContextKey,
        arg_values: List[Set[AbstractValue]],
        kwarg_values: Mapping[str, Set[AbstractValue]],
        star_arg_values: Optional[List[Set[AbstractValue]]] = None,
        dynamic_kwarg_values: Optional[Set[AbstractValue]] = None,
    ) -> bool:
        """Merge actual argument abstractions into callee parameter input sets."""
        scope = self.scopes[callee_scope_name]
        changed = False
        scope_key = (
            callee_scope_name,
            self._normalize_context_for_scope(callee_scope_name, callee_context),
        )
        param_inputs = self.scope_inputs.setdefault(
            scope_key, {param: set() for param in scope.params}
        )
        positional_params = [*scope.posonly_params, *scope.pos_or_kw_params]
        pos_or_kw_set = set(scope.pos_or_kw_params)
        kwonly_set = set(scope.kwonly_params)
        posonly_set = set(scope.posonly_params)

        for index, values in enumerate(arg_values):
            if index < len(positional_params):
                param_name = positional_params[index]
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(param_name), values
                )
                current = param_inputs.setdefault(param_name, set())
                changed = (
                    self._merge_value_set(
                        current, filtered_values, preserve_callables=True
                    )
                    or changed
                )
            elif scope.vararg:
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(scope.vararg), values
                )
                current = param_inputs.setdefault(scope.vararg, set())
                changed = (
                    self._merge_value_set(
                        current, filtered_values, preserve_callables=True
                    )
                    or changed
                )

        if star_arg_values:
            pooled_star_values: Set[AbstractValue] = set()
            for values in star_arg_values:
                pooled_star_values.update(values)
            if pooled_star_values:
                for index in range(len(arg_values), len(positional_params)):
                    param_name = positional_params[index]
                    filtered_values = self._filter_values_by_annotation(
                        scope.module,
                        scope.param_annotations.get(param_name),
                        pooled_star_values,
                    )
                    current = param_inputs.setdefault(param_name, set())
                    changed = (
                        self._merge_value_set(
                            current, filtered_values, preserve_callables=True
                        )
                        or changed
                    )
                if scope.vararg:
                    filtered_values = self._filter_values_by_annotation(
                        scope.module,
                        scope.param_annotations.get(scope.vararg),
                        pooled_star_values,
                    )
                    current = param_inputs.setdefault(scope.vararg, set())
                    changed = (
                        self._merge_value_set(
                            current, filtered_values, preserve_callables=True
                        )
                        or changed
                    )

        for kw_name, kw_values in kwarg_values.items():
            if kw_name in pos_or_kw_set or kw_name in kwonly_set:
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(kw_name), kw_values
                )
                current = param_inputs.setdefault(kw_name, set())
                changed = (
                    self._merge_value_set(
                        current, filtered_values, preserve_callables=True
                    )
                    or changed
                )
            elif kw_name in posonly_set:
                # Positional-only parameters cannot be bound by keyword.
                continue
            elif scope.kwarg:
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(scope.kwarg), kw_values
                )
                current = param_inputs.setdefault(scope.kwarg, set())
                changed = (
                    self._merge_value_set(
                        current, filtered_values, preserve_callables=True
                    )
                    or changed
                )

        if dynamic_kwarg_values and scope.kwarg:
            filtered_values = self._filter_values_by_annotation(
                scope.module,
                scope.param_annotations.get(scope.kwarg),
                dynamic_kwarg_values,
            )
            current = param_inputs.setdefault(scope.kwarg, set())
            changed = (
                self._merge_value_set(current, filtered_values, preserve_callables=True)
                or changed
            )

        return changed

    def _bind_closure_values(
        self,
        callee_scope_name: str,
        callee_context: ContextKey,
        captured: Mapping[str, Set[AbstractValue]],
        closure_origin: Optional[Tuple[str, ContextKey]] = None,
    ) -> bool:
        """Merge captured outer-scope values into closure-variable inputs."""
        scope = self.scopes[callee_scope_name]
        scope_key = (
            callee_scope_name,
            self._normalize_context_for_scope(callee_scope_name, callee_context),
        )
        param_inputs = self.scope_inputs.setdefault(
            scope_key,
            {
                **{param: set() for param in scope.params},
                **{name: set() for name in scope.closure_vars},
            },
        )
        if closure_origin is not None:
            origin_scope, origin_context = closure_origin
            normalized_origin = (
                origin_scope,
                self._normalize_context_for_scope(origin_scope, origin_context),
            )
            self.closure_origins[scope_key] = normalized_origin
            for name in scope.closure_vars:
                self.closure_dependents[
                    (normalized_origin[0], normalized_origin[1], name)
                ].add(scope_key)
        changed = False
        for name, values in captured.items():
            if name not in scope.closure_vars:
                continue
            current = param_inputs.setdefault(name, set())
            changed = (
                self._merge_value_set(current, set(values), preserve_callables=True)
                or changed
            )
        return changed
