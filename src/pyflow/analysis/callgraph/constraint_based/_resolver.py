"""Target invocation, argument binding, and attribute/MRO resolution."""

from __future__ import annotations

import ast
import warnings
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .model import (
    AbstractValue,
    BOUND_CLASS_METHOD_KIND,
    BOUND_METHOD_KIND,
    CLASS_KIND,
    CONTAINER_KIND,
    ContextKey,
    FUNC_KIND,
    INSTANCE_KIND,
    MODULE_KIND,
    NONE_KIND,
    NONE_VALUE,
    PARTIAL_KIND,
    STRING_KIND,
    ScopeInfo,
    UNKNOWN_KIND,
    UNKNOWN_VALUE,
    instance_class_name,
    make_bound_class_method,
    make_bound_method,
    make_class,
    make_container,
    make_func,
    make_instance,
    make_module,
    make_partial,
    parse_bound_class_method,
    parse_bound_method,
    parse_instance_name,
    parse_partial,
    make_string,
)


class _ResolverMixin:
    """Resolves call targets, binds arguments, and walks MRO for attribute lookup."""

    _registry_like_names = {"register", "route", "callback", "on"}

    def _resolve_string_expression_values(
        self,
        expr: ast.AST,
        module_name: str,
        env: Optional[Mapping[str, Set[AbstractValue]]] = None,
    ) -> Set[str]:
        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, str):
                return {expr.value}
            if isinstance(expr.value, int):
                return {f"#{expr.value}"}
            return set()
        if isinstance(expr, ast.Name) and expr.id == "None":
            return {"None"}
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self._resolve_string_expression_values(expr.left, module_name, env)
            right = self._resolve_string_expression_values(expr.right, module_name, env)
            return {f"{lhs}{rhs}" for lhs in left for rhs in right}
        if isinstance(expr, ast.JoinedStr):
            parts: List[List[str]] = []
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append([value.value])
                    continue
                inner = self._resolve_string_expression_values(value, module_name, env)
                if not inner:
                    return set()
                parts.append(sorted(inner))
            if not parts:
                return {""}
            out = {""}
            for chunk in parts:
                out = {f"{prefix}{piece}" for prefix in out for piece in chunk}
            return out
        if isinstance(expr, ast.FormattedValue):
            return self._resolve_string_expression_values(expr.value, module_name, env)
        lookup_env = env or self.module_bindings.get(module_name, {})
        resolved = self._eval_expr_static(expr, lookup_env)
        strings = {value.name for value in resolved if value.kind == STRING_KIND}
        if strings or lookup_env is self.module_bindings.get(module_name, {}):
            return strings
        fallback = self._eval_expr_static(expr, self.module_bindings.get(module_name, {}))
        return {value.name for value in fallback if value.kind == STRING_KIND}

    def _expr_qualname(self, expr: ast.AST) -> Optional[str]:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            base = self._expr_qualname(expr.value)
            if base:
                return f"{base}.{expr.attr}"
        return None

    def _annotation_union_items(self, expr: ast.AST) -> List[ast.AST]:
        if isinstance(expr, ast.Tuple):
            return list(expr.elts)
        return [expr]

    def _resolve_type_expression_values(
        self,
        expr: Optional[ast.AST],
        module_name: str,
        env: Optional[Mapping[str, Set[AbstractValue]]] = None,
    ) -> Set[AbstractValue]:
        if expr is None:
            return set()
        if isinstance(expr, ast.Constant):
            if expr.value is None:
                return {NONE_VALUE}
            if isinstance(expr.value, str):
                try:
                    parsed = ast.parse(expr.value, mode="eval")
                except SyntaxError:
                    return set()
                return self._resolve_type_expression_values(
                    parsed.body, module_name, env=env
                )

        if isinstance(expr, ast.Name) and expr.id == "None":
            return {NONE_VALUE}

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):
            out: Set[AbstractValue] = set()
            out.update(self._resolve_type_expression_values(expr.left, module_name, env))
            out.update(
                self._resolve_type_expression_values(expr.right, module_name, env)
            )
            return out

        if isinstance(expr, ast.Tuple):
            out: Set[AbstractValue] = set()
            for item in expr.elts:
                out.update(self._resolve_type_expression_values(item, module_name, env))
            return out

        if isinstance(expr, ast.Subscript):
            base_name = self._expr_qualname(expr.value)
            if base_name in {"Optional", "typing.Optional"}:
                out = {NONE_VALUE}
                for item in self._annotation_union_items(expr.slice):
                    out.update(
                        self._resolve_type_expression_values(item, module_name, env)
                    )
                return out
            if base_name in {
                "Union",
                "typing.Union",
                "Annotated",
                "typing.Annotated",
                "Type",
                "typing.Type",
                "type",
            }:
                out: Set[AbstractValue] = set()
                for item in self._annotation_union_items(expr.slice):
                    out.update(
                        self._resolve_type_expression_values(item, module_name, env)
                    )
                return out
            if base_name in {"Literal", "typing.Literal"}:
                out: Set[AbstractValue] = set()
                for item in self._annotation_union_items(expr.slice):
                    if isinstance(item, ast.Constant):
                        if item.value is None:
                            out.add(NONE_VALUE)
                        elif isinstance(item.value, str):
                            out.add(make_string(item.value))
                        elif isinstance(item.value, int):
                            out.add(make_string(f"#{item.value}"))
                return out

        lookup_env = env or self.module_bindings.get(module_name, {})
        resolved = self._eval_expr_static(expr, lookup_env)
        if resolved:
            return resolved
        if lookup_env is not self.module_bindings.get(module_name, {}):
            return self._eval_expr_static(expr, self.module_bindings.get(module_name, {}))
        return set()

    def _type_guard_refinement(
        self,
        expr: Optional[ast.AST],
        module_name: str,
        env: Optional[Mapping[str, Set[AbstractValue]]] = None,
    ) -> Set[AbstractValue]:
        if expr is None:
            return set()
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            try:
                parsed = ast.parse(expr.value, mode="eval")
            except SyntaxError:
                return set()
            return self._type_guard_refinement(parsed.body, module_name, env)
        if isinstance(expr, ast.Subscript):
            base_name = self._expr_qualname(expr.value)
            if base_name in {
                "TypeGuard",
                "typing.TypeGuard",
                "TypeIs",
                "typing.TypeIs",
            }:
                out: Set[AbstractValue] = set()
                for item in self._annotation_union_items(expr.slice):
                    out.update(
                        self._resolve_type_expression_values(item, module_name, env)
                    )
                return out
        return set()

    def _registry_binding_payload(
        self,
        decorator_expr: ast.AST,
        scope: ScopeInfo,
        scope_context: ContextKey,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Tuple[Set[AbstractValue], Set[str]]:
        if not isinstance(decorator_expr, ast.Call):
            return set(), set()
        func_expr = decorator_expr.func
        if not isinstance(func_expr, ast.Attribute):
            return set(), set()
        if func_expr.attr not in self._registry_like_names:
            return set(), set()
        key_names: Set[str] = set()
        if decorator_expr.args:
            key_names.update(
                self._resolve_string_expression_values(
                    decorator_expr.args[0], scope.module, env=env
                )
            )
        if not key_names:
            return set(), set()
        owner_values = self._eval_expr(
            scope,
            scope_context,
            func_expr.value,
            env,
            callees,
            input_changed_scope_contexts,
        )
        return owner_values, key_names

    def _singledispatch_registration_payload(
        self,
        decorator_expr: ast.AST,
        scope: ScopeInfo,
        scope_context: ContextKey,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Tuple[Set[str], Set[AbstractValue]]:
        if not isinstance(decorator_expr, ast.Call):
            return set(), set()
        func_expr = decorator_expr.func
        if not isinstance(func_expr, ast.Attribute) or func_expr.attr != "register":
            return set(), set()
        owner_values = self._eval_expr(
            scope,
            scope_context,
            func_expr.value,
            env,
            callees,
            input_changed_scope_contexts,
        )
        generic_names = {
            value.name
            for value in owner_values
            if value.kind == FUNC_KIND and value.name in self.singledispatch_functions
        }
        if not generic_names:
            return set(), set()
        declared_types: Set[AbstractValue] = set()
        if decorator_expr.args:
            declared_types.update(
                self._resolve_type_expression_values(
                    decorator_expr.args[0], scope.module, env=env
                )
            )
        return generic_names, declared_types

    def _register_singledispatch_implementation(
        self,
        generic_name: str,
        function_name: str,
        dispatch_types: Set[AbstractValue],
    ) -> None:
        registrations = self.singledispatch_registrations[generic_name]
        for index, (existing_name, _existing_types) in enumerate(registrations):
            if existing_name == function_name:
                replacement = (function_name, set(dispatch_types))
                if registrations[index] != replacement:
                    registrations[index] = replacement
                    self._active_singledispatch_changed = True
                return
        registrations.append((function_name, set(dispatch_types)))
        self._active_singledispatch_changed = True

    def _singledispatch_registration_types(self, function_name: str) -> Set[AbstractValue]:
        function_info = self.functions.get(function_name)
        if function_info is None or not function_info.params:
            return set()
        first_param = function_info.params[0]
        return self._resolve_type_expression_values(
            function_info.param_annotations.get(first_param),
            function_info.module,
        )

    def _matches_type_values(
        self, value: AbstractValue, type_values: Set[AbstractValue]
    ) -> bool:
        allowed_classes = {item.name for item in type_values if item.kind == CLASS_KIND}
        allowed_strings = {item.name for item in type_values if item.kind == STRING_KIND}
        allow_none = any(item.kind == NONE_KIND for item in type_values)

        protocol_classes = [
            class_name for class_name in allowed_classes if self._is_protocol_class(class_name)
        ]

        if value.kind == UNKNOWN_KIND:
            return True
        if value.kind == NONE_KIND:
            return allow_none
        if value.kind == STRING_KIND:
            return value.name in allowed_strings
        if protocol_classes and value.kind in {INSTANCE_KIND, CLASS_KIND}:
            if any(
                self._matches_protocol_structurally(value, protocol_name)
                for protocol_name in protocol_classes
            ):
                return True
        if value.kind == INSTANCE_KIND and allowed_classes:
            value_class = instance_class_name(value)
            order = self._class_lookup_order(value_class)
            return any(class_name in order for class_name in allowed_classes)
        if value.kind == CLASS_KIND and allowed_classes:
            order = self._class_lookup_order(value.name)
            return any(class_name in order for class_name in allowed_classes)
        return False

    def _is_callable_value(self, value: AbstractValue) -> bool:
        if value.kind in {
            FUNC_KIND,
            BOUND_METHOD_KIND,
            BOUND_CLASS_METHOD_KIND,
            CLASS_KIND,
            PARTIAL_KIND,
        }:
            return True
        if value.kind == INSTANCE_KIND:
            target_class_name = instance_class_name(value)
            lookup_order = self._class_lookup_order(target_class_name)
            for klass in lookup_order:
                class_info = self.classes.get(klass)
                if class_info and "__call__" in class_info.methods:
                    return True
        if value.kind == UNKNOWN_KIND:
            return True
        return False

    def _is_protocol_class(self, class_name: str) -> bool:
        class_info = self.classes.get(class_name)
        if class_info is None:
            return False
        protocol_markers = {
            "Protocol",
            "typing.Protocol",
            "typing_extensions.Protocol",
        }
        return any(base in protocol_markers or self._is_protocol_class(base) for base in class_info.bases)

    def _protocol_required_attrs(self, class_name: str) -> Set[str]:
        out: Set[str] = set()
        for proto in self._class_lookup_order(class_name):
            proto_info = self.classes.get(proto)
            if proto_info is None:
                continue
            if not self._is_protocol_class(proto) and proto != class_name:
                continue
            for method_name in proto_info.methods:
                if method_name.startswith("_") and method_name not in {"__call__"}:
                    continue
                out.add(method_name)
            out.update(self.class_fields.get(proto, {}).keys())
        return out

    def _matches_protocol_structurally(
        self, value: AbstractValue, protocol_name: str
    ) -> bool:
        required_attrs = self._protocol_required_attrs(protocol_name)
        if not required_attrs:
            return False
        return all(self._resolve_attribute({value}, attr_name) for attr_name in required_attrs)

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
                out.add(make_instance(next_base, parse_instance_name(obj_value.name)[1]))
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
                for (scope_key, context_key), context_inputs in self.scope_inputs.items():
                    if scope_key != callee_name:
                        continue
                    if any(
                        context_inputs.get(name)
                        for name in callee_function_info.closure_vars
                    ):
                        candidate_contexts.append(context_key)
                if candidate_contexts:
                    callee_context = sorted(candidate_contexts)[0]
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
        self.call_dependents[(callee_name, callee_context)].add(caller_scope_key)
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

    def _assign_reflective_attribute(
        self,
        target_values: Set[AbstractValue],
        attr_names: Set[str],
        assigned_values: Set[AbstractValue],
    ) -> None:
        if not attr_names or not assigned_values:
            return

        for target_value in target_values:
            if target_value.kind == INSTANCE_KIND:
                for attr_name in attr_names:
                    current = self.instance_fields[target_value.name][attr_name]
                    before = len(current)
                    current.update(assigned_values)
                    if (
                        len(current) != before
                        and self._active_changed_instance_fields is not None
                    ):
                        self._active_changed_instance_fields.add(
                            (target_value.name, attr_name)
                        )
            elif target_value.kind == CLASS_KIND:
                for attr_name in attr_names:
                    current = self.class_fields[target_value.name][attr_name]
                    before = len(current)
                    current.update(assigned_values)
                    if (
                        len(current) != before
                        and self._active_changed_class_fields is not None
                    ):
                        self._active_changed_class_fields.add(
                            (target_value.name, attr_name)
                        )

    def _class_lookup_order(self, class_name: str) -> List[str]:
        """
        Return class lookup order.

        Uses C3 MRO when available; falls back to conservative BFS order for
        classes with invalid/inconsistent MRO.
        """
        if class_name in self._invalid_mro_classes:
            queue = [class_name]
            seen: Set[str] = set()
            order: List[str] = []
            while queue:
                current = queue.pop(0)
                if current in seen:
                    continue
                seen.add(current)
                order.append(current)
                class_info = self.classes.get(current)
                if class_info:
                    queue.extend(class_info.bases)
            return order
        return self._mro(class_name)

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
            current = env.setdefault(name, set())
            before = len(current)
            current.update(values)
            changed = changed or len(current) != before
        for name, values in self.scope_nonlocal_writes.get(scope_key, {}).items():
            current = env.setdefault(name, set())
            before = len(current)
            current.update(values)
            changed = changed or len(current) != before
        return changed

    def _invoke_targets(
        self,
        caller_scope: ScopeInfo,
        caller_context: ContextKey,
        target_values: Set[AbstractValue],
        call_node: ast.Call,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        """
        Invoke abstract call targets and accumulate edges/return abstractions.

        This is the interprocedural transfer function. It is responsible for:
        - argument extraction (`args`, `*args`, `**kwargs`),
        - call edge emission,
        - callee input binding and dependency tracking,
        - conservative dynamic summary node generation when unresolved.
        """
        caller_scope_key = (
            caller_scope.name,
            self._normalize_context_for_scope(caller_scope.name, caller_context),
        )
        arg_values: List[Set[AbstractValue]] = []
        star_arg_values: List[Set[AbstractValue]] = []
        for arg in call_node.args:
            if isinstance(arg, ast.Starred):
                unpacked = self._eval_expr(
                    caller_scope,
                    caller_context,
                    arg.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                expanded = self._iterable_members(unpacked)
                star_arg_values.append(expanded or {UNKNOWN_VALUE})
                continue
            arg_values.append(
                self._eval_expr(
                    caller_scope,
                    caller_context,
                    arg,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
            )

        kwarg_values: Dict[str, Set[AbstractValue]] = {}
        dynamic_kwarg_values: Set[AbstractValue] = set()
        for keyword in call_node.keywords:
            values = self._eval_expr(
                caller_scope,
                caller_context,
                keyword.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            if keyword.arg is not None:
                kwarg_values.setdefault(keyword.arg, set()).update(values)
                continue

            if not values:
                dynamic_kwarg_values.add(UNKNOWN_VALUE)
                continue

            for unpacked in values:
                if unpacked.kind == CONTAINER_KIND:
                    key_map = self.container_key_values.get(unpacked.name, {})
                    if key_map:
                        for key_name, key_values in key_map.items():
                            kwarg_values.setdefault(key_name, set()).update(key_values)
                    element_values = self.container_elements.get(unpacked.name, set())
                    if element_values:
                        dynamic_kwarg_values.update(element_values)
                    else:
                        dynamic_kwarg_values.add(UNKNOWN_VALUE)
                else:
                    dynamic_kwarg_values.add(unpacked)

        if not target_values and isinstance(call_node.func, ast.Name):
            maybe_builtin = call_node.func.id
            if maybe_builtin in self._builtin_callable_names:
                target_values = {make_func(f"<builtin>.{maybe_builtin}")}

        out: Set[AbstractValue] = set()
        unresolved_dynamic = not target_values
        unresolved_reasons: Set[str] = set()
        resolved_callable = False
        deferred_parameter_call = False
        if unresolved_dynamic:
            unresolved_reasons.add("missing_target")
            if isinstance(call_node.func, ast.Name):
                unresolved_name = call_node.func.id
                is_parameter_name = (
                    unresolved_name in caller_scope.params
                    or unresolved_name in caller_scope.closure_vars
                    or unresolved_name == caller_scope.method_self_param
                    or unresolved_name == caller_scope.method_cls_param
                )
                caller_is_root_context = self._normalize_context_for_scope(
                    caller_scope.name, caller_context
                ) == ("<global>",)
                if (
                    caller_is_root_context
                    and is_parameter_name
                    and (
                        unresolved_name not in env
                        or not env.get(unresolved_name, set())
                    )
                ):
                    # In root/unbound contexts, parameter call targets are not
                    # known yet. Defer emitting dynamic edges until bindings arrive.
                    deferred_parameter_call = True
            elif isinstance(call_node.func, ast.Subscript) and isinstance(
                call_node.func.value, ast.Name
            ):
                unresolved_name = call_node.func.value.id
                caller_is_root_context = self._normalize_context_for_scope(
                    caller_scope.name, caller_context
                ) == ("<global>",)
                if (
                    caller_is_root_context
                    and unresolved_name in caller_scope.params
                    and unresolved_name in env
                    and not env[unresolved_name]
                ):
                    deferred_parameter_call = True
            elif isinstance(call_node.func, ast.Attribute) and isinstance(
                call_node.func.value, ast.Name
            ):
                unresolved_name = call_node.func.value.id
                caller_is_root_context = self._normalize_context_for_scope(
                    caller_scope.name, caller_context
                ) == ("<global>",)
                if (
                    caller_is_root_context
                    and unresolved_name in caller_scope.params
                    and unresolved_name in env
                    and not env[unresolved_name]
                ):
                    deferred_parameter_call = True

        for target in target_values:
            if target.kind == FUNC_KIND:
                resolved_callable = True
                callee_name = target.name
                callees.add(callee_name)
                if callee_name in {"<builtin>.setattr", "<builtin>.delattr"}:
                    if len(arg_values) >= 2:
                        attr_names = self._string_constants(arg_values[1])
                        if callee_name == "<builtin>.setattr" and len(arg_values) >= 3:
                            self._assign_reflective_attribute(
                                arg_values[0], attr_names, set(arg_values[2])
                            )
                        elif callee_name == "<builtin>.delattr":
                            for target_value in arg_values[0]:
                                if target_value.kind == INSTANCE_KIND:
                                    for attr_name in attr_names:
                                        if attr_name in self.instance_fields.get(
                                            target_value.name, {}
                                        ):
                                            del self.instance_fields[target_value.name][
                                                attr_name
                                            ]
                                            if (
                                                self._active_changed_instance_fields
                                                is not None
                                            ):
                                                self._active_changed_instance_fields.add(
                                                    (target_value.name, attr_name)
                                                )
                                elif target_value.kind == CLASS_KIND:
                                    for attr_name in attr_names:
                                        if attr_name in self.class_fields.get(
                                            target_value.name, {}
                                        ):
                                            del self.class_fields[target_value.name][
                                                attr_name
                                            ]
                                            if (
                                                self._active_changed_class_fields
                                                is not None
                                            ):
                                                self._active_changed_class_fields.add(
                                                    (target_value.name, attr_name)
                                                )
                    out.add(NONE_VALUE)
                elif callee_name in {
                    "<builtin>.hasattr",
                    "<builtin>.getattr",
                }:
                    out.add(UNKNOWN_VALUE)
                elif callee_name == "functools.partial":
                    if arg_values:
                        for callback in arg_values[0]:
                            if callback.kind in {
                                FUNC_KIND,
                                BOUND_METHOD_KIND,
                                BOUND_CLASS_METHOD_KIND,
                                CLASS_KIND,
                                INSTANCE_KIND,
                            }:
                                out.add(make_partial(callback.kind, callback.name))
                    if not out:
                        out.add(UNKNOWN_VALUE)
                elif callee_name in {
                    "importlib.import_module",
                    "<builtin>.__import__",
                }:
                    imported_modules: Set[AbstractValue] = set()
                    if arg_values:
                        for module_name in self._string_constants(arg_values[0]):
                            imported_modules.add(make_module(module_name))
                            self._register_imported_module_chain(module_name)
                    out.update(imported_modules or {UNKNOWN_VALUE})
                elif callee_name in self.singledispatch_functions:
                    callees.discard(callee_name)
                    matched_targets: Set[AbstractValue] = set()
                    first_arg_values = arg_values[0] if arg_values else set()
                    registrations = self.singledispatch_registrations.get(
                        callee_name, []
                    )
                    has_unmatched_runtime = not first_arg_values
                    for value in first_arg_values:
                        matched_for_value = False
                        for registered_name, dispatch_types in registrations:
                            if dispatch_types and not self._matches_type_values(
                                value, dispatch_types
                            ):
                                continue
                            matched_targets.add(make_func(registered_name))
                            matched_for_value = True
                        if not matched_for_value and value.kind != UNKNOWN_KIND:
                            has_unmatched_runtime = True
                    for matched_target in sorted(
                        matched_targets, key=lambda item: item.name
                    ):
                        out.update(
                            self._invoke_named_function(
                                matched_target.name,
                                caller_scope,
                                caller_context,
                                call_node,
                                env,
                                callees,
                                input_changed_scope_contexts,
                                arg_values,
                                kwarg_values,
                                star_arg_values=star_arg_values,
                                dynamic_kwarg_values=dynamic_kwarg_values,
                            )
                        )
                    if has_unmatched_runtime or not matched_targets:
                        out.update(
                            self._invoke_named_function(
                                callee_name,
                                caller_scope,
                                caller_context,
                                call_node,
                                env,
                                callees,
                                input_changed_scope_contexts,
                                arg_values,
                                kwarg_values,
                                star_arg_values=star_arg_values,
                                dynamic_kwarg_values=dynamic_kwarg_values,
                            )
                        )
                elif callee_name in self.scopes:
                    out.update(
                        self._invoke_named_function(
                            callee_name,
                            caller_scope,
                            caller_context,
                            call_node,
                            env,
                            callees,
                            input_changed_scope_contexts,
                            arg_values,
                            kwarg_values,
                            star_arg_values=star_arg_values,
                            dynamic_kwarg_values=dynamic_kwarg_values,
                        )
                    )
                elif callee_name in {
                    "<builtin>.map",
                    "<builtin>.filter",
                    "<builtin>.sorted",
                    "functools.reduce",
                }:
                    callback_values: Set[AbstractValue] = set()
                    callback_index = 0
                    if callee_name == "<builtin>.sorted":
                        if "key" in kwarg_values:
                            callback_values.update(kwarg_values["key"])
                        callback_index = -1
                    elif callee_name == "functools.reduce":
                        callback_index = 0
                    if callback_index >= 0 and len(arg_values) > callback_index:
                        for callback in arg_values[callback_index]:
                            if callback.kind in {
                                FUNC_KIND,
                                BOUND_METHOD_KIND,
                                BOUND_CLASS_METHOD_KIND,
                                CLASS_KIND,
                                INSTANCE_KIND,
                                PARTIAL_KIND,
                            }:
                                callback_values.add(callback)
                    if callee_name in {"<builtin>.filter", "<builtin>.map"} and not callback_values and arg_values:
                        callback_values = set(arg_values[0])
                    if callback_values:
                        callback_results = self._invoke_callback_values(
                            caller_scope=caller_scope,
                            caller_context=caller_context,
                            call_node=call_node,
                            env=env,
                            callees=callees,
                            input_changed_scope_contexts=input_changed_scope_contexts,
                            callback_values=callback_values,
                        )
                        if callback_results:
                            out.update(callback_results)
                    if not out:
                        out.add(UNKNOWN_VALUE)
                elif callee_name == "<**PyDict**>.update":
                    callees.discard(callee_name)
                    # Update dict container contents when receiver and source
                    # dictionary literals are available in the environment.
                    if isinstance(call_node.func, ast.Attribute) and isinstance(
                        call_node.func.value, ast.Name
                    ):
                        receiver_values = env.get(call_node.func.value.id, set())
                        receiver_dicts = {
                            value.name
                            for value in receiver_values
                            if value.kind == CONTAINER_KIND
                            and value.name.startswith("dict:")
                        }
                        source_dicts: Set[str] = set()
                        for values in arg_values:
                            for value in values:
                                if (
                                    value.kind == CONTAINER_KIND
                                    and value.name.startswith("dict:")
                                ):
                                    source_dicts.add(value.name)
                        for receiver_dict in receiver_dicts:
                            for source_dict in source_dicts:
                                self.container_elements[receiver_dict].update(
                                    self.container_elements.get(source_dict, set())
                                )
                                source_key_map = self.container_key_values.get(
                                    source_dict, {}
                                )
                                for key_name, key_values in source_key_map.items():
                                    self.container_key_values[receiver_dict][
                                        key_name
                                    ] = set(key_values)
                    out.add(UNKNOWN_VALUE)
                elif callee_name in {
                    "<**PyDict**>.items",
                    "<**PyStr**>.join",
                    "<**PyStr**>.split",
                }:
                    out.add(UNKNOWN_VALUE)
                elif callee_name == "<**PyDict**>.get":
                    receiver_values: Set[AbstractValue] = set()
                    if isinstance(call_node.func, ast.Attribute):
                        receiver_values = self._eval_expr(
                            caller_scope,
                            caller_context,
                            call_node.func.value,
                            env,
                            callees,
                            input_changed_scope_contexts,
                        )
                    key_names: Set[str] = set()
                    if arg_values:
                        key_names = self._string_constants(arg_values[0])
                    matched_values: Set[AbstractValue] = set()
                    for receiver in receiver_values:
                        if receiver.kind != CONTAINER_KIND:
                            continue
                        key_map = self.container_key_values.get(receiver.name, {})
                        if key_names:
                            for key_name in key_names:
                                matched_values.update(key_map.get(key_name, set()))
                        else:
                            matched_values.update(
                                self.container_elements.get(receiver.name, set())
                            )
                    if matched_values:
                        out.update(matched_values)
                    elif len(arg_values) >= 2:
                        out.update(arg_values[1])
                    else:
                        out.add(UNKNOWN_VALUE)
                elif callee_name == "<**PyDict**>.setdefault":
                    receiver_values: Set[AbstractValue] = set()
                    if isinstance(call_node.func, ast.Attribute):
                        receiver_values = self._eval_expr(
                            caller_scope,
                            caller_context,
                            call_node.func.value,
                            env,
                            callees,
                            input_changed_scope_contexts,
                        )
                    key_names = self._string_constants(arg_values[0]) if arg_values else set()
                    default_values = arg_values[1] if len(arg_values) >= 2 else {UNKNOWN_VALUE}
                    matched_values: Set[AbstractValue] = set()
                    for receiver in receiver_values:
                        if receiver.kind != CONTAINER_KIND:
                            continue
                        key_map = self.container_key_values.get(receiver.name, {})
                        for key_name in key_names:
                            existing = key_map.get(key_name, set())
                            if existing:
                                matched_values.update(existing)
                            else:
                                self.container_key_values[receiver.name][key_name].update(default_values)
                                self.container_elements[receiver.name].update(default_values)
                    out.update(matched_values or default_values)
                elif callee_name == "<**PyDict**>.pop":
                    receiver_values: Set[AbstractValue] = set()
                    if isinstance(call_node.func, ast.Attribute):
                        receiver_values = self._eval_expr(
                            caller_scope,
                            caller_context,
                            call_node.func.value,
                            env,
                            callees,
                            input_changed_scope_contexts,
                        )
                    key_names = self._string_constants(arg_values[0]) if arg_values else set()
                    default_values = arg_values[1] if len(arg_values) >= 2 else set()
                    popped_values: Set[AbstractValue] = set()
                    for receiver in receiver_values:
                        if receiver.kind != CONTAINER_KIND:
                            continue
                        key_map = self.container_key_values.get(receiver.name, {})
                        for key_name in key_names:
                            existing = key_map.pop(key_name, set())
                            if existing:
                                popped_values.update(existing)
                    out.update(popped_values or default_values or {UNKNOWN_VALUE})
                else:
                    last_segment = callee_name.rsplit(".", 1)[-1]
                    if last_segment and last_segment[0].isupper():
                        out.add(make_instance(callee_name))
                        continue
                    out.add(UNKNOWN_VALUE)

            elif target.kind == CLASS_KIND:
                resolved_callable = True
                class_name = target.name
                if self.options.allocation_site_sensitive_instances:
                    line = getattr(call_node, "lineno", -1)
                    col = getattr(call_node, "col_offset", -1)
                    normalized_ctx = self._normalize_context_for_scope(
                        caller_scope.name, caller_context
                    )
                    context_token = "|".join(normalized_ctx)
                    alloc_site = f"{caller_scope.name}@{line}:{col}:{context_token}"
                    instance_value = make_instance(class_name, alloc_site)
                else:
                    instance_value = make_instance(class_name)
                out.add(instance_value)
                init_name: Optional[str] = None
                class_order = self._class_lookup_order(class_name)
                for klass in class_order:
                    candidate = f"{klass}.__init__"
                    if candidate in self.scopes:
                        init_name = candidate
                        break
                    if klass not in self.classes and "." in klass:
                        init_name = candidate
                        break
                if init_name is not None:
                    callees.add(init_name)
                    implicit_values = [{instance_value}] + arg_values
                    raw_context = self._derive_callee_context(
                        caller_scope.name, caller_context, call_node
                    )
                    callee_context = self._normalize_context_for_scope(
                        init_name, raw_context
                    )
                    if init_name in self.scopes:
                        changed = self._bind_call_arguments(
                            init_name,
                            callee_context,
                            implicit_values,
                            kwarg_values,
                            star_arg_values=star_arg_values,
                            dynamic_kwarg_values=dynamic_kwarg_values,
                        )
                        if changed:
                            input_changed_scope_contexts.add(
                                (init_name, callee_context)
                            )
                        if (
                            init_name,
                            callee_context,
                        ) not in self._analyzed_scope_contexts:
                            input_changed_scope_contexts.add(
                                (init_name, callee_context)
                            )
                        self.call_dependents[(init_name, callee_context)].add(
                            caller_scope_key
                        )
                        self._apply_callee_side_effects(init_name, callee_context, env)

            elif target.kind == BOUND_METHOD_KIND:
                resolved_callable = True
                method_name, receiver_instance = parse_bound_method(target)
                callees.add(method_name)
                receiver_class, receiver_alloc = parse_instance_name(receiver_instance)
                implicit_values = [
                    {make_instance(receiver_class, receiver_alloc)}
                ] + arg_values
                callee_context = self._derive_callee_context(
                    caller_scope.name, caller_context, call_node
                )
                callee_context = self._normalize_context_for_scope(
                    method_name, callee_context
                )
                changed = self._bind_call_arguments(
                    method_name,
                    callee_context,
                    implicit_values,
                    kwarg_values,
                    star_arg_values=star_arg_values,
                    dynamic_kwarg_values=dynamic_kwarg_values,
                )
                if changed:
                    input_changed_scope_contexts.add((method_name, callee_context))
                if (method_name, callee_context) not in self._analyzed_scope_contexts:
                    input_changed_scope_contexts.add((method_name, callee_context))
                self.call_dependents[(method_name, callee_context)].add(
                    caller_scope_key
                )
                out.update(self.scope_returns[(method_name, callee_context)])
                self._apply_callee_side_effects(method_name, callee_context, env)

            elif target.kind == BOUND_CLASS_METHOD_KIND:
                resolved_callable = True
                method_name, receiver_class = parse_bound_class_method(target)
                callees.add(method_name)
                implicit_values = [{make_class(receiver_class)}] + arg_values
                callee_context = self._derive_callee_context(
                    caller_scope.name, caller_context, call_node
                )
                callee_context = self._normalize_context_for_scope(
                    method_name, callee_context
                )
                changed = self._bind_call_arguments(
                    method_name,
                    callee_context,
                    implicit_values,
                    kwarg_values,
                    star_arg_values=star_arg_values,
                    dynamic_kwarg_values=dynamic_kwarg_values,
                )
                if changed:
                    input_changed_scope_contexts.add((method_name, callee_context))
                if (method_name, callee_context) not in self._analyzed_scope_contexts:
                    input_changed_scope_contexts.add((method_name, callee_context))
                self.call_dependents[(method_name, callee_context)].add(
                    caller_scope_key
                )
                out.update(self.scope_returns[(method_name, callee_context)])
                self._apply_callee_side_effects(method_name, callee_context, env)

            elif target.kind == INSTANCE_KIND:
                called = False
                target_class_name = instance_class_name(target)
                lookup_order = self._class_lookup_order(target_class_name)
                for klass in lookup_order:
                    class_info = self.classes.get(klass)
                    if not class_info:
                        continue
                    call_name = class_info.methods.get("__call__")
                    if not call_name:
                        continue
                    called = True
                    callees.add(call_name)
                    implicit_values = [{target}] + arg_values
                    callee_context = self._derive_callee_context(
                        caller_scope.name, caller_context, call_node
                    )
                    callee_context = self._normalize_context_for_scope(
                        call_name, callee_context
                    )
                    changed = self._bind_call_arguments(
                        call_name,
                        callee_context,
                        implicit_values,
                        kwarg_values,
                        star_arg_values=star_arg_values,
                        dynamic_kwarg_values=dynamic_kwarg_values,
                    )
                    if changed:
                        input_changed_scope_contexts.add((call_name, callee_context))
                    if (call_name, callee_context) not in self._analyzed_scope_contexts:
                        input_changed_scope_contexts.add((call_name, callee_context))
                    self.call_dependents[(call_name, callee_context)].add(
                        caller_scope_key
                    )
                    out.update(self.scope_returns[(call_name, callee_context)])
                    self._apply_callee_side_effects(call_name, callee_context, env)
                    resolved_callable = True
                    if target_class_name not in self._invalid_mro_classes:
                        break
                if not called:
                    unresolved_dynamic = True
                    unresolved_reasons.add("instance_without_call")
                    out.add(UNKNOWN_VALUE)

            elif target.kind == PARTIAL_KIND:
                resolved_callable = True
                inner_kind, inner_name = parse_partial(target)
                forwarded_target = AbstractValue(inner_kind, inner_name)
                partial_result = self._invoke_targets(
                    caller_scope=caller_scope,
                    caller_context=caller_context,
                    target_values={forwarded_target},
                    call_node=call_node,
                    env=env,
                    callees=callees,
                    input_changed_scope_contexts=input_changed_scope_contexts,
                )
                out.update(partial_result or {UNKNOWN_VALUE})

            elif target.kind in {CONTAINER_KIND, STRING_KIND, UNKNOWN_KIND, NONE_KIND}:
                unresolved_dynamic = True
                unresolved_reasons.add("unknown_callable")
                out.add(UNKNOWN_VALUE)

        if unresolved_dynamic and not resolved_callable and not deferred_parameter_call:
            reasons = unresolved_reasons or {"unresolved"}
            for reason in sorted(reasons):
                callees.add(
                    self._dynamic_summary_node_with_reason(
                        caller_scope, call_node, reason
                    )
                )
            out.add(UNKNOWN_VALUE)

        return out

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
                before = len(current)
                current.update(filtered_values)
                changed = changed or len(current) != before
            elif scope.vararg:
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(scope.vararg), values
                )
                current = param_inputs.setdefault(scope.vararg, set())
                before = len(current)
                current.update(filtered_values)
                changed = changed or len(current) != before

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
                    before = len(current)
                    current.update(filtered_values)
                    changed = changed or len(current) != before
                if scope.vararg:
                    filtered_values = self._filter_values_by_annotation(
                        scope.module,
                        scope.param_annotations.get(scope.vararg),
                        pooled_star_values,
                    )
                    current = param_inputs.setdefault(scope.vararg, set())
                    before = len(current)
                    current.update(filtered_values)
                    changed = changed or len(current) != before

        for kw_name, kw_values in kwarg_values.items():
            if kw_name in pos_or_kw_set or kw_name in kwonly_set:
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(kw_name), kw_values
                )
                current = param_inputs.setdefault(kw_name, set())
                before = len(current)
                current.update(filtered_values)
                changed = changed or len(current) != before
            elif kw_name in posonly_set:
                # Positional-only parameters cannot be bound by keyword.
                continue
            elif scope.kwarg:
                filtered_values = self._filter_values_by_annotation(
                    scope.module, scope.param_annotations.get(scope.kwarg), kw_values
                )
                current = param_inputs.setdefault(scope.kwarg, set())
                before = len(current)
                current.update(filtered_values)
                changed = changed or len(current) != before

        if dynamic_kwarg_values and scope.kwarg:
            filtered_values = self._filter_values_by_annotation(
                scope.module, scope.param_annotations.get(scope.kwarg), dynamic_kwarg_values
            )
            current = param_inputs.setdefault(scope.kwarg, set())
            before = len(current)
            current.update(filtered_values)
            changed = changed or len(current) != before

        return changed

    def _bind_closure_values(
        self,
        callee_scope_name: str,
        callee_context: ContextKey,
        captured: Mapping[str, Set[AbstractValue]],
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
        changed = False
        for name, values in captured.items():
            if name not in scope.closure_vars:
                continue
            current = param_inputs.setdefault(name, set())
            before = len(current)
            current.update(values)
            changed = changed or len(current) != before
        return changed

    def _assign_target(
        self,
        scope: ScopeInfo,
        target: ast.AST,
        values: Set[AbstractValue],
        env: Dict[str, Set[AbstractValue]],
        weak: bool = False,
        global_writes: Optional[Dict[str, Set[AbstractValue]]] = None,
        nonlocal_writes: Optional[Dict[str, Set[AbstractValue]]] = None,
        changed_instance_fields: Optional[Set[Tuple[str, str]]] = None,
        changed_class_fields: Optional[Set[Tuple[str, str]]] = None,
    ) -> bool:
        """
        Assign abstract values into a target (name, destructuring, attr, subscript).

        Returns `True` when heap-like field/container state changed.
        """
        if not values:
            values = {UNKNOWN_VALUE}

        if isinstance(target, ast.Name):
            if target.id in scope.global_names:
                if weak:
                    env.setdefault(target.id, set()).update(values)
                else:
                    env[target.id] = set(values)
                if global_writes is not None:
                    global_writes.setdefault(target.id, set()).update(values)
                return False
            if target.id in scope.nonlocal_names:
                if weak:
                    env.setdefault(target.id, set()).update(values)
                else:
                    env[target.id] = set(values)
                if nonlocal_writes is not None:
                    nonlocal_writes.setdefault(target.id, set()).update(values)
                return False
            if weak:
                env.setdefault(target.id, set()).update(values)
            else:
                env[target.id] = set(values)
            return False

        if isinstance(target, (ast.Tuple, ast.List)):
            starred_indices = [
                index
                for index, elt in enumerate(target.elts)
                if isinstance(elt, ast.Starred)
            ]
            indexed_values: Dict[int, Set[AbstractValue]] = {}
            for value in values:
                if value.kind != CONTAINER_KIND:
                    continue
                key_map = self.container_key_values.get(value.name, {})
                for key_name, key_values in key_map.items():
                    if not key_name.startswith("#"):
                        continue
                    try:
                        key_index = int(key_name[1:])
                    except ValueError:
                        continue
                    indexed_values.setdefault(key_index, set()).update(key_values)

            if len(starred_indices) <= 1 and indexed_values:
                changed = False
                max_index = max(indexed_values)
                sequence_len = max_index + 1
                star_index = starred_indices[0] if starred_indices else None
                prefix_len = star_index if star_index is not None else len(target.elts)
                suffix_len = (
                    len(target.elts) - star_index - 1 if star_index is not None else 0
                )
                for elt_index, elt in enumerate(target.elts):
                    if isinstance(elt, ast.Starred):
                        start = prefix_len
                        end = max(start, sequence_len - suffix_len)
                        star_container_name = (
                            f"unpack:{scope.name}@{getattr(elt, 'lineno', -1)}:"
                            f"{getattr(elt, 'col_offset', -1)}:{start}:{end}"
                        )
                        star_container = make_container(star_container_name)
                        for src_index in range(start, end):
                            src_values = indexed_values.get(src_index, set())
                            if not src_values:
                                continue
                            self.container_elements[star_container.name].update(
                                src_values
                            )
                            self.container_key_values[star_container.name][
                                f"#{src_index - start}"
                            ].update(src_values)
                        assign_values = (
                            {star_container}
                            if self.container_elements.get(star_container.name)
                            else {UNKNOWN_VALUE}
                        )
                        changed = (
                            self._assign_target(
                                scope,
                                elt.value,
                                assign_values,
                                env,
                                weak=weak,
                                global_writes=global_writes,
                                nonlocal_writes=nonlocal_writes,
                                changed_instance_fields=changed_instance_fields,
                                changed_class_fields=changed_class_fields,
                            )
                            or changed
                        )
                        continue

                    if star_index is None or elt_index < star_index:
                        src_index = elt_index
                    else:
                        src_index = sequence_len - (len(target.elts) - elt_index)
                    assign_values = indexed_values.get(src_index, set()) or {
                        UNKNOWN_VALUE
                    }
                    changed = (
                        self._assign_target(
                            scope,
                            elt,
                            assign_values,
                            env,
                            weak=weak,
                            global_writes=global_writes,
                            nonlocal_writes=nonlocal_writes,
                            changed_instance_fields=changed_instance_fields,
                            changed_class_fields=changed_class_fields,
                        )
                        or changed
                    )
                return changed

            changed = False
            item_values = self._iterable_members(values) or {UNKNOWN_VALUE}
            for elt in target.elts:
                changed = (
                    self._assign_target(
                        scope,
                        elt,
                        item_values,
                        env,
                        weak=weak,
                        global_writes=global_writes,
                        nonlocal_writes=nonlocal_writes,
                        changed_instance_fields=changed_instance_fields,
                        changed_class_fields=changed_class_fields,
                    )
                    or changed
                )
            return changed

        if isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name):
                base_name = target.value.id
                if scope.method_self_param and base_name == scope.method_self_param:
                    receiver_instances = {
                        value.name
                        for value in env.get(base_name, set())
                        if value.kind == INSTANCE_KIND
                    }
                    if receiver_instances:
                        changed = False
                        for receiver_instance in receiver_instances:
                            current = self.instance_fields[receiver_instance][
                                target.attr
                            ]
                            before = len(current)
                            current.update(values)
                            did_change = len(current) != before
                            changed = changed or did_change
                            if did_change and changed_instance_fields is not None:
                                changed_instance_fields.add(
                                    (receiver_instance, target.attr)
                                )
                        return changed
                    owner = self._owner_class_for_scope(scope.name)
                    if owner:
                        current = self.instance_fields[owner][target.attr]
                        before = len(current)
                        current.update(values)
                        changed = len(current) != before
                        if changed and changed_instance_fields is not None:
                            changed_instance_fields.add((owner, target.attr))
                        return changed
                if scope.method_cls_param and base_name == scope.method_cls_param:
                    receiver_classes = {
                        value.name
                        for value in env.get(base_name, set())
                        if value.kind == CLASS_KIND
                    }
                    if receiver_classes:
                        changed = False
                        for receiver_class in receiver_classes:
                            current = self.class_fields[receiver_class][target.attr]
                            before = len(current)
                            current.update(values)
                            did_change = len(current) != before
                            changed = changed or did_change
                            if did_change and changed_class_fields is not None:
                                changed_class_fields.add((receiver_class, target.attr))
                        return changed
                    owner = self._owner_class_for_scope(scope.name)
                    if owner:
                        current = self.class_fields[owner][target.attr]
                        before = len(current)
                        current.update(values)
                        changed = len(current) != before
                        if changed and changed_class_fields is not None:
                            changed_class_fields.add((owner, target.attr))
                        return changed
                base_values = env.get(base_name, set())
                class_values = {v.name for v in base_values if v.kind == CLASS_KIND}
                instance_values = {
                    v.name for v in base_values if v.kind == INSTANCE_KIND
                }
                changed = False
                for class_name in class_values:
                    current = self.class_fields[class_name][target.attr]
                    before = len(current)
                    current.update(values)
                    did_change = len(current) != before
                    changed = changed or did_change
                    if did_change and changed_class_fields is not None:
                        changed_class_fields.add((class_name, target.attr))
                for instance_or_class_name in instance_values:
                    current = self.instance_fields[instance_or_class_name][target.attr]
                    before = len(current)
                    current.update(values)
                    did_change = len(current) != before
                    changed = changed or did_change
                    if did_change and changed_instance_fields is not None:
                        changed_instance_fields.add(
                            (instance_or_class_name, target.attr)
                        )
                return changed
            return False

        if isinstance(target, ast.Subscript):
            base_values: Set[AbstractValue] = set()
            if isinstance(target.value, ast.Name):
                base_values = set(env.get(target.value.id, set()))
            elif isinstance(target.value, ast.Subscript) and isinstance(
                target.value.value, ast.Name
            ):
                parent_values = set(env.get(target.value.value.id, set()))
                parent_keys = self._subscript_keys(target.value)
                for parent_value in parent_values:
                    if parent_value.kind != CONTAINER_KIND:
                        continue
                    parent_key_map = self.container_key_values.get(
                        parent_value.name, {}
                    )
                    nested_values: Set[AbstractValue] = set()
                    if parent_keys:
                        for key_name in parent_keys:
                            nested_values.update(parent_key_map.get(key_name, set()))
                    else:
                        nested_values.update(
                            self.container_elements.get(parent_value.name, set())
                        )
                    base_values.update(
                        value for value in nested_values if value.kind == CONTAINER_KIND
                    )
            key_names = self._subscript_keys(target)
            changed = False
            for base_value in base_values:
                if base_value.kind != CONTAINER_KIND:
                    continue
                current = self.container_elements[base_value.name]
                before = len(current)
                current.update(values)
                changed = changed or len(current) != before
                for key_name in key_names:
                    keyed_current = self.container_key_values[base_value.name][key_name]
                    if weak:
                        keyed_before = len(keyed_current)
                        keyed_current.update(values)
                        changed = changed or len(keyed_current) != keyed_before
                    else:
                        if keyed_current != values:
                            self.container_key_values[base_value.name][key_name] = set(
                                values
                            )
                            changed = True
            return changed

        return False

    def _lookup_name(
        self,
        module_name: str,
        name: str,
        env: Mapping[str, Set[AbstractValue]],
    ) -> Set[AbstractValue]:
        """Resolve symbol from environment or builtin callable namespace."""
        self._register_module_dependency(module_name)
        if name in env:
            return set(env[name])
        if name in self._builtin_callable_names:
            return {make_func(f"<builtin>.{name}")}
        return set()

    def _descriptor_bind_values(
        self,
        values: Iterable[AbstractValue],
        owner_class: Optional[str],
        instance_class: Optional[str],
    ) -> Set[AbstractValue]:
        """Apply descriptor `__get__`-style binding to attribute values."""
        out: Set[AbstractValue] = set()
        for value in values:
            if value.kind == FUNC_KIND:
                if instance_class is not None:
                    out.add(make_bound_method(value.name, instance_class))
                else:
                    out.add(value)
                continue

            if value.kind == INSTANCE_KIND:
                descriptor_class, _descriptor_alloc = parse_instance_name(value.name)
                descriptor_mro = self._mro(descriptor_class)
                for descriptor_class in descriptor_mro:
                    descriptor_info = self.classes.get(descriptor_class)
                    if not descriptor_info:
                        continue
                    get_method = descriptor_info.methods.get("__get__")
                    if not get_method:
                        continue
                    if instance_class is not None:
                        out.add(make_bound_method(get_method, value.name))
                    else:
                        out.add(make_bound_class_method(get_method, value.name))
                    break
                out.add(value)
                continue

            out.add(value)
        return out

    def _resolve_attribute(
        self, base_values: Iterable[AbstractValue], attr_name: str
    ) -> Set[AbstractValue]:
        """
        Resolve attribute access over modules/classes/instances/containers.

        Also records dependency edges so future field/module updates can requeue
        impacted scopes.
        """
        out: Set[AbstractValue] = set()

        for base_value in base_values:
            if base_value.kind == STRING_KIND:
                if attr_name in {"join", "split"}:
                    out.add(make_func(f"<**PyStr**>.{attr_name}"))
                continue

            if base_value.kind == MODULE_KIND:
                self._register_module_dependency(base_value.name)
                module_bindings = self.module_bindings.get(base_value.name)
                if module_bindings and attr_name in module_bindings:
                    out.update(module_bindings[attr_name])
                else:
                    out.add(make_func(f"{base_value.name}.{attr_name}"))

            elif base_value.kind == CLASS_KIND:
                class_order = self._class_lookup_order(base_value.name)
                stop_after_first = base_value.name not in self._invalid_mro_classes
                for klass in class_order:
                    class_info = self.classes.get(klass)
                    if not class_info or attr_name not in class_info.methods:
                        continue
                    method_name = class_info.methods[attr_name]
                    if attr_name in class_info.static_methods:
                        out.add(make_func(method_name))
                    elif attr_name in class_info.class_methods:
                        out.add(make_bound_class_method(method_name, base_value.name))
                    else:
                        out.add(make_bound_method(method_name, base_value.name))
                    if stop_after_first:
                        break

                for klass in class_order:
                    self._register_class_field_dependency(klass, attr_name)
                    class_attr_values = self.class_fields.get(klass, {}).get(
                        attr_name, set()
                    )
                    out.update(
                        self._descriptor_bind_values(
                            class_attr_values,
                            owner_class=base_value.name,
                            instance_class=None,
                        )
                    )
                nested_class = f"{base_value.name}.{attr_name}"
                if nested_class in self.classes:
                    out.add(make_class(nested_class))

            elif base_value.kind == INSTANCE_KIND:
                base_instance_name = base_value.name
                base_class_name = instance_class_name(base_value)
                class_order = self._class_lookup_order(base_class_name)
                stop_after_first = base_class_name not in self._invalid_mro_classes
                for klass in class_order:
                    class_info = self.classes.get(klass)
                    if class_info and attr_name in class_info.methods:
                        method_name = class_info.methods[attr_name]
                        if attr_name in class_info.static_methods:
                            out.add(make_func(method_name))
                        elif attr_name in class_info.class_methods:
                            out.add(
                                make_bound_class_method(method_name, base_class_name)
                            )
                        else:
                            out.add(make_bound_method(method_name, base_instance_name))
                        if stop_after_first:
                            break
                    if class_info is None and "." in klass:
                        out.add(make_func(f"{klass}.{attr_name}"))
                self._register_instance_field_dependency(base_instance_name, attr_name)
                out.update(
                    self.instance_fields.get(base_instance_name, {}).get(
                        attr_name, set()
                    )
                )
                for klass in class_order:
                    self._register_instance_field_dependency(klass, attr_name)
                    out.update(
                        self.instance_fields.get(klass, {}).get(attr_name, set())
                    )
                    self._register_class_field_dependency(klass, attr_name)
                    class_attr_values = self.class_fields.get(klass, {}).get(
                        attr_name, set()
                    )
                    out.update(
                        self._descriptor_bind_values(
                            class_attr_values,
                            owner_class=klass,
                            instance_class=base_value.name,
                        )
                    )
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "items"
                ):
                    out.add(make_func("<**PyDict**>.items"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "update"
                ):
                    out.add(make_func("<**PyDict**>.update"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "setdefault"
                ):
                    out.add(make_func("<**PyDict**>.setdefault"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "pop"
                ):
                    out.add(make_func("<**PyDict**>.pop"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "get"
                ):
                    out.add(make_func("<**PyDict**>.get"))

            elif base_value.kind == CONTAINER_KIND:
                if base_value.name.startswith("dict:"):
                    if attr_name == "items":
                        out.add(make_func("<**PyDict**>.items"))
                    elif attr_name == "update":
                        out.add(make_func("<**PyDict**>.update"))
                    elif attr_name == "setdefault":
                        out.add(make_func("<**PyDict**>.setdefault"))
                    elif attr_name == "pop":
                        out.add(make_func("<**PyDict**>.pop"))
                    elif attr_name == "get":
                        out.add(make_func("<**PyDict**>.get"))

        return out

    def _owner_class_for_scope(self, scope_name: str) -> Optional[str]:
        function_info = self.functions.get(scope_name)
        if not function_info:
            return None
        return function_info.owner_class

    def _mro(self, class_name: str) -> List[str]:
        """Compute and cache class MRO (C3) with conservative fallback on failure."""
        if class_name in self._mro_cache:
            return list(self._mro_cache[class_name])

        class_info = self.classes.get(class_name)
        if not class_info:
            self._mro_cache[class_name] = [class_name]
            return [class_name]

        base_mros = [self._mro(base) for base in class_info.bases]
        merge_input = [list(seq) for seq in base_mros]
        merge_input.append(list(class_info.bases))

        linearized: List[str] = [class_name]
        merged = self._c3_merge(merge_input)
        if merged is None:
            self._invalid_mro_classes.add(class_name)
            warnings.warn(
                (
                    f"Inconsistent MRO detected for {class_name}; "
                    "falling back to conservative attribute dispatch."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            seen = {class_name}
            queue = list(class_info.bases)
            while queue:
                base = queue.pop(0)
                if base in seen:
                    continue
                seen.add(base)
                linearized.append(base)
                base_info = self.classes.get(base)
                if base_info:
                    queue.extend(base_info.bases)
        else:
            linearized.extend(merged)
        self._mro_cache[class_name] = list(linearized)
        return linearized

    def _c3_merge(self, sequences: List[List[str]]) -> Optional[List[str]]:
        """C3 merge step used by `_mro`; returns None when constraints conflict."""
        result: List[str] = []
        pending = [list(seq) for seq in sequences if seq]

        while pending:
            candidate: Optional[str] = None
            for seq in pending:
                head = seq[0]
                if any(head in other[1:] for other in pending):
                    continue
                candidate = head
                break

            if candidate is None:
                return None

            result.append(candidate)
            next_pending: List[List[str]] = []
            for seq in pending:
                filtered = [name for name in seq if name != candidate]
                if filtered:
                    next_pending.append(filtered)
            pending = next_pending

        return result

    # --------------------------------------------------------------- utilities
    def _eval_expr_static(
        self, expr: ast.expr, env: Mapping[str, Set[AbstractValue]]
    ) -> Set[AbstractValue]:
        if isinstance(expr, ast.Name):
            return set(env.get(expr.id, set()))
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name):
                base = env.get(expr.value.id, set())
                if len(base) == 1:
                    base_value = next(iter(base))
                    if base_value.kind == MODULE_KIND:
                        module_bindings = self.module_bindings.get(base_value.name, {})
                        return set(module_bindings.get(expr.attr, set()))
        return set()

    def _register_imported_module_chain(self, module_name: str) -> None:
        if not module_name:
            return
        self.module_bindings.setdefault(module_name, {})
        parts = module_name.split(".")
        for idx in range(1, len(parts)):
            parent = ".".join(parts[:idx])
            child = ".".join(parts[: idx + 1])
            attr = parts[idx]
            parent_bindings = self.module_bindings.setdefault(parent, {})
            parent_bindings.setdefault(attr, set()).add(make_module(child))

    def _bind_import_alias(
        self,
        imported_name: str,
        local_name: str,
        env: Dict[str, Set[AbstractValue]],
        explicit_alias: bool = False,
    ) -> None:
        if not imported_name:
            return
        root_name = imported_name.split(".")[0]
        if not explicit_alias and "." in imported_name and local_name == root_name:
            env[local_name] = {make_module(root_name)}
        else:
            env[local_name] = {make_module(imported_name)}
        self._register_imported_module_chain(imported_name)

    def _bind_import(
        self, stmt: ast.Import, module_name: str, env: Dict[str, Set[AbstractValue]]
    ) -> None:
        for alias in stmt.names:
            imported_name = alias.name
            as_name = alias.asname or imported_name.split(".")[0]
            self._bind_import_alias(
                imported_name,
                as_name,
                env,
                explicit_alias=alias.asname is not None,
            )

    def _bind_import_from(
        self, stmt: ast.ImportFrom, module_name: str, env: Dict[str, Set[AbstractValue]]
    ) -> None:
        source_module = self._resolve_import_module_name(
            module_name, stmt.module, stmt.level
        )
        if not source_module:
            return

        source_exports = self.module_bindings.get(source_module, {})
        for alias in stmt.names:
            if alias.name == "*":
                for exported_name, exported_values in source_exports.items():
                    env.setdefault(exported_name, set()).update(exported_values)
                continue

            local_name = alias.asname or alias.name
            if alias.name in source_exports:
                env.setdefault(local_name, set()).update(source_exports[alias.name])
            else:
                candidate_module = f"{source_module}.{alias.name}"
                if candidate_module in self.modules or self._resolve_module_file(
                    candidate_module
                ):
                    env.setdefault(local_name, set()).add(make_module(candidate_module))
                    self._register_imported_module_chain(candidate_module)
                    self.module_bindings.setdefault(source_module, {}).setdefault(
                        alias.name, set()
                    ).add(make_module(candidate_module))
                else:
                    env.setdefault(local_name, set()).add(
                        make_func(f"{source_module}.{alias.name}")
                    )

    def _merge_bindings(
        self,
        target: Dict[str, Set[AbstractValue]],
        source: Mapping[str, Set[AbstractValue]],
    ) -> bool:
        changed = False
        for name, values in source.items():
            current = target.setdefault(name, set())
            before = len(current)
            current.update(values)
            changed = changed or len(current) != before
        return changed
