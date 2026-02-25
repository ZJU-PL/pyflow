"""Target invocation, argument binding, and attribute/MRO resolution."""

from __future__ import annotations

import ast
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
    ScopeInfo,
    STRING_KIND,
    UNKNOWN_KIND,
    UNKNOWN_VALUE,
    make_bound_class_method,
    make_bound_method,
    make_class,
    make_func,
    make_instance,
    make_module,
    parse_bound_class_method,
    parse_bound_method,
)


class _ResolverMixin:
    """Resolves call targets, binds arguments, and walks MRO for attribute lookup."""

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
                    caller_scope, caller_context, arg, env, callees, input_changed_scope_contexts
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
        resolved_any = False
        unresolved_dynamic = not target_values

        for target in target_values:
            if target.kind == FUNC_KIND:
                callee_name = target.name
                callees.add(callee_name)
                resolved_any = True
                if callee_name in self.scopes:
                    raw_context = self._derive_callee_context(
                        caller_scope.name, caller_context, call_node
                    )
                    callee_context = self._normalize_context_for_scope(callee_name, raw_context)
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
                    out.update(self.scope_returns[(callee_name, callee_context)])
                elif callee_name == "<builtin>.map":
                    if arg_values:
                        for callback in arg_values[0]:
                            if callback.kind in {FUNC_KIND, BOUND_METHOD_KIND, BOUND_CLASS_METHOD_KIND}:
                                callees.add(
                                    callback.name.split("|", 1)[0]
                                    if "|" in callback.name
                                    else callback.name
                                )
                    out.add(UNKNOWN_VALUE)
                else:
                    out.add(UNKNOWN_VALUE)

            elif target.kind == CLASS_KIND:
                class_name = target.name
                resolved_any = True
                out.add(make_instance(class_name))
                init_name = f"{class_name}.__init__"
                if init_name in self.scopes:
                    callees.add(init_name)
                    implicit_values = [{make_instance(class_name)}] + arg_values
                    raw_context = self._derive_callee_context(
                        caller_scope.name, caller_context, call_node
                    )
                    callee_context = self._normalize_context_for_scope(init_name, raw_context)
                    changed = self._bind_call_arguments(
                        init_name,
                        callee_context,
                        implicit_values,
                        kwarg_values,
                        star_arg_values=star_arg_values,
                        dynamic_kwarg_values=dynamic_kwarg_values,
                    )
                    if changed:
                        input_changed_scope_contexts.add((init_name, callee_context))

            elif target.kind == BOUND_METHOD_KIND:
                method_name, receiver_class = parse_bound_method(target)
                callees.add(method_name)
                resolved_any = True
                implicit_values = [{make_instance(receiver_class)}] + arg_values
                callee_context = self._derive_callee_context(
                    caller_scope.name, caller_context, call_node
                )
                callee_context = self._normalize_context_for_scope(method_name, callee_context)
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
                out.update(self.scope_returns[(method_name, callee_context)])

            elif target.kind == BOUND_CLASS_METHOD_KIND:
                method_name, receiver_class = parse_bound_class_method(target)
                callees.add(method_name)
                resolved_any = True
                implicit_values = [{make_class(receiver_class)}] + arg_values
                callee_context = self._derive_callee_context(
                    caller_scope.name, caller_context, call_node
                )
                callee_context = self._normalize_context_for_scope(method_name, callee_context)
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
                out.update(self.scope_returns[(method_name, callee_context)])

            elif target.kind == INSTANCE_KIND:
                called = False
                for klass in self._mro(target.name):
                    class_info = self.classes.get(klass)
                    if not class_info:
                        continue
                    call_name = class_info.methods.get("__call__")
                    if not call_name:
                        continue
                    called = True
                    resolved_any = True
                    callees.add(call_name)
                    implicit_values = [{make_instance(target.name)}] + arg_values
                    callee_context = self._derive_callee_context(
                        caller_scope.name, caller_context, call_node
                    )
                    callee_context = self._normalize_context_for_scope(call_name, callee_context)
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
                    out.update(self.scope_returns[(call_name, callee_context)])
                    break
                if not called:
                    unresolved_dynamic = True
                    out.add(UNKNOWN_VALUE)

            elif target.kind in {CONTAINER_KIND, UNKNOWN_KIND}:
                unresolved_dynamic = True
                out.add(UNKNOWN_VALUE)

        if unresolved_dynamic:
            callees.add(self._dynamic_summary_node(caller_scope, call_node))
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
        scope = self.scopes[callee_scope_name]
        changed = False
        scope_key = (
            callee_scope_name,
            self._normalize_context_for_scope(callee_scope_name, callee_context),
        )
        param_inputs = self.scope_inputs.setdefault(
            scope_key, {param: set() for param in scope.params}
        )

        for index, values in enumerate(arg_values):
            if index < len(scope.params):
                param_name = scope.params[index]
                current = param_inputs.setdefault(param_name, set())
                before = len(current)
                current.update(values)
                changed = changed or len(current) != before
            elif scope.vararg:
                current = param_inputs.setdefault(scope.vararg, set())
                before = len(current)
                current.update(values)
                changed = changed or len(current) != before

        if star_arg_values:
            pooled_star_values: Set[AbstractValue] = set()
            for values in star_arg_values:
                pooled_star_values.update(values)
            if pooled_star_values:
                for index in range(len(arg_values), len(scope.params)):
                    param_name = scope.params[index]
                    current = param_inputs.setdefault(param_name, set())
                    before = len(current)
                    current.update(pooled_star_values)
                    changed = changed or len(current) != before
                if scope.vararg:
                    current = param_inputs.setdefault(scope.vararg, set())
                    before = len(current)
                    current.update(pooled_star_values)
                    changed = changed or len(current) != before

        for kw_name, kw_values in kwarg_values.items():
            if kw_name in scope.params:
                current = param_inputs.setdefault(kw_name, set())
                before = len(current)
                current.update(kw_values)
                changed = changed or len(current) != before
            elif scope.kwarg:
                current = param_inputs.setdefault(scope.kwarg, set())
                before = len(current)
                current.update(kw_values)
                changed = changed or len(current) != before

        if dynamic_kwarg_values and scope.kwarg:
            current = param_inputs.setdefault(scope.kwarg, set())
            before = len(current)
            current.update(dynamic_kwarg_values)
            changed = changed or len(current) != before

        return changed

    def _bind_closure_values(
        self,
        callee_scope_name: str,
        callee_context: ContextKey,
        captured: Mapping[str, Set[AbstractValue]],
    ) -> bool:
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
    ) -> bool:
        if not values:
            values = {UNKNOWN_VALUE}

        if isinstance(target, ast.Name):
            if weak:
                env.setdefault(target.id, set()).update(values)
            else:
                env[target.id] = set(values)
            return False

        if isinstance(target, (ast.Tuple, ast.List)):
            changed = False
            for elt in target.elts:
                changed = self._assign_target(scope, elt, values, env, weak=True) or changed
            return changed

        if isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name):
                base_name = target.value.id
                if scope.method_self_param and base_name == scope.method_self_param:
                    owner = self._owner_class_for_scope(scope.name)
                    if owner:
                        current = self.instance_fields[owner][target.attr]
                        before = len(current)
                        current.update(values)
                        return len(current) != before
                base_values = env.get(base_name, set())
                class_values = {v.name for v in base_values if v.kind == CLASS_KIND}
                instance_values = {v.name for v in base_values if v.kind == INSTANCE_KIND}
                changed = False
                for class_name in class_values:
                    current = self.class_fields[class_name][target.attr]
                    before = len(current)
                    current.update(values)
                    changed = changed or len(current) != before
                for instance_name in instance_values:
                    current = self.instance_fields[instance_name][target.attr]
                    before = len(current)
                    current.update(values)
                    changed = changed or len(current) != before
                return changed
            return False

        if isinstance(target, ast.Subscript):
            base_values: Set[AbstractValue] = set()
            if isinstance(target.value, ast.Name):
                base_values = set(env.get(target.value.id, set()))
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
                    keyed_before = len(keyed_current)
                    keyed_current.update(values)
                    changed = changed or len(keyed_current) != keyed_before
            return changed

        return False

    def _lookup_name(
        self,
        module_name: str,
        name: str,
        env: Mapping[str, Set[AbstractValue]],
    ) -> Set[AbstractValue]:
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
        out: Set[AbstractValue] = set()
        for value in values:
            if value.kind == FUNC_KIND:
                if instance_class is not None:
                    out.add(make_bound_method(value.name, instance_class))
                else:
                    out.add(value)
                continue

            if value.kind == INSTANCE_KIND:
                descriptor_mro = self._mro(value.name)
                invoked_descriptor = False
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
                    invoked_descriptor = True
                    break
                out.add(value)
                continue

            out.add(value)
        return out

    def _resolve_attribute(
        self, base_values: Iterable[AbstractValue], attr_name: str
    ) -> Set[AbstractValue]:
        out: Set[AbstractValue] = set()

        for base_value in base_values:
            if base_value.kind == MODULE_KIND:
                module_bindings = self.module_bindings.get(base_value.name)
                if module_bindings and attr_name in module_bindings:
                    out.update(module_bindings[attr_name])
                else:
                    out.add(make_func(f"{base_value.name}.{attr_name}"))

            elif base_value.kind == CLASS_KIND:
                for klass in self._mro(base_value.name):
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
                    break

                for klass in self._mro(base_value.name):
                    class_attr_values = self.class_fields.get(klass, {}).get(attr_name, set())
                    out.update(
                        self._descriptor_bind_values(
                            class_attr_values,
                            owner_class=base_value.name,
                            instance_class=None,
                        )
                    )

            elif base_value.kind == INSTANCE_KIND:
                for klass in self._mro(base_value.name):
                    class_info = self.classes.get(klass)
                    if class_info and attr_name in class_info.methods:
                        method_name = class_info.methods[attr_name]
                        if attr_name in class_info.static_methods:
                            out.add(make_func(method_name))
                        elif attr_name in class_info.class_methods:
                            out.add(make_bound_class_method(method_name, klass))
                        else:
                            out.add(make_bound_method(method_name, base_value.name))
                        break
                for klass in self._mro(base_value.name):
                    out.update(self.instance_fields.get(klass, {}).get(attr_name, set()))
                    class_attr_values = self.class_fields.get(klass, {}).get(attr_name, set())
                    out.update(
                        self._descriptor_bind_values(
                            class_attr_values,
                            owner_class=klass,
                            instance_class=base_value.name,
                        )
                    )

        return out

    def _owner_class_for_scope(self, scope_name: str) -> Optional[str]:
        function_info = self.functions.get(scope_name)
        if not function_info:
            return None
        return function_info.owner_class

    def _mro(self, class_name: str) -> list[str]:
        if class_name in self._mro_cache:
            return list(self._mro_cache[class_name])

        class_info = self.classes.get(class_name)
        if not class_info:
            self._mro_cache[class_name] = [class_name]
            return [class_name]

        base_mros = [self._mro(base) for base in class_info.bases]
        merge_input = [list(seq) for seq in base_mros]
        merge_input.append(list(class_info.bases))

        linearized: list[str] = [class_name]
        linearized.extend(self._c3_merge(merge_input))
        self._mro_cache[class_name] = list(linearized)
        return linearized

    def _c3_merge(self, sequences: list[list[str]]) -> list[str]:
        result: list[str] = []
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
                candidate = pending[0][0]

            result.append(candidate)
            next_pending: list[list[str]] = []
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

    def _bind_import(
        self, stmt: ast.Import, module_name: str, env: Dict[str, Set[AbstractValue]]
    ) -> None:
        for alias in stmt.names:
            imported_name = alias.name
            as_name = alias.asname or imported_name.split(".")[0]
            env[as_name] = {make_module(imported_name)}

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
                env.setdefault(local_name, set()).add(make_func(f"{source_module}.{alias.name}"))

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
