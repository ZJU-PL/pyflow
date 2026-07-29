"""Dispatch and invocation of abstract call targets."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from .model import (
    AbstractValue,
    BOUND_CLASS_METHOD_KIND,
    BOUND_METHOD_KIND,
    CLASS_KIND,
    CONTAINER_KIND,
    COROUTINE_KIND,
    ContextKey,
    FUNC_KIND,
    GENERATOR_KIND,
    INSTANCE_KIND,
    NONE_KIND,
    NONE_VALUE,
    PARTIAL_KIND,
    STRING_KIND,
    ScopeInfo,
    UNKNOWN_KIND,
    UNKNOWN_VALUE,
    instance_class_name,
    join_envs,
    make_class,
    make_func,
    make_instance,
    make_module,
    make_partial,
    parse_bound_class_method,
    parse_bound_method,
    parse_instance_name,
    parse_partial,
    copy_env,
)


class _CallTargetMixin:
    """Abstract call-target dispatch."""

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
                expanded = self._iterable_members(
                    unpacked,
                    scope=caller_scope,
                    scope_context=caller_context,
                    env=env,
                    callees=callees,
                    input_changed_scope_contexts=input_changed_scope_contexts,
                )
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
                    self._register_container_read(unpacked.name)
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

        def add_direct_callee(callee_name: str) -> None:
            callees.add(callee_name)
            self._record_callsite_callee(
                caller_scope,
                caller_context,
                call_node,
                callee_name,
            )

        def discard_direct_callee(callee_name: str) -> None:
            callees.discard(callee_name)
            self._discard_callsite_callee(
                caller_scope,
                caller_context,
                call_node,
                callee_name,
            )

        unresolved_dynamic = not target_values
        unresolved_reasons: Set[str] = set()
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
                callee_name = target.name
                add_direct_callee(callee_name)
                if callee_name in {"<builtin>.setattr", "<builtin>.delattr"}:
                    if len(arg_values) >= 2:
                        attr_names = self._string_constants(arg_values[1])
                        if callee_name == "<builtin>.setattr" and len(arg_values) >= 3:
                            self._assign_reflective_attribute(
                                arg_values[0], attr_names, set(arg_values[2])
                            )
                        elif callee_name == "<builtin>.delattr":
                            self._mark_attribute_maybe_missing(
                                arg_values[0], attr_names
                            )
                    out.add(NONE_VALUE)
                elif callee_name in {
                    "<builtin>.hasattr",
                    "<builtin>.getattr",
                }:
                    out.add(UNKNOWN_VALUE)
                elif callee_name == "<builtin>.exec":
                    if arg_values:
                        merged_env = copy_env(env)
                        for code_value in arg_values[0]:
                            if code_value.kind != STRING_KIND:
                                continue
                            try:
                                parsed = ast.parse(code_value.name)
                            except SyntaxError:
                                continue
                            (
                                branch_env,
                                _branch_returns,
                                branch_calls,
                                branch_inputs,
                                _branch_instance_changed,
                                _branch_class_changed,
                                branch_globals,
                                branch_nonlocals,
                                _branch_fallthrough,
                            ) = self._process_block(
                                caller_scope,
                                caller_context,
                                parsed.body,
                                copy_env(env),
                            )
                            merged_env = join_envs(merged_env, branch_env)
                            callees.update(branch_calls)
                            input_changed_scope_contexts.update(branch_inputs)
                            for name, values in branch_globals.items():
                                if values:
                                    self._merge_value_set(
                                        merged_env.setdefault(name, set()),
                                        set(values),
                                        preserve_callables=True,
                                    )
                            for name, values in branch_nonlocals.items():
                                if values:
                                    self._merge_value_set(
                                        merged_env.setdefault(name, set()),
                                        set(values),
                                        preserve_callables=True,
                                    )
                        env.clear()
                        env.update(merged_env)
                    out.add(NONE_VALUE)
                elif callee_name == "<builtin>.eval":
                    if arg_values:
                        for code_value in arg_values[0]:
                            if code_value.kind != STRING_KIND:
                                continue
                            try:
                                parsed = ast.parse(code_value.name, mode="eval")
                            except SyntaxError:
                                continue
                            out.update(
                                self._eval_expr(
                                    caller_scope,
                                    caller_context,
                                    parsed.body,
                                    env,
                                    callees,
                                    input_changed_scope_contexts,
                                )
                            )
                    if not out:
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
                    discard_direct_callee(callee_name)
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
                    if (
                        callee_name in {"<builtin>.filter", "<builtin>.map"}
                        and not callback_values
                        and arg_values
                    ):
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
                    discard_direct_callee(callee_name)
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
                                changed = self._merge_value_set(
                                    self.container_elements[receiver_dict],
                                    set(
                                        self.container_elements.get(source_dict, set())
                                    ),
                                    preserve_callables=True,
                                )
                                if changed:
                                    self._note_container_state_changed(
                                        receiver_dict, "*"
                                    )
                                self._register_container_read(source_dict)
                                source_key_map = self.container_key_values.get(
                                    source_dict, {}
                                )
                                for key_name, key_values in source_key_map.items():
                                    self._register_container_read(
                                        source_dict, {key_name}
                                    )
                                    if self._merge_value_set(
                                        self.container_key_values[receiver_dict][
                                            key_name
                                        ],
                                        set(key_values),
                                        preserve_callables=True,
                                    ):
                                        self._note_container_state_changed(
                                            receiver_dict, key_name
                                        )
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
                    maybe_missing = False
                    for receiver in receiver_values:
                        if receiver.kind != CONTAINER_KIND:
                            continue
                        key_map = self.container_key_values.get(receiver.name, {})
                        self._register_container_read(receiver.name, key_names)
                        if key_names:
                            for key_name in key_names:
                                existing = key_map.get(key_name, set())
                                if existing:
                                    matched_values.update(existing)
                                else:
                                    maybe_missing = True
                            maybe_missing = (
                                maybe_missing
                                or self._container_key_maybe_missing(
                                    receiver.name, key_names
                                )
                            )
                        else:
                            if key_map and len(key_map) <= 8:
                                for key_values in key_map.values():
                                    matched_values.update(key_values)
                            else:
                                self._register_container_read(receiver.name)
                                matched_values.update(
                                    self.container_elements.get(receiver.name, set())
                                )
                            maybe_missing = True
                    if matched_values:
                        out.update(matched_values)
                    if len(arg_values) >= 2 and (maybe_missing or not matched_values):
                        out.update(arg_values[1])
                    elif not matched_values:
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
                    key_names = (
                        self._string_constants(arg_values[0]) if arg_values else set()
                    )
                    default_values = (
                        arg_values[1] if len(arg_values) >= 2 else {UNKNOWN_VALUE}
                    )
                    matched_values: Set[AbstractValue] = set()
                    maybe_missing = False
                    for receiver in receiver_values:
                        if receiver.kind != CONTAINER_KIND:
                            continue
                        key_map = self.container_key_values.get(receiver.name, {})
                        self._register_container_read(receiver.name, key_names)
                        if key_names:
                            for key_name in key_names:
                                existing = key_map.get(key_name, set())
                                if existing:
                                    matched_values.update(existing)
                                else:
                                    maybe_missing = True
                                    if self._merge_value_set(
                                        self.container_key_values[receiver.name][
                                            key_name
                                        ],
                                        set(default_values),
                                        preserve_callables=True,
                                    ):
                                        self._note_container_state_changed(
                                            receiver.name, key_name
                                        )
                                    if self._merge_value_set(
                                        self.container_elements[receiver.name],
                                        set(default_values),
                                        preserve_callables=True,
                                    ):
                                        self._note_container_state_changed(
                                            receiver.name, "*"
                                        )
                            maybe_missing = (
                                maybe_missing
                                or self._container_key_maybe_missing(
                                    receiver.name, key_names
                                )
                            )
                        else:
                            self._register_container_read(receiver.name)
                            matched_values.update(
                                self.container_elements.get(receiver.name, set())
                            )
                            maybe_missing = True
                    if matched_values:
                        out.update(matched_values)
                    if maybe_missing or not matched_values:
                        out.update(default_values)
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
                    key_names = (
                        self._string_constants(arg_values[0]) if arg_values else set()
                    )
                    default_values = arg_values[1] if len(arg_values) >= 2 else set()
                    popped_values: Set[AbstractValue] = set()
                    maybe_missing = False
                    for receiver in receiver_values:
                        if receiver.kind != CONTAINER_KIND:
                            continue
                        key_map = self.container_key_values.get(receiver.name, {})
                        self._register_container_read(receiver.name, key_names)
                        if key_names:
                            for key_name in key_names:
                                existing = key_map.get(key_name, set())
                                if existing:
                                    popped_values.update(existing)
                                else:
                                    maybe_missing = True
                            maybe_missing = (
                                maybe_missing
                                or self._container_key_maybe_missing(
                                    receiver.name, key_names
                                )
                            )
                        else:
                            if key_map and len(key_map) <= 8:
                                for existing in key_map.values():
                                    popped_values.update(existing)
                            else:
                                self._register_container_read(receiver.name)
                                popped_values.update(
                                    self.container_elements.get(receiver.name, set())
                                )
                            maybe_missing = True
                    if popped_values:
                        out.update(popped_values)
                    if default_values and (maybe_missing or not popped_values):
                        out.update(default_values)
                    elif not popped_values and not default_values:
                        out.add(UNKNOWN_VALUE)
                else:
                    last_segment = callee_name.rsplit(".", 1)[-1]
                    if last_segment and last_segment[0].isupper():
                        out.add(make_instance(callee_name))
                        continue
                    out.add(UNKNOWN_VALUE)

            elif target.kind == CLASS_KIND:
                class_name = target.name
                class_info = self.classes.get(class_name)
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
                raw_context = self._derive_callee_context(
                    caller_scope.name, caller_context, call_node
                )
                init_name: Optional[str] = None
                new_name: Optional[str] = None
                constructed_values: Set[AbstractValue] = set()
                init_receivers: Set[AbstractValue] = {instance_value}
                metaclass_results: Set[AbstractValue] = set()
                if (
                    class_info is not None
                    and class_info.metaclass
                    and class_info.metaclass != "type"
                ):
                    metaclass_call = f"{class_info.metaclass}.__call__"
                    if metaclass_call in self.scopes:
                        metaclass_results.update(
                            self._invoke_with_implicit_receiver(
                                metaclass_call,
                                {make_class(class_name)},
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
                use_default_constructor = not metaclass_results or any(
                    value.kind == UNKNOWN_KIND for value in metaclass_results
                )
                constructed_values.update(metaclass_results)
                class_order = self._class_lookup_order(class_name)
                for klass in class_order:
                    new_candidate = f"{klass}.__new__"
                    if new_name is None:
                        if new_candidate in self.scopes:
                            new_name = new_candidate
                        elif klass not in self.classes and "." in klass:
                            new_name = new_candidate
                    candidate = f"{klass}.__init__"
                    if candidate in self.scopes:
                        init_name = candidate
                        break
                    if klass not in self.classes and "." in klass:
                        init_name = candidate
                        break

                if use_default_constructor and new_name is not None:
                    add_direct_callee(new_name)
                    callee_context = self._normalize_context_for_scope(
                        new_name, raw_context
                    )
                    if new_name in self.scopes:
                        changed = self._bind_call_arguments(
                            new_name,
                            callee_context,
                            [{make_class(class_name)}] + arg_values,
                            kwarg_values,
                            star_arg_values=star_arg_values,
                            dynamic_kwarg_values=dynamic_kwarg_values,
                        )
                        if changed:
                            input_changed_scope_contexts.add((new_name, callee_context))
                        if (
                            new_name,
                            callee_context,
                        ) not in self._analyzed_scope_contexts:
                            input_changed_scope_contexts.add((new_name, callee_context))
                        self._add_call_dependency(
                            new_name, callee_context, caller_scope_key
                        )
                        new_returns = set(
                            self.scope_returns[(new_name, callee_context)]
                        )
                        if new_returns:
                            constructed_values = set(new_returns)
                            matching_receivers = {
                                value
                                for value in new_returns
                                if value.kind == INSTANCE_KIND
                                and self._matches_type_values(
                                    value, {make_class(class_name)}
                                )
                            }
                            if matching_receivers:
                                init_receivers = matching_receivers
                            elif any(
                                value.kind == UNKNOWN_KIND for value in new_returns
                            ):
                                init_receivers = {instance_value}
                            else:
                                init_receivers = set()
                        self._apply_callee_side_effects(new_name, callee_context, env)

                if use_default_constructor:
                    constructed_values.add(instance_value)
                out.update(constructed_values)
                if use_default_constructor and init_name is not None and init_receivers:
                    add_direct_callee(init_name)
                    implicit_values = [init_receivers] + arg_values
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
                        self._add_call_dependency(
                            init_name, callee_context, caller_scope_key
                        )
                        self._apply_callee_side_effects(init_name, callee_context, env)

            elif target.kind == BOUND_METHOD_KIND:
                method_name, receiver_instance = parse_bound_method(target)
                add_direct_callee(method_name)
                if method_name not in self.scopes:
                    unresolved_dynamic = True
                    unresolved_reasons.add("external_bound_method")
                    out.add(UNKNOWN_VALUE)
                    continue
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
                function_info = self.functions.get(method_name)
                if function_info and function_info.is_async:
                    out.add(
                        self._suspended_value(
                            COROUTINE_KIND, method_name, callee_context
                        )
                    )
                    continue
                if function_info and function_info.is_generator:
                    out.add(
                        self._suspended_value(
                            GENERATOR_KIND, method_name, callee_context
                        )
                    )
                    continue
                self._add_call_dependency(method_name, callee_context, caller_scope_key)
                out.update(self.scope_returns[(method_name, callee_context)])
                self._apply_callee_side_effects(method_name, callee_context, env)

            elif target.kind == BOUND_CLASS_METHOD_KIND:
                method_name, receiver_class = parse_bound_class_method(target)
                add_direct_callee(method_name)
                if method_name not in self.scopes:
                    unresolved_dynamic = True
                    unresolved_reasons.add("external_bound_class_method")
                    out.add(UNKNOWN_VALUE)
                    continue
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
                function_info = self.functions.get(method_name)
                if function_info and function_info.is_async:
                    out.add(
                        self._suspended_value(
                            COROUTINE_KIND, method_name, callee_context
                        )
                    )
                    continue
                if function_info and function_info.is_generator:
                    out.add(
                        self._suspended_value(
                            GENERATOR_KIND, method_name, callee_context
                        )
                    )
                    continue
                self._add_call_dependency(method_name, callee_context, caller_scope_key)
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
                    add_direct_callee(call_name)
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
                    function_info = self.functions.get(call_name)
                    if function_info and function_info.is_async:
                        out.add(
                            self._suspended_value(
                                COROUTINE_KIND, call_name, callee_context
                            )
                        )
                        if target_class_name not in self._invalid_mro_classes:
                            break
                        continue
                    if function_info and function_info.is_generator:
                        out.add(
                            self._suspended_value(
                                GENERATOR_KIND, call_name, callee_context
                            )
                        )
                        if target_class_name not in self._invalid_mro_classes:
                            break
                        continue
                    self._add_call_dependency(
                        call_name, callee_context, caller_scope_key
                    )
                    out.update(self.scope_returns[(call_name, callee_context)])
                    self._apply_callee_side_effects(call_name, callee_context, env)
                    if target_class_name not in self._invalid_mro_classes:
                        break
                if not called:
                    unresolved_dynamic = True
                    unresolved_reasons.add("instance_without_call")
                    out.add(UNKNOWN_VALUE)

            elif target.kind == PARTIAL_KIND:
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
                if target.kind != NONE_KIND:
                    unresolved_dynamic = True
                    unresolved_reasons.add("unknown_callable")
                out.add(UNKNOWN_VALUE)

        if unresolved_dynamic and not deferred_parameter_call:
            reasons = unresolved_reasons or {"unresolved"}
            for reason in sorted(reasons):
                add_direct_callee(
                    self._dynamic_summary_node_with_reason(
                        caller_scope, call_node, reason
                    )
                )
                self.solver_stats.dynamic_summary_edges += 1
            out.add(UNKNOWN_VALUE)

        return out
