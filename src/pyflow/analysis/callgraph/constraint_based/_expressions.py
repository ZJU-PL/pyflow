"""Expression semantics for constraint-based call graph analysis."""

from __future__ import annotations

import ast
from itertools import product
from typing import Dict, Set, Sequence, Tuple, List

from .model import (
    AbstractValue,
    BOOL_VALUE,
    CONTAINER_KIND,
    COROUTINE_KIND,
    GENERATOR_KIND,
    ContextKey,
    GLOBAL_CONTEXT,
    INSTANCE_KIND,
    NONE_VALUE,
    ScopeInfo,
    STRING_KIND,
    UNKNOWN_VALUE,
    make_bound_method,
    copy_env,
    make_class,
    make_func,
    make_string,
)


class _ExpressionAnalysisMixin:
    """Evaluates AST expressions to sets of abstract values."""

    def _iterable_members(
        self,
        values,
        scope: ScopeInfo | None = None,
        scope_context: ContextKey | None = None,
        env: Dict[str, Set[AbstractValue]] | None = None,
        callees: Set[str] | None = None,
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]] | None = None,
    ) -> Set[AbstractValue]:
        """Approximate iteration by expanding container element sets."""
        out: Set[AbstractValue] = set()
        for value in values:
            if value.kind == CONTAINER_KIND:
                self._register_container_dependency(value.name, "*")
                out.update(self.container_elements.get(value.name, set()))
            elif (
                value.kind == GENERATOR_KIND
                and scope is not None
                and scope_context is not None
                and env is not None
                and input_changed_scope_contexts is not None
            ):
                out.update(
                    self._materialize_suspended_values(
                        {value},
                        expected_kind=GENERATOR_KIND,
                        caller_scope=scope,
                        caller_context=scope_context,
                        env=env,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )
                )
            else:
                out.add(value)
        return out

    def _string_constants(self, values) -> Set[str]:
        """Extract concrete string-like keys from abstract value sets."""
        return {
            value.name for value in values if value.kind == STRING_KIND and value.name
        }

    def _combine_string_values(
        self, left: Set[AbstractValue], right: Set[AbstractValue]
    ) -> Set[AbstractValue]:
        """Build concrete string abstractions when both operands are string-like."""
        left_strings = self._string_constants(left)
        right_strings = self._string_constants(right)
        return {
            make_string(f"{lhs}{rhs}") for lhs in left_strings for rhs in right_strings
        }

    def _subscript_keys(self, subscript: ast.Subscript) -> Set[str]:
        """Return normalized key tokens used in container key-value maps."""
        target = subscript.slice
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            return {target.value}
        if isinstance(target, ast.Constant) and isinstance(target.value, int):
            return {f"#{target.value}"}
        if (
            isinstance(target, ast.UnaryOp)
            and isinstance(target.op, ast.USub)
            and isinstance(target.operand, ast.Constant)
            and isinstance(target.operand.value, int)
        ):
            return {f"#{-target.operand.value}"}
        return set()

    def _eval_comprehension(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        generators: Sequence[ast.comprehension],
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Dict[str, Set[AbstractValue]]:
        """Evaluate generator clauses and return resulting comprehension env."""
        comp_env = copy_env(env)
        for generator in generators:
            iter_values = self._eval_expr(
                scope,
                scope_context,
                generator.iter,
                comp_env,
                callees,
                input_changed_scope_contexts,
            )
            iter_members = self._iterable_members(
                iter_values,
                scope=scope,
                scope_context=scope_context,
                env=comp_env,
                callees=callees,
                input_changed_scope_contexts=input_changed_scope_contexts,
            ) or {UNKNOWN_VALUE}
            self._assign_target(
                scope, generator.target, iter_members, comp_env, weak=True
            )
            for cond in generator.ifs:
                condition_values = self._eval_expr(
                    scope,
                    scope_context,
                    cond,
                    comp_env,
                    callees,
                    input_changed_scope_contexts,
                )
                self._eval_truth_test(
                    scope,
                    scope_context,
                    cond,
                    condition_values,
                    comp_env,
                    callees,
                    input_changed_scope_contexts,
                )
        return comp_env

    def _eval_truth_test(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        expression: ast.AST,
        values: Set[AbstractValue],
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> None:
        """Record Python's implicit ``__bool__``/``__len__`` protocol calls."""
        for value in values:
            truth_targets = self._resolve_attribute({value}, "__bool__")
            if not truth_targets:
                truth_targets = self._resolve_attribute({value}, "__len__")
            if not truth_targets:
                continue
            synthetic_call = ast.copy_location(
                ast.Call(
                    func=ast.Name(id="bool", ctx=ast.Load()),
                    args=[],
                    keywords=[],
                ),
                expression,
            )
            self._invoke_targets(
                caller_scope=scope,
                caller_context=scope_context,
                target_values=truth_targets,
                call_node=synthetic_call,
                env=env,
                callees=callees,
                input_changed_scope_contexts=input_changed_scope_contexts,
            )

    def _eval_expr(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        expr: ast.AST,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        """
        Evaluate expression into a set of abstract values.

        This function is the value-transfer core used by `_process_block`.
        It is intentionally monotone: each evaluation may discover additional
        abstract targets but never retract prior global solver knowledge.
        """
        if isinstance(expr, ast.Name):
            return set(self._lookup_name(scope.module, expr.id, env))

        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, bool):
                return {BOOL_VALUE}
            if isinstance(expr.value, str):
                return {make_string(expr.value)}
            if isinstance(expr.value, int):
                return {make_string(f"#{expr.value}")}
            if expr.value is None:
                return {NONE_VALUE}
            return set()

        if isinstance(expr, ast.Starred):
            base_values = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            members = self._iterable_members(
                base_values,
                scope=scope,
                scope_context=scope_context,
                env=env,
                callees=callees,
                input_changed_scope_contexts=input_changed_scope_contexts,
            )
            return members or {UNKNOWN_VALUE}

        if isinstance(expr, ast.Attribute):
            base_values = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            resolved = self._resolve_attribute(base_values, expr.attr)
            instance_values = {
                value for value in base_values if value.kind == INSTANCE_KIND
            }
            if instance_values:
                # Attribute access itself is dynamically dispatchable in
                # Python.  Preserve ordinary lookup results, but also include
                # values returned by a user-defined __getattribute__.  A
                # user-defined __getattr__ participates when ordinary lookup
                # may fail.  This is deliberately additive: the call graph is
                # a may-graph, so hooks never remove statically known targets.
                hook_names = ["__getattribute__"]
                if not resolved or self._attribute_maybe_missing(
                    instance_values, expr.attr
                ):
                    hook_names.append("__getattr__")
                for hook_name in hook_names:
                    hook_targets = self._resolve_attribute(instance_values, hook_name)
                    if not hook_targets:
                        continue
                    hook_call = ast.copy_location(
                        ast.Call(
                            func=expr,
                            args=[ast.Constant(value=expr.attr)],
                            keywords=[],
                        ),
                        expr,
                    )
                    resolved.update(
                        self._invoke_targets(
                            caller_scope=scope,
                            caller_context=scope_context,
                            target_values=hook_targets,
                            call_node=hook_call,
                            env=env,
                            callees=callees,
                            input_changed_scope_contexts=input_changed_scope_contexts,
                        )
                    )
            if (
                isinstance(expr.value, ast.Name)
                and expr.value.id == scope.method_self_param
            ):
                owner_class = self._owner_class_for_scope(scope.name)
                if owner_class:
                    owner_info = self.classes.get(owner_class)
                    owner_method = (
                        owner_info.methods.get(expr.attr) if owner_info else None
                    )
                    if owner_method:
                        for base_value in base_values:
                            if base_value.kind == INSTANCE_KIND:
                                resolved.add(
                                    make_bound_method(owner_method, base_value.name)
                                )
            return resolved

        if isinstance(expr, ast.Call):
            # Model zero-arg super() as an abstract class receiver rooted at
            # the lexical owner class so super().__init__()/super().m() can
            # resolve through base classes.
            if isinstance(expr.func, ast.Name) and expr.func.id == "super":
                self._invoke_targets(
                    caller_scope=scope,
                    caller_context=scope_context,
                    target_values={make_func("<builtin>.super")},
                    call_node=expr,
                    env=env,
                    callees=callees,
                    input_changed_scope_contexts=input_changed_scope_contexts,
                )
                owner_class = self._owner_class_for_scope(scope.name)
                if len(expr.args) >= 2:
                    type_values = self._eval_expr(
                        scope,
                        scope_context,
                        expr.args[0],
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    obj_values = self._eval_expr(
                        scope,
                        scope_context,
                        expr.args[1],
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    candidate_classes = [
                        value.name for value in type_values if value.kind == "class"
                    ]
                    if obj_values:
                        for candidate in candidate_classes:
                            receiver = self._super_receiver_value(candidate, obj_values)
                            if receiver:
                                return receiver
                    return {UNKNOWN_VALUE}
                receiver_values: Set[AbstractValue] = set()
                if scope.method_self_param:
                    receiver_values.update(env.get(scope.method_self_param, set()))
                if scope.method_cls_param:
                    receiver_values.update(env.get(scope.method_cls_param, set()))
                if owner_class and receiver_values:
                    receiver = self._super_receiver_value(owner_class, receiver_values)
                    if receiver:
                        return receiver
                if owner_class:
                    class_order = self._class_lookup_order(owner_class)
                    if len(class_order) >= 2:
                        return {make_class(class_order[1])}
                return {UNKNOWN_VALUE}

            # Special-case getattr so chained calls like getattr(x, "f")() can
            # recover concrete method targets.
            if isinstance(expr.func, ast.Name) and expr.func.id == "getattr":
                target_values: Set[AbstractValue] = set()
                default_values: Set[AbstractValue] = set()
                maybe_missing = False
                if expr.args:
                    obj_values = self._eval_expr(
                        scope,
                        scope_context,
                        expr.args[0],
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    attr_names: Set[str] = set()
                    if len(expr.args) >= 2:
                        attr_values = self._eval_expr(
                            scope,
                            scope_context,
                            expr.args[1],
                            env,
                            callees,
                            input_changed_scope_contexts,
                        )
                        for attr_value in attr_values:
                            if attr_value.kind == STRING_KIND:
                                attr_names.add(attr_value.name)
                    for attr_name in attr_names:
                        target_values.update(
                            self._resolve_attribute(obj_values, attr_name)
                        )
                        maybe_missing = (
                            maybe_missing
                            or self._attribute_maybe_missing(obj_values, attr_name)
                            or any(
                                not self._resolve_attribute({obj_value}, attr_name)
                                for obj_value in obj_values
                            )
                        )
                    if len(expr.args) >= 3:
                        default_values = self._eval_expr(
                            scope,
                            scope_context,
                            expr.args[2],
                            env,
                            callees,
                            input_changed_scope_contexts,
                        )
                        if not attr_names:
                            maybe_missing = True
                self._invoke_targets(
                    caller_scope=scope,
                    caller_context=scope_context,
                    target_values={make_func("<builtin>.getattr")},
                    call_node=expr,
                    env=env,
                    callees=callees,
                    input_changed_scope_contexts=input_changed_scope_contexts,
                )
                if target_values:
                    if default_values and maybe_missing:
                        return target_values | default_values
                    return target_values
                if default_values:
                    return default_values
                return {UNKNOWN_VALUE}

            func_qualname = self._expr_qualname(expr.func)
            if func_qualname in {"cast", "typing.cast"} and len(expr.args) >= 2:
                cast_values = self._eval_expr(
                    scope,
                    scope_context,
                    expr.args[1],
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                target_types = self._resolve_type_expression_values(
                    expr.args[0], scope.module, env=env
                )
                if target_types:
                    return self._refine_values_with_type_filter(
                        cast_values, target_types, True
                    )
                return cast_values or {UNKNOWN_VALUE}

            if isinstance(expr.func, ast.Call) and expr.args:
                generic_names, dispatch_types = (
                    self._singledispatch_registration_payload(
                        expr.func,
                        scope,
                        scope_context,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                )
                if generic_names:
                    callback_values = self._eval_expr(
                        scope,
                        scope_context,
                        expr.args[0],
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    for generic_name in generic_names:
                        for callback in callback_values:
                            if callback.kind != "func":
                                continue
                            resolved_types = (
                                dispatch_types
                                or self._singledispatch_registration_types(
                                    callback.name
                                )
                            )
                            self._register_singledispatch_implementation(
                                generic_name,
                                callback.name,
                                resolved_types,
                            )
                    if callback_values:
                        return callback_values

                registry_owner_values, registry_keys = self._registry_binding_payload(
                    expr.func,
                    scope,
                    scope_context,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                if registry_owner_values and registry_keys:
                    callback_values = self._eval_expr(
                        scope,
                        scope_context,
                        expr.args[0],
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    self._assign_reflective_attribute(
                        registry_owner_values, registry_keys, callback_values
                    )
                    if callback_values:
                        return callback_values

            target_values = self._eval_expr(
                scope,
                scope_context,
                expr.func,
                env,
                callees,
                input_changed_scope_contexts,
            )
            return self._invoke_targets(
                caller_scope=scope,
                caller_context=scope_context,
                target_values=target_values,
                call_node=expr,
                env=env,
                callees=callees,
                input_changed_scope_contexts=input_changed_scope_contexts,
            )

        if isinstance(expr, ast.Await):
            awaited_values = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            materialized = self._materialize_suspended_values(
                awaited_values,
                expected_kind=COROUTINE_KIND,
                caller_scope=scope,
                caller_context=scope_context,
                env=env,
                input_changed_scope_contexts=input_changed_scope_contexts,
            )
            if materialized:
                return materialized
            return awaited_values or {UNKNOWN_VALUE}

        if isinstance(expr, ast.Lambda):
            line = getattr(expr, "lineno", -1)
            col = getattr(expr, "col_offset", -1)
            lambda_qualname = self.lambda_functions_by_node.get(id(expr))
            if not lambda_qualname:
                lambda_qualname = self.lambda_functions.get((scope.name, line, col))
            if not lambda_qualname:
                return {UNKNOWN_VALUE}

            if self.options.context_sensitive and self.options.context_depth > 0:
                callee_context = self._normalize_context_for_scope(
                    lambda_qualname,
                    (
                        (*scope_context, f"lambda@{scope.name}:{line}:{col}")[
                            -self.options.context_depth :
                        ]
                    ),
                )
            else:
                callee_context = GLOBAL_CONTEXT

            function_info = self.functions.get(lambda_qualname)
            if function_info:
                captured = {
                    name: set(env.get(name, set()))
                    for name in function_info.closure_vars
                }
                if function_info.closure_vars and self._bind_closure_values(
                    lambda_qualname,
                    callee_context,
                    captured,
                    closure_origin=(scope.name, scope_context),
                ):
                    input_changed_scope_contexts.add((lambda_qualname, callee_context))

            return {make_func(lambda_qualname)}

        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            out: Set[AbstractValue] = set()
            indexed_values: List[Set[AbstractValue]] = []
            for item in expr.elts:
                values = self._eval_expr(
                    scope,
                    scope_context,
                    item,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                indexed_values.append(set(values))
                out.update(values)
            kind = (
                "Tuple"
                if isinstance(expr, ast.Tuple)
                else "Set" if isinstance(expr, ast.Set) else "List"
            )
            container = self._new_container(kind, scope, scope_context, expr)
            self._merge_value_set(
                self.container_elements[container.name],
                set(out),
                preserve_callables=True,
            )
            if isinstance(expr, (ast.List, ast.Tuple)):
                for index, values in enumerate(indexed_values):
                    if values:
                        self._merge_value_set(
                            self.container_key_values[container.name][f"#{index}"],
                            set(values),
                            preserve_callables=True,
                        )
            return {container}

        if isinstance(expr, ast.Dict):
            out2: Set[AbstractValue] = set()
            key_values = []
            for key in expr.keys:
                if key is not None:
                    evaluated_key = self._eval_expr(
                        scope,
                        scope_context,
                        key,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    out2.update(evaluated_key)
                    key_values.append(evaluated_key)
                else:
                    key_values.append(set())
            container = self._new_container("dict", scope, scope_context, expr)
            for index, value in enumerate(expr.values):
                evaluated_value = self._eval_expr(
                    scope,
                    scope_context,
                    value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                out2.update(evaluated_value)
                self._merge_value_set(
                    self.container_elements[container.name],
                    set(evaluated_value),
                    preserve_callables=True,
                )
                for key_name in self._string_constants(key_values[index]):
                    self._merge_value_set(
                        self.container_key_values[container.name][key_name],
                        set(evaluated_value),
                        preserve_callables=True,
                    )
                if isinstance(expr.keys[index], ast.Constant) and isinstance(
                    expr.keys[index].value, int
                ):
                    self._merge_value_set(
                        self.container_key_values[container.name][
                            f"#{expr.keys[index].value}"
                        ],
                        set(evaluated_value),
                        preserve_callables=True,
                    )
            return {container}

        if isinstance(expr, ast.ListComp):
            comp_env = self._eval_comprehension(
                scope,
                scope_context,
                expr.generators,
                env,
                callees,
                input_changed_scope_contexts,
            )
            elements = self._eval_expr(
                scope,
                scope_context,
                expr.elt,
                comp_env,
                callees,
                input_changed_scope_contexts,
            )
            container = self._new_container("listcomp", scope, scope_context, expr)
            self._merge_value_set(
                self.container_elements[container.name],
                set(elements),
                preserve_callables=True,
            )
            return {container}

        if isinstance(expr, ast.SetComp):
            comp_env = self._eval_comprehension(
                scope,
                scope_context,
                expr.generators,
                env,
                callees,
                input_changed_scope_contexts,
            )
            elements = self._eval_expr(
                scope,
                scope_context,
                expr.elt,
                comp_env,
                callees,
                input_changed_scope_contexts,
            )
            container = self._new_container("setcomp", scope, scope_context, expr)
            self._merge_value_set(
                self.container_elements[container.name],
                set(elements),
                preserve_callables=True,
            )
            return {container}

        if isinstance(expr, ast.DictComp):
            comp_env = self._eval_comprehension(
                scope,
                scope_context,
                expr.generators,
                env,
                callees,
                input_changed_scope_contexts,
            )
            key_out = self._eval_expr(
                scope,
                scope_context,
                expr.key,
                comp_env,
                callees,
                input_changed_scope_contexts,
            )
            value_out = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                comp_env,
                callees,
                input_changed_scope_contexts,
            )
            container = self._new_container("dictcomp", scope, scope_context, expr)
            self._merge_value_set(
                self.container_elements[container.name],
                set(value_out),
                preserve_callables=True,
            )
            for key_name in self._string_constants(key_out):
                self._merge_value_set(
                    self.container_key_values[container.name][key_name],
                    set(value_out),
                    preserve_callables=True,
                )
            return {container}

        if isinstance(expr, ast.GeneratorExp):
            comp_env = self._eval_comprehension(
                scope,
                scope_context,
                expr.generators,
                env,
                callees,
                input_changed_scope_contexts,
            )
            elements = self._eval_expr(
                scope,
                scope_context,
                expr.elt,
                comp_env,
                callees,
                input_changed_scope_contexts,
            )
            container = self._new_container("generator", scope, scope_context, expr)
            self._merge_value_set(
                self.container_elements[container.name],
                set(elements),
                preserve_callables=True,
            )
            return {container}

        if isinstance(expr, ast.IfExp):
            condition_values = self._eval_expr(
                scope,
                scope_context,
                expr.test,
                env,
                callees,
                input_changed_scope_contexts,
            )
            self._eval_truth_test(
                scope,
                scope_context,
                expr.test,
                condition_values,
                env,
                callees,
                input_changed_scope_contexts,
            )
            truth = self._static_truthiness(expr.test, env)
            out3: Set[AbstractValue] = set()
            if truth is not False:
                out3.update(
                    self._eval_expr(
                        scope,
                        scope_context,
                        expr.body,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                )
            if truth is not True:
                out3.update(
                    self._eval_expr(
                        scope,
                        scope_context,
                        expr.orelse,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                )
            return out3

        if isinstance(expr, ast.BoolOp):
            out4: Set[AbstractValue] = set()
            last_index = len(expr.values) - 1
            for index, value in enumerate(expr.values):
                value_out = self._eval_expr(
                    scope,
                    scope_context,
                    value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                if index == last_index:
                    out4.update(value_out)
                    break
                self._eval_truth_test(
                    scope,
                    scope_context,
                    value,
                    value_out,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                truth = self._static_truthiness(value, env)
                if isinstance(expr.op, ast.And):
                    if truth is not True:
                        out4.update(value_out)
                    if truth is False:
                        break
                else:
                    if truth is not False:
                        out4.update(value_out)
                    if truth is True:
                        break
            return out4

        if isinstance(expr, ast.UnaryOp):
            operand_values = self._eval_expr(
                scope,
                scope_context,
                expr.operand,
                env,
                callees,
                input_changed_scope_contexts,
            )
            if isinstance(expr.op, ast.Not):
                self._eval_truth_test(
                    scope,
                    scope_context,
                    expr.operand,
                    operand_values,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                return {BOOL_VALUE}
            return operand_values

        if isinstance(expr, ast.BinOp):
            left_values = self._eval_expr(
                scope,
                scope_context,
                expr.left,
                env,
                callees,
                input_changed_scope_contexts,
            )
            right_values = self._eval_expr(
                scope,
                scope_context,
                expr.right,
                env,
                callees,
                input_changed_scope_contexts,
            )
            out5 = set(left_values)
            out5.update(right_values)
            if isinstance(expr.op, ast.Add):
                out5.update(self._combine_string_values(left_values, right_values))
            return out5

        if isinstance(expr, ast.Compare):
            out6 = self._eval_expr(
                scope,
                scope_context,
                expr.left,
                env,
                callees,
                input_changed_scope_contexts,
            )
            for comparator in expr.comparators:
                out6.update(
                    self._eval_expr(
                        scope,
                        scope_context,
                        comparator,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                )
            return out6

        if isinstance(expr, ast.Subscript):
            base_values = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            slice_values = self._eval_expr(
                scope,
                scope_context,
                expr.slice,
                env,
                callees,
                input_changed_scope_contexts,
            )
            keys = self._subscript_keys(expr)
            keys.update(self._string_constants(slice_values))
            out7: Set[AbstractValue] = set()
            for base_value in base_values:
                if base_value.kind != CONTAINER_KIND:
                    if keys:
                        for key_name in keys:
                            out7.update(self._resolve_attribute({base_value}, key_name))
                    continue
                if keys:
                    for key_name in keys:
                        self._register_container_dependency(base_value.name, key_name)
                else:
                    self._register_container_dependency(base_value.name, "*")
                key_map = self.container_key_values.get(base_value.name, {})
                if isinstance(expr.slice, ast.Slice):
                    # Preserve positional precision for slices by creating a
                    # dedicated abstract container representing the slice view.
                    self._register_container_dependency(base_value.name, "*")
                    index_keys = sorted(
                        [k for k in key_map if k.startswith("#")],
                        key=lambda k: int(k[1:]),
                    )
                    index_values = [set(key_map[key]) for key in index_keys]
                    start = None
                    stop = None
                    step = None
                    if isinstance(expr.slice.lower, ast.Constant) and isinstance(
                        expr.slice.lower.value, int
                    ):
                        start = expr.slice.lower.value
                    if isinstance(expr.slice.upper, ast.Constant) and isinstance(
                        expr.slice.upper.value, int
                    ):
                        stop = expr.slice.upper.value
                    if isinstance(expr.slice.step, ast.Constant) and isinstance(
                        expr.slice.step.value, int
                    ):
                        step = expr.slice.step.value
                    sliced_values = index_values[slice(start, stop, step)]
                    slice_container = self._new_container(
                        "slice", scope, scope_context, expr
                    )
                    for index, values in enumerate(sliced_values):
                        self._merge_value_set(
                            self.container_elements[slice_container.name],
                            set(values),
                            preserve_callables=True,
                        )
                        self._merge_value_set(
                            self.container_key_values[slice_container.name][
                                f"#{index}"
                            ],
                            set(values),
                            preserve_callables=True,
                        )
                    if not sliced_values:
                        self._merge_value_set(
                            self.container_elements[slice_container.name],
                            set(self.container_elements.get(base_value.name, set())),
                            preserve_callables=True,
                        )
                    out7.add(slice_container)
                    continue
                if keys:
                    matched: Set[AbstractValue] = set()
                    for key_name in keys:
                        matched.update(key_map.get(key_name, set()))
                    if matched:
                        out7.update(matched)
                        continue
                    self._register_container_dependency(base_value.name, "*")
                out7.update(self.container_elements.get(base_value.name, set()))
            return out7

        if isinstance(expr, ast.FormattedValue):
            return self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )

        if isinstance(expr, ast.JoinedStr):
            pieces: List[List[str]] = []
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    pieces.append([value.value])
                    continue
                evaluated = self._eval_expr(
                    scope,
                    scope_context,
                    value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                strings = sorted(self._string_constants(evaluated))
                if not strings:
                    return {make_string("<joined>")}
                pieces.append(strings)
            if not pieces:
                return {make_string("")}
            combination_count = 1
            combination_cap = max(1, int(self.options.max_values_per_binding))
            for strings in pieces:
                combination_count *= len(strings)
                if combination_count > combination_cap:
                    return {make_string("<joined>")}
            return {make_string("".join(parts)) for parts in product(*pieces)}

        if isinstance(expr, ast.NamedExpr):
            values = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            self._assign_target(scope, expr.target, values, env)
            return values

        if isinstance(expr, ast.Yield):
            if expr.value is None:
                return {UNKNOWN_VALUE}
            return self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )

        if isinstance(expr, ast.YieldFrom):
            yielded_values = self._eval_expr(
                scope,
                scope_context,
                expr.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            iterated = self._iterable_members(
                yielded_values,
                scope=scope,
                scope_context=scope_context,
                env=env,
                callees=callees,
                input_changed_scope_contexts=input_changed_scope_contexts,
            )
            return iterated or yielded_values or {UNKNOWN_VALUE}

        return set()
