"""Expression evaluation for constraint-based call graph analysis."""

from __future__ import annotations

import ast
from typing import Dict, Set, Sequence, Tuple

from .model import (
    AbstractValue,
    CONTAINER_KIND,
    ContextKey,
    ScopeInfo,
    STRING_KIND,
    UNKNOWN_VALUE,
    copy_env,
    make_func,
    make_string,
)


class _EvaluatorMixin:
    """Evaluates AST expressions to sets of abstract values."""

    def _iterable_members(self, values) -> Set[AbstractValue]:
        out: Set[AbstractValue] = set()
        for value in values:
            if value.kind == CONTAINER_KIND:
                out.update(self.container_elements.get(value.name, set()))
            else:
                out.add(value)
        return out

    def _string_constants(self, values) -> Set[str]:
        return {value.name for value in values if value.kind == STRING_KIND and value.name}

    def _subscript_keys(self, subscript: ast.Subscript) -> Set[str]:
        target = subscript.slice
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            return {target.value}
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
        comp_env = copy_env(env)
        for generator in generators:
            iter_values = self._eval_expr(
                scope, scope_context, generator.iter, comp_env, callees, input_changed_scope_contexts
            )
            iter_members = self._iterable_members(iter_values) or {UNKNOWN_VALUE}
            self._assign_target(scope, generator.target, iter_members, comp_env, weak=True)
            for cond in generator.ifs:
                self._eval_expr(
                    scope, scope_context, cond, comp_env, callees, input_changed_scope_contexts
                )
        return comp_env

    def _eval_expr(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        expr: ast.AST,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        if isinstance(expr, ast.Name):
            return set(self._lookup_name(scope.module, expr.id, env))

        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, str):
                return {make_string(expr.value)}
            return set()

        if isinstance(expr, ast.Starred):
            base_values = self._eval_expr(
                scope, scope_context, expr.value, env, callees, input_changed_scope_contexts
            )
            members = self._iterable_members(base_values)
            return members or {UNKNOWN_VALUE}

        if isinstance(expr, ast.Attribute):
            base_values = self._eval_expr(
                scope, scope_context, expr.value, env, callees, input_changed_scope_contexts
            )
            return self._resolve_attribute(base_values, expr.attr)

        if isinstance(expr, ast.Call):
            # Special-case getattr so chained calls like getattr(x, "f")() can
            # recover concrete method targets.
            if isinstance(expr.func, ast.Name) and expr.func.id == "getattr":
                target_values: Set[AbstractValue] = set()
                if expr.args:
                    obj_values = self._eval_expr(
                        scope, scope_context, expr.args[0], env, callees, input_changed_scope_contexts
                    )
                    attr_names: Set[str] = set()
                    if len(expr.args) >= 2:
                        attr_values = self._eval_expr(
                            scope, scope_context, expr.args[1], env, callees, input_changed_scope_contexts
                        )
                        for attr_value in attr_values:
                            if attr_value.kind == STRING_KIND:
                                attr_names.add(attr_value.name)
                    for attr_name in attr_names:
                        target_values.update(self._resolve_attribute(obj_values, attr_name))
                self._invoke_targets(
                    caller_scope=scope,
                    caller_context=scope_context,
                    target_values={make_func("<builtin>.getattr")},
                    call_node=expr,
                    env=env,
                    callees=callees,
                    input_changed_scope_contexts=input_changed_scope_contexts,
                )
                return target_values or {UNKNOWN_VALUE}

            target_values = self._eval_expr(
                scope, scope_context, expr.func, env, callees, input_changed_scope_contexts
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
            return self._eval_expr(
                scope, scope_context, expr.value, env, callees, input_changed_scope_contexts
            )

        if isinstance(expr, ast.Lambda):
            return {UNKNOWN_VALUE}

        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            out: Set[AbstractValue] = set()
            for item in expr.elts:
                out.update(
                    self._eval_expr(scope, scope_context, item, env, callees, input_changed_scope_contexts)
                )
            kind = (
                "Tuple" if isinstance(expr, ast.Tuple)
                else "Set" if isinstance(expr, ast.Set) else "List"
            )
            container = self._new_container(kind, scope, scope_context, expr)
            self.container_elements[container.name].update(out)
            return {container}

        if isinstance(expr, ast.Dict):
            out2: Set[AbstractValue] = set()
            key_values = []
            for key in expr.keys:
                if key is not None:
                    evaluated_key = self._eval_expr(
                        scope, scope_context, key, env, callees, input_changed_scope_contexts
                    )
                    out2.update(evaluated_key)
                    key_values.append(evaluated_key)
                else:
                    key_values.append(set())
            container = self._new_container("dict", scope, scope_context, expr)
            for index, value in enumerate(expr.values):
                evaluated_value = self._eval_expr(
                    scope, scope_context, value, env, callees, input_changed_scope_contexts
                )
                out2.update(evaluated_value)
                self.container_elements[container.name].update(evaluated_value)
                for key_name in self._string_constants(key_values[index]):
                    self.container_key_values[container.name][key_name].update(evaluated_value)
            return {container}

        if isinstance(expr, ast.ListComp):
            comp_env = self._eval_comprehension(
                scope, scope_context, expr.generators, env, callees, input_changed_scope_contexts
            )
            elements = self._eval_expr(
                scope, scope_context, expr.elt, comp_env, callees, input_changed_scope_contexts
            )
            container = self._new_container("listcomp", scope, scope_context, expr)
            self.container_elements[container.name].update(elements)
            return {container}

        if isinstance(expr, ast.SetComp):
            comp_env = self._eval_comprehension(
                scope, scope_context, expr.generators, env, callees, input_changed_scope_contexts
            )
            elements = self._eval_expr(
                scope, scope_context, expr.elt, comp_env, callees, input_changed_scope_contexts
            )
            container = self._new_container("setcomp", scope, scope_context, expr)
            self.container_elements[container.name].update(elements)
            return {container}

        if isinstance(expr, ast.DictComp):
            comp_env = self._eval_comprehension(
                scope, scope_context, expr.generators, env, callees, input_changed_scope_contexts
            )
            key_out = self._eval_expr(
                scope, scope_context, expr.key, comp_env, callees, input_changed_scope_contexts
            )
            value_out = self._eval_expr(
                scope, scope_context, expr.value, comp_env, callees, input_changed_scope_contexts
            )
            container = self._new_container("dictcomp", scope, scope_context, expr)
            self.container_elements[container.name].update(value_out)
            for key_name in self._string_constants(key_out):
                self.container_key_values[container.name][key_name].update(value_out)
            return {container}

        if isinstance(expr, ast.GeneratorExp):
            comp_env = self._eval_comprehension(
                scope, scope_context, expr.generators, env, callees, input_changed_scope_contexts
            )
            elements = self._eval_expr(
                scope, scope_context, expr.elt, comp_env, callees, input_changed_scope_contexts
            )
            container = self._new_container("generator", scope, scope_context, expr)
            self.container_elements[container.name].update(elements)
            return {container}

        if isinstance(expr, ast.IfExp):
            out3 = self._eval_expr(
                scope, scope_context, expr.body, env, callees, input_changed_scope_contexts
            )
            out3.update(
                self._eval_expr(
                    scope, scope_context, expr.orelse, env, callees, input_changed_scope_contexts
                )
            )
            return out3

        if isinstance(expr, ast.BoolOp):
            out4: Set[AbstractValue] = set()
            for value in expr.values:
                out4.update(
                    self._eval_expr(scope, scope_context, value, env, callees, input_changed_scope_contexts)
                )
            return out4

        if isinstance(expr, ast.UnaryOp):
            return self._eval_expr(
                scope, scope_context, expr.operand, env, callees, input_changed_scope_contexts
            )

        if isinstance(expr, ast.BinOp):
            out5 = self._eval_expr(
                scope, scope_context, expr.left, env, callees, input_changed_scope_contexts
            )
            out5.update(
                self._eval_expr(
                    scope, scope_context, expr.right, env, callees, input_changed_scope_contexts
                )
            )
            return out5

        if isinstance(expr, ast.Compare):
            out6 = self._eval_expr(
                scope, scope_context, expr.left, env, callees, input_changed_scope_contexts
            )
            for comparator in expr.comparators:
                out6.update(
                    self._eval_expr(
                        scope, scope_context, comparator, env, callees, input_changed_scope_contexts
                    )
                )
            return out6

        if isinstance(expr, ast.Subscript):
            base_values = self._eval_expr(
                scope, scope_context, expr.value, env, callees, input_changed_scope_contexts
            )
            slice_values = self._eval_expr(
                scope, scope_context, expr.slice, env, callees, input_changed_scope_contexts
            )
            keys = self._subscript_keys(expr)
            keys.update(self._string_constants(slice_values))
            out7: Set[AbstractValue] = set()
            for base_value in base_values:
                if base_value.kind != CONTAINER_KIND:
                    continue
                out7.update(self.container_elements.get(base_value.name, set()))
                key_map = self.container_key_values.get(base_value.name, {})
                for key_name in keys:
                    out7.update(key_map.get(key_name, set()))
            return out7

        if isinstance(expr, ast.FormattedValue):
            return self._eval_expr(
                scope, scope_context, expr.value, env, callees, input_changed_scope_contexts
            )

        if isinstance(expr, ast.JoinedStr):
            return {make_string("<joined>")}

        if isinstance(expr, ast.NamedExpr):
            values = self._eval_expr(
                scope, scope_context, expr.value, env, callees, input_changed_scope_contexts
            )
            self._assign_target(scope, expr.target, values, env)
            return values

        return set()
