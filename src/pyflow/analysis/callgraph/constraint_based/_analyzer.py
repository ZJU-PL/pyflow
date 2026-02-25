"""Fixpoint loop and block/scope analysis for constraint-based call graph analysis."""

from __future__ import annotations

import ast
from collections import deque
from typing import Dict, Set, Sequence, Tuple

from .model import (
    AbstractValue,
    ContextKey,
    GLOBAL_CONTEXT,
    ScopeInfo,
    ScopeResult,
    UNKNOWN_VALUE,
    copy_env,
    join_envs,
    make_class,
    make_func,
    make_module,
)


class _AnalyzerMixin:
    """Fixpoint iteration and per-scope/block analysis."""

    def _run_fixpoint(self) -> None:
        queue: deque[tuple[str, ContextKey]] = deque(
            (scope_name, self._root_context()) for scope_name in self.scopes
        )
        in_queue = set(queue)
        iterations = 0
        max_iterations = max(256, len(self.scopes) * 256)

        while queue and iterations < max_iterations:
            iterations += 1
            scope_name, scope_context = queue.popleft()
            scope_context = self._normalize_context_for_scope(scope_name, scope_context)
            in_queue.discard((scope_name, scope_context))
            scope = self.scopes[scope_name]
            result = self._analyze_scope(scope, scope_context)
            scope_ctx_key = (scope_name, scope_context)

            changed = False
            if not result.returns.issubset(self.scope_returns[scope_ctx_key]):
                self.scope_returns[scope_ctx_key].update(result.returns)
                changed = True
            if not result.callees.issubset(self.scope_callees[scope_ctx_key]):
                self.scope_callees[scope_ctx_key].update(result.callees)
                changed = True
            if result.module_binding_changed or result.instance_field_changed:
                changed = True

            for callee_scope, callee_context in result.input_changed_scope_contexts:
                normalized = self._normalize_context_for_scope(callee_scope, callee_context)
                key = (callee_scope, normalized)
                if key not in in_queue:
                    queue.append(key)
                    in_queue.add(key)

            if changed:
                for candidate in self._known_scope_contexts():
                    if candidate not in in_queue:
                        queue.append(candidate)
                        in_queue.add(candidate)

    def _analyze_scope(self, scope: ScopeInfo, scope_context: ContextKey) -> ScopeResult:
        env = copy_env(self.module_bindings.get(scope.module, {}))
        scope_ctx_key = (scope.name, scope_context)
        param_inputs = self.scope_inputs.setdefault(
            scope_ctx_key,
            {
                **{param: set() for param in scope.params},
                **{name: set() for name in scope.closure_vars},
            },
        )
        for param in scope.params:
            env[param] = set(param_inputs.get(param, set()))
        for closure_var in scope.closure_vars:
            captured_values = set(param_inputs.get(closure_var, set()))
            if captured_values:
                env[closure_var] = captured_values

        callees: Set[str] = set()
        returns: Set[AbstractValue] = set()
        input_changed_scope_contexts: Set[tuple[str, ContextKey]] = set()
        instance_field_changed = False

        env, block_returns, block_callees, block_inputs, block_field_changed = (
            self._process_block(
                scope=scope,
                scope_context=scope_context,
                statements=scope.body,
                env=env,
            )
        )
        returns.update(block_returns)
        callees.update(block_callees)
        input_changed_scope_contexts.update(block_inputs)
        instance_field_changed = instance_field_changed or block_field_changed

        module_binding_changed = False
        if scope.name == scope.module:
            module_binding_changed = self._merge_bindings(self.module_bindings[scope.module], env)

        return ScopeResult(
            callees=callees,
            returns=returns,
            input_changed_scope_contexts=input_changed_scope_contexts,
            module_binding_changed=module_binding_changed,
            instance_field_changed=instance_field_changed,
        )

    def _process_block(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        statements: Sequence[ast.stmt],
        env: Dict[str, Set[AbstractValue]],
    ) -> tuple[
        Dict[str, Set[AbstractValue]],
        Set[AbstractValue],
        Set[str],
        Set[tuple[str, ContextKey]],
        bool,
    ]:
        returns: Set[AbstractValue] = set()
        callees: Set[str] = set()
        input_changed_scope_contexts: Set[tuple[str, ContextKey]] = set()
        instance_field_changed = False

        for stmt in statements:
            if isinstance(stmt, ast.Assign):
                value = self._eval_expr(
                    scope, scope_context, stmt.value, env, callees, input_changed_scope_contexts
                )
                for target in stmt.targets:
                    changed = self._assign_target(scope, target, value, env)
                    instance_field_changed = instance_field_changed or changed

            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    value = self._eval_expr(
                        scope, scope_context, stmt.value, env, callees, input_changed_scope_contexts
                    )
                    changed = self._assign_target(scope, stmt.target, value, env)
                    instance_field_changed = instance_field_changed or changed

            elif isinstance(stmt, ast.AugAssign):
                value = self._eval_expr(
                    scope, scope_context, stmt.value, env, callees, input_changed_scope_contexts
                )
                changed = self._assign_target(scope, stmt.target, value, env, weak=True)
                instance_field_changed = instance_field_changed or changed

            elif isinstance(stmt, ast.Expr):
                self._eval_expr(
                    scope, scope_context, stmt.value, env, callees, input_changed_scope_contexts
                )

            elif isinstance(stmt, ast.Return):
                if stmt.value is None:
                    continue
                returns.update(
                    self._eval_expr(
                        scope, scope_context, stmt.value, env, callees, input_changed_scope_contexts
                    )
                )

            elif isinstance(stmt, ast.If):
                self._eval_expr(
                    scope, scope_context, stmt.test, env, callees, input_changed_scope_contexts
                )
                then_env, then_ret, then_calls, then_inputs, then_field_changed = (
                    self._process_block(scope, scope_context, stmt.body, copy_env(env))
                )
                else_env, else_ret, else_calls, else_inputs, else_field_changed = (
                    self._process_block(scope, scope_context, stmt.orelse, copy_env(env))
                )
                env = join_envs(then_env, else_env)
                returns.update(then_ret)
                returns.update(else_ret)
                callees.update(then_calls)
                callees.update(else_calls)
                input_changed_scope_contexts.update(then_inputs)
                input_changed_scope_contexts.update(else_inputs)
                instance_field_changed = (
                    instance_field_changed or then_field_changed or else_field_changed
                )

            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                self._eval_expr(
                    scope, scope_context, stmt.iter, env, callees, input_changed_scope_contexts
                )
                body_env = copy_env(env)
                self._assign_target(scope, stmt.target, {UNKNOWN_VALUE}, body_env, weak=True)
                body_env, body_ret, body_calls, body_inputs, body_field_changed = (
                    self._process_block(scope, scope_context, stmt.body, body_env)
                )
                orelse_env, else_ret, else_calls, else_inputs, else_field_changed = (
                    self._process_block(scope, scope_context, stmt.orelse, copy_env(env))
                )
                env = join_envs(join_envs(env, body_env), orelse_env)
                returns.update(body_ret)
                returns.update(else_ret)
                callees.update(body_calls)
                callees.update(else_calls)
                input_changed_scope_contexts.update(body_inputs)
                input_changed_scope_contexts.update(else_inputs)
                instance_field_changed = (
                    instance_field_changed or body_field_changed or else_field_changed
                )

            elif isinstance(stmt, ast.While):
                self._eval_expr(
                    scope, scope_context, stmt.test, env, callees, input_changed_scope_contexts
                )
                body_env, body_ret, body_calls, body_inputs, body_field_changed = (
                    self._process_block(scope, scope_context, stmt.body, copy_env(env))
                )
                orelse_env, else_ret, else_calls, else_inputs, else_field_changed = (
                    self._process_block(scope, scope_context, stmt.orelse, copy_env(env))
                )
                env = join_envs(join_envs(env, body_env), orelse_env)
                returns.update(body_ret)
                returns.update(else_ret)
                callees.update(body_calls)
                callees.update(else_calls)
                input_changed_scope_contexts.update(body_inputs)
                input_changed_scope_contexts.update(else_inputs)
                instance_field_changed = (
                    instance_field_changed or body_field_changed or else_field_changed
                )

            elif isinstance(stmt, ast.Try):
                body_env, body_ret, body_calls, body_inputs, body_field_changed = (
                    self._process_block(scope, scope_context, stmt.body, copy_env(env))
                )
                merged_env = body_env
                returns.update(body_ret)
                callees.update(body_calls)
                input_changed_scope_contexts.update(body_inputs)
                instance_field_changed = instance_field_changed or body_field_changed

                for handler in stmt.handlers:
                    handler_env, handler_ret, handler_calls, handler_inputs, handler_changed = (
                        self._process_block(scope, scope_context, handler.body, copy_env(env))
                    )
                    merged_env = join_envs(merged_env, handler_env)
                    returns.update(handler_ret)
                    callees.update(handler_calls)
                    input_changed_scope_contexts.update(handler_inputs)
                    instance_field_changed = instance_field_changed or handler_changed

                orelse_env, else_ret, else_calls, else_inputs, else_changed = (
                    self._process_block(scope, scope_context, stmt.orelse, copy_env(merged_env))
                )
                final_env, final_ret, final_calls, final_inputs, final_changed = (
                    self._process_block(
                        scope, scope_context, stmt.finalbody, copy_env(orelse_env)
                    )
                )
                env = final_env
                returns.update(else_ret)
                returns.update(final_ret)
                callees.update(else_calls)
                callees.update(final_calls)
                input_changed_scope_contexts.update(else_inputs)
                input_changed_scope_contexts.update(final_inputs)
                instance_field_changed = (
                    instance_field_changed or else_changed or final_changed
                )

            elif isinstance(stmt, ast.With):
                for item in stmt.items:
                    self._eval_expr(
                        scope, scope_context, item.context_expr, env, callees,
                        input_changed_scope_contexts,
                    )
                    if item.optional_vars is not None:
                        self._assign_target(scope, item.optional_vars, {UNKNOWN_VALUE}, env, weak=True)
                env, with_ret, with_calls, with_inputs, with_changed = self._process_block(
                    scope, scope_context, stmt.body, env
                )
                returns.update(with_ret)
                callees.update(with_calls)
                input_changed_scope_contexts.update(with_inputs)
                instance_field_changed = instance_field_changed or with_changed

            elif isinstance(stmt, ast.Import):
                self._bind_import(stmt, scope.module, env)

            elif isinstance(stmt, ast.ImportFrom):
                self._bind_import_from(stmt, scope.module, env)

            elif isinstance(stmt, ast.Raise):
                if stmt.exc is not None:
                    self._eval_expr(
                        scope, scope_context, stmt.exc, env, callees, input_changed_scope_contexts
                    )

            elif isinstance(stmt, ast.Assert):
                self._eval_expr(
                    scope, scope_context, stmt.test, env, callees, input_changed_scope_contexts
                )

            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env.pop(target.id, None)

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                prefix = scope.name if scope.name not in self.modules else scope.module
                qualname = f"{prefix}.{stmt.name}"
                if qualname in self.functions:
                    env[stmt.name] = {make_func(qualname)}
                    callee_context = self._normalize_context_for_scope(
                        qualname,
                        (
                            (*scope_context, f"def@{scope.name}:{getattr(stmt, 'lineno', -1)}")[
                                -self.options.context_depth :
                            ]
                            if self.options.context_sensitive
                            and self.options.context_depth > 0
                            else GLOBAL_CONTEXT
                        ),
                    )
                    captured = {
                        name: set(env.get(name, set()))
                        for name in self.functions[qualname].closure_vars
                        if env.get(name)
                    }
                    if captured and self._bind_closure_values(qualname, callee_context, captured):
                        input_changed_scope_contexts.add((qualname, callee_context))

            elif isinstance(stmt, ast.ClassDef):
                qualname = f"{scope.module}.{stmt.name}"
                if qualname in self.classes:
                    env[stmt.name] = {make_class(qualname)}

        return env, returns, callees, input_changed_scope_contexts, instance_field_changed
