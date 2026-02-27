"""Fixpoint loop and block/scope analysis for constraint-based call graph analysis."""

from __future__ import annotations

import ast
import warnings
from collections import deque
from typing import Dict, Mapping, Sequence, Set, Tuple, List

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
)


class _AnalyzerMixin:
    """Fixpoint iteration and per-scope/block analysis."""

    def _pattern_bound_names(self, pattern: ast.pattern) -> Set[str]:
        if isinstance(pattern, ast.MatchAs):
            return {pattern.name} if pattern.name else set()
        if isinstance(pattern, ast.MatchStar):
            return {pattern.name} if pattern.name else set()
        if isinstance(pattern, ast.MatchMapping):
            names: Set[str] = set()
            for inner in pattern.patterns:
                names.update(self._pattern_bound_names(inner))
            if pattern.rest:
                names.add(pattern.rest)
            return names
        if isinstance(pattern, ast.MatchSequence):
            names: Set[str] = set()
            for inner in pattern.patterns:
                names.update(self._pattern_bound_names(inner))
            return names
        if isinstance(pattern, ast.MatchClass):
            names: Set[str] = set()
            for inner in pattern.patterns:
                names.update(self._pattern_bound_names(inner))
            for inner in pattern.kwd_patterns:
                names.update(self._pattern_bound_names(inner))
            return names
        if isinstance(pattern, ast.MatchOr):
            names: Set[str] = set()
            for inner in pattern.patterns:
                names.update(self._pattern_bound_names(inner))
            return names
        return set()

    def _merge_value_maps(
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

    def _apply_decorators(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        name: str,
        initial_values: Set[AbstractValue],
        decorators: Sequence[ast.expr],
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        """
        Apply decorator chain and return the final bound value set for `name`.

        Decorators are evaluated left-to-right but applied right-to-left, so we
        pre-evaluate expressions and then invoke targets in reverse order.
        """
        if not decorators:
            return set(initial_values)

        env[name] = set(initial_values)
        evaluated = [
            self._eval_expr(
                scope,
                scope_context,
                decorator,
                env,
                callees,
                input_changed_scope_contexts,
            )
            for decorator in decorators
        ]
        for decorator, targets in reversed(list(zip(decorators, evaluated))):
            synthetic_call = ast.copy_location(
                ast.Call(
                    func=decorator,
                    args=[ast.Name(id=name, ctx=ast.Load())],
                    keywords=[],
                ),
                decorator,
            )
            decorated_values = self._invoke_targets(
                caller_scope=scope,
                caller_context=scope_context,
                target_values=targets or {UNKNOWN_VALUE},
                call_node=synthetic_call,
                env=env,
                callees=callees,
                input_changed_scope_contexts=input_changed_scope_contexts,
            )
            env[name] = set(decorated_values or {UNKNOWN_VALUE})
        return set(env.get(name, initial_values))

    def _run_fixpoint(self) -> None:
        """
        Solve interprocedural constraints to a fixpoint over scope-context pairs.

        Worklist strategy:
        - Seed module scopes and top-level functions in root context.
        - Requeue direct callees when argument/closure inputs change.
        - Requeue dependents when outputs/fields/module bindings change.
        """
        def _is_seed_scope(scope_name: str) -> bool:
            if scope_name in self.modules:
                return True
            function_info = self.functions.get(scope_name)
            if function_info is None:
                return True
            return function_info.parent_scope is None

        queue: deque[Tuple[str, ContextKey]] = deque(
            (scope_name, self._root_context())
            for scope_name in self.scopes
            if _is_seed_scope(scope_name)
        )
        in_queue = set(queue)
        iterations = 0
        configured_max = self.options.fixpoint_max_iterations
        max_iterations = (
            max(1, int(configured_max))
            if configured_max is not None
            else max(256, len(self.scopes) * 256)
        )

        while queue and iterations < max_iterations:
            iterations += 1
            scope_name, scope_context = queue.popleft()
            scope_context = self._normalize_context_for_scope(scope_name, scope_context)
            in_queue.discard((scope_name, scope_context))
            self._analyzed_scope_contexts.add((scope_name, scope_context))
            scope = self.scopes[scope_name]
            result = self._analyze_scope(scope, scope_context)
            scope_ctx_key = (scope_name, scope_context)

            previous_returns = self.scope_returns.get(scope_ctx_key, set())
            previous_callees = self.scope_callees.get(scope_ctx_key, set())
            returns_changed = previous_returns != result.returns
            callees_changed = previous_callees != result.callees
            if returns_changed:
                self.scope_returns[scope_ctx_key] = set(result.returns)
            if callees_changed:
                self.scope_callees[scope_ctx_key] = set(result.callees)

            for callee_scope, callee_context in result.input_changed_scope_contexts:
                normalized = self._normalize_context_for_scope(
                    callee_scope, callee_context
                )
                key = (callee_scope, normalized)
                if key not in in_queue:
                    queue.append(key)
                    in_queue.add(key)

            changed = (
                returns_changed
                or callees_changed
                or result.module_binding_changed
                or bool(result.changed_instance_fields)
                or bool(result.changed_class_fields)
                or result.nonlocal_binding_changed
            )
            if changed:
                impacted: Set[Tuple[str, ContextKey]] = set()
                if (
                    returns_changed
                    or callees_changed
                    or result.nonlocal_binding_changed
                ):
                    impacted.update(self.call_dependents.get(scope_ctx_key, set()))
                if result.module_binding_changed:
                    impacted.update(self.module_dependents.get(scope.module, set()))
                for field_key in result.changed_instance_fields:
                    impacted.update(
                        self.instance_field_dependents.get(field_key, set())
                    )
                for field_key in result.changed_class_fields:
                    impacted.update(self.class_field_dependents.get(field_key, set()))
                for candidate in impacted:
                    if candidate not in in_queue:
                        queue.append(candidate)
                        in_queue.add(candidate)

        self.fixpoint_iterations = iterations
        self.fixpoint_truncated = bool(queue)
        if self.fixpoint_truncated and self.options.warn_on_fixpoint_truncation:
            warnings.warn(
                (
                    "Constraint call graph fixpoint hit the iteration cap "
                    f"({max_iterations}) before convergence; results may be incomplete."
                ),
                RuntimeWarning,
                stacklevel=2,
            )

    def _analyze_scope(
        self, scope: ScopeInfo, scope_context: ContextKey
    ) -> ScopeResult:
        """
        Analyze one scope instance under one context and return delta summary.

        The returned `ScopeResult` is consumed by `_run_fixpoint` to decide
        which other scope-context states must be revisited.
        """
        env = copy_env(self.module_bindings.get(scope.module, {}))
        scope_ctx_key = (scope.name, scope_context)
        previous_active_scope_context = self._active_scope_context
        self._active_scope_context = scope_ctx_key
        self._register_module_dependency(scope.module, scope_ctx_key)
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

        try:
            callees: Set[str] = set()
            returns: Set[AbstractValue] = set()
            input_changed_scope_contexts: Set[Tuple[str, ContextKey]] = set()

            (
                env,
                block_returns,
                block_callees,
                block_inputs,
                changed_instance_fields,
                changed_class_fields,
                block_global_writes,
                block_nonlocal_writes,
                _,
            ) = self._process_block(
                scope=scope,
                scope_context=scope_context,
                statements=scope.body,
                env=env,
            )
            returns.update(block_returns)
            callees.update(block_callees)
            input_changed_scope_contexts.update(block_inputs)

            module_binding_changed = False
            if scope.name == scope.module:
                previous_module_bindings = self.module_bindings.get(scope.module, {})
                module_binding_changed = previous_module_bindings != env
                self.module_bindings[scope.module] = {
                    name: set(values) for name, values in env.items()
                }
            if block_global_writes:
                module_binding_changed = (
                    self._merge_bindings(
                        self.module_bindings[scope.module], block_global_writes
                    )
                    or module_binding_changed
                )

            previous_global_writes = self.scope_global_writes.get(scope_ctx_key, {})
            previous_nonlocal_writes = self.scope_nonlocal_writes.get(scope_ctx_key, {})
            global_changed = previous_global_writes != block_global_writes
            nonlocal_changed = previous_nonlocal_writes != block_nonlocal_writes
            self.scope_global_writes[scope_ctx_key] = {
                name: set(values) for name, values in block_global_writes.items()
            }
            self.scope_nonlocal_writes[scope_ctx_key] = {
                name: set(values) for name, values in block_nonlocal_writes.items()
            }

            return ScopeResult(
                callees=callees,
                returns=returns,
                input_changed_scope_contexts=input_changed_scope_contexts,
                module_binding_changed=module_binding_changed,
                changed_instance_fields=changed_instance_fields,
                changed_class_fields=changed_class_fields,
                nonlocal_binding_changed=global_changed or nonlocal_changed,
            )
        finally:
            self._active_scope_context = previous_active_scope_context

    def _process_block(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        statements: Sequence[ast.stmt],
        env: Dict[str, Set[AbstractValue]],
    ) -> Tuple[
        Dict[str, Set[AbstractValue]],
        Set[AbstractValue],
        Set[str],
        Set[Tuple[str, ContextKey]],
        Set[Tuple[str, str]],
        Set[Tuple[str, str]],
        Dict[str, Set[AbstractValue]],
        Dict[str, Set[AbstractValue]],
        bool,
    ]:
        """
        Flow-sensitively interpret a statement block.

        Returns:
        - updated env for fall-through path,
        - collected return values and callee edges,
        - input-change notifications for downstream scopes,
        - side-effect summaries (instance/class/global/nonlocal writes),
        - fall-through flag for control-flow composition by enclosing blocks.
        """
        returns: Set[AbstractValue] = set()
        callees: Set[str] = set()
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]] = set()
        changed_instance_fields: Set[Tuple[str, str]] = set()
        changed_class_fields: Set[Tuple[str, str]] = set()
        global_writes: Dict[str, Set[AbstractValue]] = {}
        nonlocal_writes: Dict[str, Set[AbstractValue]] = {}
        falls_through = True

        for stmt in statements:
            if not falls_through:
                break

            if isinstance(stmt, ast.Assign):
                value = self._eval_expr(
                    scope,
                    scope_context,
                    stmt.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                for target in stmt.targets:
                    self._assign_target(
                        scope,
                        target,
                        value,
                        env,
                        global_writes=global_writes,
                        nonlocal_writes=nonlocal_writes,
                        changed_instance_fields=changed_instance_fields,
                        changed_class_fields=changed_class_fields,
                    )

            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    value = self._eval_expr(
                        scope,
                        scope_context,
                        stmt.value,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    self._assign_target(
                        scope,
                        stmt.target,
                        value,
                        env,
                        global_writes=global_writes,
                        nonlocal_writes=nonlocal_writes,
                        changed_instance_fields=changed_instance_fields,
                        changed_class_fields=changed_class_fields,
                    )

            elif isinstance(stmt, ast.AugAssign):
                value = self._eval_expr(
                    scope,
                    scope_context,
                    stmt.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                self._assign_target(
                    scope,
                    stmt.target,
                    value,
                    env,
                    weak=True,
                    global_writes=global_writes,
                    nonlocal_writes=nonlocal_writes,
                    changed_instance_fields=changed_instance_fields,
                    changed_class_fields=changed_class_fields,
                )

            elif isinstance(stmt, ast.Expr):
                expr_values = self._eval_expr(
                    scope,
                    scope_context,
                    stmt.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                if isinstance(stmt.value, (ast.Yield, ast.YieldFrom)):
                    returns.update(expr_values)

            elif isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    returns.update(
                        self._eval_expr(
                            scope,
                            scope_context,
                            stmt.value,
                            env,
                            callees,
                            input_changed_scope_contexts,
                        )
                    )
                falls_through = False

            elif isinstance(stmt, ast.If):
                self._eval_expr(
                    scope,
                    scope_context,
                    stmt.test,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                (
                    then_env,
                    then_ret,
                    then_calls,
                    then_inputs,
                    then_instance_changed,
                    then_class_changed,
                    then_globals,
                    then_nonlocals,
                    then_fallthrough,
                ) = self._process_block(scope, scope_context, stmt.body, copy_env(env))
                (
                    else_env,
                    else_ret,
                    else_calls,
                    else_inputs,
                    else_instance_changed,
                    else_class_changed,
                    else_globals,
                    else_nonlocals,
                    else_fallthrough,
                ) = self._process_block(
                    scope, scope_context, stmt.orelse, copy_env(env)
                )
                if then_fallthrough and else_fallthrough:
                    env = join_envs(then_env, else_env)
                elif then_fallthrough:
                    env = then_env
                elif else_fallthrough:
                    env = else_env
                falls_through = then_fallthrough or else_fallthrough
                returns.update(then_ret)
                returns.update(else_ret)
                callees.update(then_calls)
                callees.update(else_calls)
                input_changed_scope_contexts.update(then_inputs)
                input_changed_scope_contexts.update(else_inputs)
                changed_instance_fields.update(then_instance_changed)
                changed_instance_fields.update(else_instance_changed)
                changed_class_fields.update(then_class_changed)
                changed_class_fields.update(else_class_changed)
                self._merge_value_maps(global_writes, then_globals)
                self._merge_value_maps(global_writes, else_globals)
                self._merge_value_maps(nonlocal_writes, then_nonlocals)
                self._merge_value_maps(nonlocal_writes, else_nonlocals)

            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                iter_values = self._eval_expr(
                    scope,
                    scope_context,
                    stmt.iter,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                body_env = copy_env(env)
                iter_members = self._iterable_members(iter_values)
                for iter_value in iter_values:
                    iter_targets = self._resolve_attribute({iter_value}, "__iter__")
                    if not iter_targets:
                        continue
                    iter_call = ast.copy_location(
                        ast.Call(func=stmt.iter, args=[], keywords=[]),
                        stmt.iter,
                    )
                    iterated_values = self._invoke_targets(
                        caller_scope=scope,
                        caller_context=scope_context,
                        target_values=iter_targets,
                        call_node=iter_call,
                        env=body_env,
                        callees=callees,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )
                    next_targets = self._resolve_attribute(iterated_values, "__next__")
                    if not next_targets:
                        continue
                    next_values = self._invoke_targets(
                        caller_scope=scope,
                        caller_context=scope_context,
                        target_values=next_targets,
                        call_node=iter_call,
                        env=body_env,
                        callees=callees,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )
                    iter_members.update(next_values)
                if not iter_members:
                    iter_members = {UNKNOWN_VALUE}
                self._assign_target(
                    scope,
                    stmt.target,
                    iter_members,
                    body_env,
                    weak=True,
                    global_writes=global_writes,
                    nonlocal_writes=nonlocal_writes,
                    changed_instance_fields=changed_instance_fields,
                    changed_class_fields=changed_class_fields,
                )
                (
                    body_env,
                    body_ret,
                    body_calls,
                    body_inputs,
                    body_instance_changed,
                    body_class_changed,
                    body_globals,
                    body_nonlocals,
                    body_fallthrough,
                ) = self._process_block(scope, scope_context, stmt.body, body_env)
                (
                    orelse_env,
                    else_ret,
                    else_calls,
                    else_inputs,
                    else_instance_changed,
                    else_class_changed,
                    else_globals,
                    else_nonlocals,
                    else_fallthrough,
                ) = self._process_block(
                    scope, scope_context, stmt.orelse, copy_env(env)
                )
                merged_env = copy_env(env)
                if body_fallthrough:
                    merged_env = join_envs(merged_env, body_env)
                if else_fallthrough:
                    merged_env = join_envs(merged_env, orelse_env)
                env = merged_env
                returns.update(body_ret)
                returns.update(else_ret)
                callees.update(body_calls)
                callees.update(else_calls)
                input_changed_scope_contexts.update(body_inputs)
                input_changed_scope_contexts.update(else_inputs)
                changed_instance_fields.update(body_instance_changed)
                changed_instance_fields.update(else_instance_changed)
                changed_class_fields.update(body_class_changed)
                changed_class_fields.update(else_class_changed)
                self._merge_value_maps(global_writes, body_globals)
                self._merge_value_maps(global_writes, else_globals)
                self._merge_value_maps(nonlocal_writes, body_nonlocals)
                self._merge_value_maps(nonlocal_writes, else_nonlocals)

            elif isinstance(stmt, ast.While):
                self._eval_expr(
                    scope,
                    scope_context,
                    stmt.test,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                (
                    body_env,
                    body_ret,
                    body_calls,
                    body_inputs,
                    body_instance_changed,
                    body_class_changed,
                    body_globals,
                    body_nonlocals,
                    body_fallthrough,
                ) = self._process_block(scope, scope_context, stmt.body, copy_env(env))
                (
                    orelse_env,
                    else_ret,
                    else_calls,
                    else_inputs,
                    else_instance_changed,
                    else_class_changed,
                    else_globals,
                    else_nonlocals,
                    else_fallthrough,
                ) = self._process_block(
                    scope, scope_context, stmt.orelse, copy_env(env)
                )
                merged_env = copy_env(env)
                if body_fallthrough:
                    merged_env = join_envs(merged_env, body_env)
                if else_fallthrough:
                    merged_env = join_envs(merged_env, orelse_env)
                env = merged_env
                returns.update(body_ret)
                returns.update(else_ret)
                callees.update(body_calls)
                callees.update(else_calls)
                input_changed_scope_contexts.update(body_inputs)
                input_changed_scope_contexts.update(else_inputs)
                changed_instance_fields.update(body_instance_changed)
                changed_instance_fields.update(else_instance_changed)
                changed_class_fields.update(body_class_changed)
                changed_class_fields.update(else_class_changed)
                self._merge_value_maps(global_writes, body_globals)
                self._merge_value_maps(global_writes, else_globals)
                self._merge_value_maps(nonlocal_writes, body_nonlocals)
                self._merge_value_maps(nonlocal_writes, else_nonlocals)

            elif isinstance(stmt, ast.Try):
                (
                    body_env,
                    body_ret,
                    body_calls,
                    body_inputs,
                    body_instance_changed,
                    body_class_changed,
                    body_globals,
                    body_nonlocals,
                    body_fallthrough,
                ) = self._process_block(scope, scope_context, stmt.body, copy_env(env))
                returns.update(body_ret)
                callees.update(body_calls)
                input_changed_scope_contexts.update(body_inputs)
                changed_instance_fields.update(body_instance_changed)
                changed_class_fields.update(body_class_changed)
                self._merge_value_maps(global_writes, body_globals)
                self._merge_value_maps(nonlocal_writes, body_nonlocals)

                handler_envs: List[Dict[str, Set[AbstractValue]]] = []
                handler_exit_envs: List[Dict[str, Set[AbstractValue]]] = []
                handler_fallthrough = False
                for handler in stmt.handlers:
                    (
                        handler_env,
                        handler_ret,
                        handler_calls,
                        handler_inputs,
                        handler_instance_changed,
                        handler_class_changed,
                        handler_globals,
                        handler_nonlocals,
                        handler_fall,
                    ) = self._process_block(
                        scope, scope_context, handler.body, copy_env(env)
                    )
                    handler_envs.append(handler_env)
                    if handler_fall:
                        handler_fallthrough = True
                        handler_exit_envs.append(handler_env)
                    returns.update(handler_ret)
                    callees.update(handler_calls)
                    input_changed_scope_contexts.update(handler_inputs)
                    changed_instance_fields.update(handler_instance_changed)
                    changed_class_fields.update(handler_class_changed)
                    self._merge_value_maps(global_writes, handler_globals)
                    self._merge_value_maps(nonlocal_writes, handler_nonlocals)

                else_env = copy_env(body_env)
                else_fallthrough = body_fallthrough and not stmt.orelse
                if body_fallthrough and stmt.orelse:
                    (
                        else_env,
                        else_ret,
                        else_calls,
                        else_inputs,
                        else_instance_changed,
                        else_class_changed,
                        else_globals,
                        else_nonlocals,
                        else_fallthrough,
                    ) = self._process_block(
                        scope, scope_context, stmt.orelse, copy_env(body_env)
                    )
                    returns.update(else_ret)
                    callees.update(else_calls)
                    input_changed_scope_contexts.update(else_inputs)
                    changed_instance_fields.update(else_instance_changed)
                    changed_class_fields.update(else_class_changed)
                    self._merge_value_maps(global_writes, else_globals)
                    self._merge_value_maps(nonlocal_writes, else_nonlocals)

                before_final_env: Dict[str, Set[AbstractValue]] = {}
                if body_fallthrough and not stmt.orelse:
                    before_final_env = join_envs(before_final_env, body_env)
                if body_fallthrough and stmt.orelse and else_fallthrough:
                    before_final_env = join_envs(before_final_env, else_env)
                for handler_env in handler_exit_envs:
                    before_final_env = join_envs(before_final_env, handler_env)

                if stmt.finalbody:
                    final_entry = copy_env(body_env)
                    if body_fallthrough and stmt.orelse:
                        final_entry = join_envs(final_entry, else_env)
                    for handler_env in handler_envs:
                        final_entry = join_envs(final_entry, handler_env)
                    (
                        final_env,
                        final_ret,
                        final_calls,
                        final_inputs,
                        final_instance_changed,
                        final_class_changed,
                        final_globals,
                        final_nonlocals,
                        final_fallthrough,
                    ) = self._process_block(
                        scope, scope_context, stmt.finalbody, final_entry
                    )
                    env = final_env
                    returns.update(final_ret)
                    callees.update(final_calls)
                    input_changed_scope_contexts.update(final_inputs)
                    changed_instance_fields.update(final_instance_changed)
                    changed_class_fields.update(final_class_changed)
                    self._merge_value_maps(global_writes, final_globals)
                    self._merge_value_maps(nonlocal_writes, final_nonlocals)
                    falls_through = final_fallthrough and (
                        (body_fallthrough and (not stmt.orelse or else_fallthrough))
                        or handler_fallthrough
                    )
                else:
                    env = before_final_env if before_final_env else copy_env(env)
                    falls_through = bool(before_final_env)

            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                enter_name = (
                    "__aenter__" if isinstance(stmt, ast.AsyncWith) else "__enter__"
                )
                exit_name = (
                    "__aexit__" if isinstance(stmt, ast.AsyncWith) else "__exit__"
                )
                exit_calls: List[Tuple[Set[AbstractValue], ast.expr]] = []
                for item in stmt.items:
                    manager_values = self._eval_expr(
                        scope,
                        scope_context,
                        item.context_expr,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    enter_targets = self._resolve_attribute(manager_values, enter_name)
                    enter_call = ast.copy_location(
                        ast.Call(func=item.context_expr, args=[], keywords=[]),
                        item.context_expr,
                    )
                    entered_values = self._invoke_targets(
                        caller_scope=scope,
                        caller_context=scope_context,
                        target_values=enter_targets,
                        call_node=enter_call,
                        env=env,
                        callees=callees,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )
                    if item.optional_vars is not None:
                        self._assign_target(
                            scope,
                            item.optional_vars,
                            entered_values or {UNKNOWN_VALUE},
                            env,
                            global_writes=global_writes,
                            nonlocal_writes=nonlocal_writes,
                            changed_instance_fields=changed_instance_fields,
                            changed_class_fields=changed_class_fields,
                        )
                    exit_calls.append(
                        (
                            self._resolve_attribute(manager_values, exit_name),
                            item.context_expr,
                        )
                    )

                (
                    env,
                    with_ret,
                    with_calls,
                    with_inputs,
                    with_instance_changed,
                    with_class_changed,
                    with_globals,
                    with_nonlocals,
                    with_fallthrough,
                ) = self._process_block(scope, scope_context, stmt.body, env)
                for exit_targets, context_expr in reversed(exit_calls):
                    exit_call = ast.copy_location(
                        ast.Call(func=context_expr, args=[], keywords=[]),
                        context_expr,
                    )
                    self._invoke_targets(
                        caller_scope=scope,
                        caller_context=scope_context,
                        target_values=exit_targets,
                        call_node=exit_call,
                        env=env,
                        callees=callees,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )
                returns.update(with_ret)
                callees.update(with_calls)
                input_changed_scope_contexts.update(with_inputs)
                changed_instance_fields.update(with_instance_changed)
                changed_class_fields.update(with_class_changed)
                self._merge_value_maps(global_writes, with_globals)
                self._merge_value_maps(nonlocal_writes, with_nonlocals)
                falls_through = with_fallthrough

            elif isinstance(stmt, ast.Match):
                self._eval_expr(
                    scope,
                    scope_context,
                    stmt.subject,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                merged_env = copy_env(env)
                for case in stmt.cases:
                    case_env = copy_env(env)
                    for bound_name in self._pattern_bound_names(case.pattern):
                        case_env.setdefault(bound_name, set()).add(UNKNOWN_VALUE)
                    if case.guard is not None:
                        self._eval_expr(
                            scope,
                            scope_context,
                            case.guard,
                            case_env,
                            callees,
                            input_changed_scope_contexts,
                        )
                    (
                        branch_env,
                        branch_ret,
                        branch_calls,
                        branch_inputs,
                        branch_instance_changed,
                        branch_class_changed,
                        branch_globals,
                        branch_nonlocals,
                        branch_fallthrough,
                    ) = self._process_block(scope, scope_context, case.body, case_env)
                    if branch_fallthrough:
                        merged_env = join_envs(merged_env, branch_env)
                    returns.update(branch_ret)
                    callees.update(branch_calls)
                    input_changed_scope_contexts.update(branch_inputs)
                    changed_instance_fields.update(branch_instance_changed)
                    changed_class_fields.update(branch_class_changed)
                    self._merge_value_maps(global_writes, branch_globals)
                    self._merge_value_maps(nonlocal_writes, branch_nonlocals)
                env = merged_env

            elif isinstance(stmt, ast.Import):
                self._bind_import(stmt, scope.module, env)

            elif isinstance(stmt, ast.ImportFrom):
                self._bind_import_from(stmt, scope.module, env)

            elif isinstance(stmt, ast.Raise):
                if stmt.exc is not None:
                    raised_values = self._eval_expr(
                        scope,
                        scope_context,
                        stmt.exc,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    class_values = {
                        value for value in raised_values if value.kind == "class"
                    }
                    if class_values:
                        raise_call = ast.copy_location(
                            ast.Call(func=stmt.exc, args=[], keywords=[]),
                            stmt.exc,
                        )
                        self._invoke_targets(
                            caller_scope=scope,
                            caller_context=scope_context,
                            target_values=class_values,
                            call_node=raise_call,
                            env=env,
                            callees=callees,
                            input_changed_scope_contexts=input_changed_scope_contexts,
                        )
                falls_through = False

            elif isinstance(stmt, ast.Assert):
                self._eval_expr(
                    scope,
                    scope_context,
                    stmt.test,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )

            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env.pop(target.id, None)

            elif isinstance(stmt, (ast.Break, ast.Continue)):
                falls_through = False

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                prefix = scope.name if scope.name not in self.modules else scope.module
                qualname = f"{prefix}.{stmt.name}"
                if qualname in self.functions:
                    base_values = {make_func(qualname)}
                    env[stmt.name] = set(base_values)
                    if scope.name not in self.modules:
                        callee_context = self._normalize_context_for_scope(
                            qualname,
                            (
                                (
                                    *scope_context,
                                    f"def@{scope.name}:{getattr(stmt, 'lineno', -1)}",
                                )[-self.options.context_depth :]
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
                        if captured and self._bind_closure_values(
                            qualname, callee_context, captured
                        ):
                            input_changed_scope_contexts.add((qualname, callee_context))
                    env[stmt.name] = self._apply_decorators(
                        scope=scope,
                        scope_context=scope_context,
                        name=stmt.name,
                        initial_values=base_values,
                        decorators=stmt.decorator_list,
                        env=env,
                        callees=callees,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )

            elif isinstance(stmt, ast.ClassDef):
                prefix = scope.name if scope.name not in self.modules else scope.module
                qualname = f"{prefix}.{stmt.name}"
                if qualname in self.classes:
                    env[stmt.name] = self._apply_decorators(
                        scope=scope,
                        scope_context=scope_context,
                        name=stmt.name,
                        initial_values={make_class(qualname)},
                        decorators=stmt.decorator_list,
                        env=env,
                        callees=callees,
                        input_changed_scope_contexts=input_changed_scope_contexts,
                    )

        return (
            env,
            returns,
            callees,
            input_changed_scope_contexts,
            changed_instance_fields,
            changed_class_fields,
            global_writes,
            nonlocal_writes,
            falls_through,
        )
