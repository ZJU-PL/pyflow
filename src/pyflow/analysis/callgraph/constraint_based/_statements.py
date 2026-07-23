"""Statement and control-flow interpretation for constraint call analysis."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set, Tuple

from .model import (
    AbstractValue,
    ContextKey,
    GLOBAL_CONTEXT,
    ScopeInfo,
    UNKNOWN_VALUE,
    copy_env,
    join_envs,
    make_class,
    make_func,
)


_BlockResult = Tuple[
    Dict[str, Set[AbstractValue]],
    Set[AbstractValue],
    Set[str],
    Set[Tuple[str, ContextKey]],
    Set[Tuple[str, str]],
    Set[Tuple[str, str]],
    Dict[str, Set[AbstractValue]],
    Dict[str, Set[AbstractValue]],
    bool,
]


@dataclass(frozen=True)
class _StatementContext:
    scope: ScopeInfo
    scope_context: ContextKey
    class_definition_env: Dict[str, Set[AbstractValue]] | None


@dataclass
class _BlockState:
    env: Dict[str, Set[AbstractValue]]
    returns: Set[AbstractValue] = field(default_factory=set)
    callees: Set[str] = field(default_factory=set)
    input_changed_scope_contexts: Set[Tuple[str, ContextKey]] = field(
        default_factory=set
    )
    changed_instance_fields: Set[Tuple[str, str]] = field(default_factory=set)
    changed_class_fields: Set[Tuple[str, str]] = field(default_factory=set)
    global_writes: Dict[str, Set[AbstractValue]] = field(default_factory=dict)
    nonlocal_writes: Dict[str, Set[AbstractValue]] = field(default_factory=dict)
    falls_through: bool = True

    def finish(self) -> _BlockResult:
        return (
            self.env,
            self.returns,
            self.callees,
            self.input_changed_scope_contexts,
            self.changed_instance_fields,
            self.changed_class_fields,
            self.global_writes,
            self.nonlocal_writes,
            self.falls_through,
        )


class _StatementAnalysisMixin:
    """Interpret statements and recursively combine block effects."""

    def _process_block(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        statements: Sequence[ast.stmt],
        env: Dict[str, Set[AbstractValue]],
        class_definition_env: Dict[str, Set[AbstractValue]] | None = None,
    ) -> _BlockResult:
        """Interpret a statement block and collect flow-insensitive effects."""
        context = _StatementContext(
            scope=scope,
            scope_context=scope_context,
            class_definition_env=class_definition_env,
        )
        state = _BlockState(env=env)
        for stmt in statements:
            if not state.falls_through:
                break
            self._process_statement(context, state, stmt)
        return state.finish()

    def _process_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        if isinstance(stmt, ast.Assign):
            self._process_assign_statement(context, state, stmt)
        elif isinstance(stmt, ast.AnnAssign):
            self._process_annotated_assign_statement(context, state, stmt)
        elif isinstance(stmt, ast.AugAssign):
            self._process_augmented_assign_statement(context, state, stmt)
        elif isinstance(stmt, ast.Expr):
            self._process_expression_statement(context, state, stmt)
        elif isinstance(stmt, ast.Return):
            self._process_return_statement(context, state, stmt)
        elif isinstance(stmt, ast.If):
            self._process_if_statement(context, state, stmt)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._process_for_statement(context, state, stmt)
        elif isinstance(stmt, ast.While):
            self._process_while_statement(context, state, stmt)
        elif isinstance(stmt, ast.Try):
            self._process_try_statement(context, state, stmt)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._process_with_statement(context, state, stmt)
        elif isinstance(stmt, ast.Match):
            self._process_match_statement(context, state, stmt)
        elif isinstance(stmt, ast.Import):
            self._process_import_statement(context, state, stmt)
        elif isinstance(stmt, ast.ImportFrom):
            self._process_import_from_statement(context, state, stmt)
        elif isinstance(stmt, ast.Raise):
            self._process_raise_statement(context, state, stmt)
        elif isinstance(stmt, ast.Assert):
            self._process_assert_statement(context, state, stmt)
        elif isinstance(stmt, ast.Delete):
            self._process_delete_statement(context, state, stmt)
        elif isinstance(stmt, (ast.Break, ast.Continue)):
            self._process_loop_control_statement(context, state, stmt)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._process_function_definition(context, state, stmt)
        elif isinstance(stmt, ast.ClassDef):
            self._process_class_definition(context, state, stmt)

    def _process_assign_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes

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
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes

    def _process_annotated_assign_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes

        if stmt.value is not None:
            value = self._eval_expr(
                scope,
                scope_context,
                stmt.value,
                env,
                callees,
                input_changed_scope_contexts,
            )
            value = self._filter_values_by_annotation(
                scope.module, stmt.annotation, value
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
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes

    def _process_augmented_assign_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes

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
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes

    def _process_expression_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts

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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts

    def _process_return_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        falls_through = state.falls_through

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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.falls_through = falls_through

    def _process_if_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes
        falls_through = state.falls_through

        self._eval_expr(
            scope,
            scope_context,
            stmt.test,
            env,
            callees,
            input_changed_scope_contexts,
        )
        then_entry_env = self._refine_env_for_test(
            scope, scope_context, stmt.test, env, True
        )
        else_entry_env = self._refine_env_for_test(
            scope, scope_context, stmt.test, env, False
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
        ) = self._process_block(
            scope,
            scope_context,
            stmt.body,
            then_entry_env,
            class_definition_env=class_definition_env,
        )
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
            scope,
            scope_context,
            stmt.orelse,
            else_entry_env,
            class_definition_env=class_definition_env,
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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes
        state.falls_through = falls_through

    def _process_for_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes

        iter_values = self._eval_expr(
            scope,
            scope_context,
            stmt.iter,
            env,
            callees,
            input_changed_scope_contexts,
        )
        body_env = copy_env(env)
        iter_members = self._iterable_members(
            iter_values,
            scope=scope,
            scope_context=scope_context,
            env=body_env,
            callees=callees,
            input_changed_scope_contexts=input_changed_scope_contexts,
        )
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
        ) = self._process_block(
            scope,
            scope_context,
            stmt.body,
            body_env,
            class_definition_env=class_definition_env,
        )
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
            scope,
            scope_context,
            stmt.orelse,
            copy_env(env),
            class_definition_env=class_definition_env,
        )
        merged_env = copy_env(env)
        if body_fallthrough or body_env != env:
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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes

    def _process_while_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes

        self._eval_expr(
            scope,
            scope_context,
            stmt.test,
            env,
            callees,
            input_changed_scope_contexts,
        )
        body_entry_env = self._refine_env_for_test(
            scope, scope_context, stmt.test, env, True
        )
        else_entry_env = self._refine_env_for_test(
            scope, scope_context, stmt.test, env, False
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
        ) = self._process_block(
            scope,
            scope_context,
            stmt.body,
            body_entry_env,
            class_definition_env=class_definition_env,
        )
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
            scope,
            scope_context,
            stmt.orelse,
            else_entry_env,
            class_definition_env=class_definition_env,
        )
        merged_env = copy_env(env)
        if body_fallthrough or body_env != body_entry_env:
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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes

    def _process_try_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes
        falls_through = state.falls_through

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
        ) = self._process_block(
            scope,
            scope_context,
            stmt.body,
            copy_env(env),
            class_definition_env=class_definition_env,
        )
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
            handler_entry_env = copy_env(body_env)
            if handler.name:
                handler_entry_env[handler.name] = self._exception_handler_values(
                    scope,
                    scope_context,
                    handler,
                    body_env,
                    callees,
                    input_changed_scope_contexts,
                )
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
                scope,
                scope_context,
                handler.body,
                handler_entry_env,
                class_definition_env=class_definition_env,
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
                scope,
                scope_context,
                stmt.orelse,
                copy_env(body_env),
                class_definition_env=class_definition_env,
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
                scope,
                scope_context,
                stmt.finalbody,
                final_entry,
                class_definition_env=class_definition_env,
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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes
        state.falls_through = falls_through

    def _process_with_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes
        falls_through = state.falls_through

        enter_name = "__aenter__" if isinstance(stmt, ast.AsyncWith) else "__enter__"
        exit_name = "__aexit__" if isinstance(stmt, ast.AsyncWith) else "__exit__"
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
        ) = self._process_block(
            scope,
            scope_context,
            stmt.body,
            env,
            class_definition_env=class_definition_env,
        )
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
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes
        state.falls_through = falls_through

    def _process_match_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        returns = state.returns
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        changed_instance_fields = state.changed_instance_fields
        changed_class_fields = state.changed_class_fields
        global_writes = state.global_writes
        nonlocal_writes = state.nonlocal_writes

        subject_values = self._eval_expr(
            scope,
            scope_context,
            stmt.subject,
            env,
            callees,
            input_changed_scope_contexts,
        )
        merged_env = copy_env(env)
        remaining_subject_values = set(subject_values or {UNKNOWN_VALUE})
        for case in stmt.cases:
            if not remaining_subject_values:
                break
            case_env = self._refine_env_for_pattern(
                scope,
                scope_context,
                remaining_subject_values,
                case.pattern,
                env,
            )
            matched_subject_values = set(
                case_env.get("__match_subject__", remaining_subject_values)
            )
            if not matched_subject_values:
                continue
            case_env["__match_subject__"] = set(matched_subject_values)
            if isinstance(stmt.subject, ast.Name):
                case_env[stmt.subject.id] = set(matched_subject_values)
            for bound_name in self._pattern_bound_names(case.pattern):
                if not case_env.get(bound_name):
                    case_env.setdefault(bound_name, set()).add(UNKNOWN_VALUE)
            guard_truth: bool | None = True if case.guard is None else None
            if case.guard is not None:
                self._eval_expr(
                    scope,
                    scope_context,
                    case.guard,
                    case_env,
                    callees,
                    input_changed_scope_contexts,
                )
                guard_truth = self._static_truthiness(case.guard, case_env)
                if guard_truth is False:
                    continue
                case_env = self._refine_env_for_test(
                    scope, scope_context, case.guard, case_env, True
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
            ) = self._process_block(
                scope,
                scope_context,
                case.body,
                case_env,
                class_definition_env=class_definition_env,
            )
            if branch_fallthrough:
                merged_env = join_envs(merged_env, branch_env)
            returns.update(branch_ret)
            callees.update(branch_calls)
            input_changed_scope_contexts.update(branch_inputs)
            changed_instance_fields.update(branch_instance_changed)
            changed_class_fields.update(branch_class_changed)
            self._merge_value_maps(global_writes, branch_globals)
            self._merge_value_maps(nonlocal_writes, branch_nonlocals)
            if case.guard is None or guard_truth is True:
                remaining_subject_values.difference_update(matched_subject_values)
                if not remaining_subject_values:
                    break
        env = merged_env
        state.env = env
        state.returns = returns
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.changed_instance_fields = changed_instance_fields
        state.changed_class_fields = changed_class_fields
        state.global_writes = global_writes
        state.nonlocal_writes = nonlocal_writes

    def _process_import_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        env = state.env

        self._bind_import(stmt, scope.module, env)
        state.env = env

    def _process_import_from_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        env = state.env

        self._bind_import_from(stmt, scope.module, env)
        state.env = env

    def _process_raise_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts
        falls_through = state.falls_through

        if stmt.exc is not None:
            raised_values = self._eval_expr(
                scope,
                scope_context,
                stmt.exc,
                env,
                callees,
                input_changed_scope_contexts,
            )
            class_values = {value for value in raised_values if value.kind == "class"}
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
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
        state.falls_through = falls_through

    def _process_assert_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts

        self._eval_expr(
            scope,
            scope_context,
            stmt.test,
            env,
            callees,
            input_changed_scope_contexts,
        )
        env = self._refine_env_for_test(scope, scope_context, stmt.test, env, True)
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts

    def _process_delete_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts

        for target in stmt.targets:
            if isinstance(target, ast.Name):
                # A may-analysis does not kill a binding.  Another path
                # or an earlier/later loop iteration can still expose
                # any value previously assigned to this name.
                continue
            elif isinstance(target, ast.Attribute):
                base_values = self._eval_expr(
                    scope,
                    scope_context,
                    target.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                self._mark_attribute_maybe_missing(base_values, {target.attr})
            elif isinstance(target, ast.Subscript):
                base_values = self._eval_expr(
                    scope,
                    scope_context,
                    target.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                key_names = self._subscript_keys(target)
                if not key_names:
                    key_values = self._eval_expr(
                        scope,
                        scope_context,
                        target.slice,
                        env,
                        callees,
                        input_changed_scope_contexts,
                    )
                    key_names = self._string_constants(key_values)
                self._mark_container_key_maybe_missing(base_values, key_names)
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts

    def _process_loop_control_statement(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        falls_through = state.falls_through

        falls_through = False
        state.falls_through = falls_through

    def _process_function_definition(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts

        prefix = scope.name if scope.name not in self.modules else scope.module
        qualname = f"{prefix}.{stmt.name}"
        if qualname in self.functions:
            self._evaluate_function_header(
                scope,
                scope_context,
                stmt,
                env,
                callees,
                input_changed_scope_contexts,
            )
            base_values = {make_func(qualname)}
            env[stmt.name] = set(base_values)
            if scope.name not in self.modules:
                capture_env = (
                    class_definition_env
                    if scope.class_owner is not None
                    and class_definition_env is not None
                    else env
                )
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
                    name: set(capture_env.get(name, set()))
                    for name in self.functions[qualname].closure_vars
                }
                if self.functions[qualname].closure_vars and self._bind_closure_values(
                    qualname,
                    callee_context,
                    captured,
                    closure_origin=(scope.name, scope_context),
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
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts

    def _process_class_definition(
        self,
        context: _StatementContext,
        state: _BlockState,
        stmt: ast.stmt,
    ) -> None:
        scope = context.scope
        scope_context = context.scope_context
        class_definition_env = context.class_definition_env
        env = state.env
        callees = state.callees
        input_changed_scope_contexts = state.input_changed_scope_contexts

        prefix = scope.name if scope.name not in self.modules else scope.module
        qualname = f"{prefix}.{stmt.name}"
        if qualname in self.classes:
            resolved_bases = [
                self._eval_expr(
                    scope,
                    scope_context,
                    base_expr,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
                for base_expr in stmt.bases
            ]
            for keyword in stmt.keywords:
                self._eval_expr(
                    scope,
                    scope_context,
                    keyword.value,
                    env,
                    callees,
                    input_changed_scope_contexts,
                )
            self._update_runtime_class_bases(qualname, resolved_bases)
            if scope.name not in self.modules:
                class_info = self.classes[qualname]
                capture_env = (
                    class_definition_env
                    if scope.class_owner is not None
                    and class_definition_env is not None
                    else env
                )
                callee_context = self._normalize_context_for_scope(
                    qualname,
                    (
                        (
                            *scope_context,
                            f"class@{scope.name}:{getattr(stmt, 'lineno', -1)}",
                        )[-self.options.context_depth :]
                        if self.options.context_sensitive
                        and self.options.context_depth > 0
                        else GLOBAL_CONTEXT
                    ),
                )
                captured = {
                    name: set(capture_env.get(name, set()))
                    for name in class_info.closure_vars
                }
                if class_info.closure_vars and self._bind_closure_values(
                    qualname,
                    callee_context,
                    captured,
                    closure_origin=(scope.name, scope_context),
                ):
                    input_changed_scope_contexts.add((qualname, callee_context))
                if (qualname, callee_context) not in self._analyzed_scope_contexts:
                    input_changed_scope_contexts.add((qualname, callee_context))
            class_info = self.classes[qualname]
            class_call = ast.copy_location(
                ast.Call(
                    func=ast.Name(id=stmt.name, ctx=ast.Load()),
                    args=[],
                    keywords=[],
                ),
                stmt,
            )
            for base_name in self._class_lookup_order(qualname)[1:]:
                hook_name = f"{base_name}.__init_subclass__"
                if hook_name not in self.scopes and (
                    base_name in self.classes or "." not in base_name
                ):
                    continue
                self._invoke_with_implicit_receiver(
                    hook_name,
                    {make_class(qualname)},
                    scope,
                    scope_context,
                    class_call,
                    env,
                    callees,
                    input_changed_scope_contexts,
                    [],
                    {},
                )
                break
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
        state.env = env
        state.callees = callees
        state.input_changed_scope_contexts = input_changed_scope_contexts
