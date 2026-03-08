"""Fixpoint loop and block/scope analysis for constraint-based call graph analysis."""

from __future__ import annotations

import ast
import heapq
import warnings
from collections import deque
from typing import Dict, Mapping, Sequence, Set, Tuple, List

from .model import (
    AbstractValue,
    CLASS_KIND,
    ContextKey,
    FUNC_KIND,
    GLOBAL_CONTEXT,
    NONE_VALUE,
    ScopeInfo,
    ScopeResult,
    UNKNOWN_VALUE,
    copy_env,
    join_envs,
    make_class,
    make_func,
    make_instance,
)


class _AnalyzerMixin:
    """Fixpoint iteration and per-scope/block analysis."""

    def _evaluate_function_header(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        env: Dict[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> None:
        """Evaluate definition-time expressions for a function header."""
        expressions: List[ast.AST] = list(node.args.defaults)
        expressions.extend(
            default for default in node.args.kw_defaults if default is not None
        )
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        ):
            if arg.annotation is not None:
                expressions.append(arg.annotation)
        if node.args.vararg and node.args.vararg.annotation is not None:
            expressions.append(node.args.vararg.annotation)
        if node.args.kwarg and node.args.kwarg.annotation is not None:
            expressions.append(node.args.kwarg.annotation)
        if node.returns is not None:
            expressions.append(node.returns)
        for expression in expressions:
            self._eval_expr(
                scope,
                scope_context,
                expression,
                env,
                callees,
                input_changed_scope_contexts,
            )

    def _update_runtime_class_bases(
        self,
        class_name: str,
        base_value_sets: Sequence[Set[AbstractValue]],
    ) -> None:
        """Merge runtime-resolved base classes discovered during class definition."""
        class_info = self.classes.get(class_name)
        if class_info is None:
            return
        resolved = list(class_info.bases)
        changed = False
        for values in base_value_sets:
            for value in values:
                if value.kind != CLASS_KIND or value.name in resolved:
                    continue
                resolved.append(value.name)
                changed = True
        if changed:
            class_info.bases = resolved
            self._mro_cache.clear()
            self._invalid_mro_classes.discard(class_name)

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
            changed = self._merge_value_set(current, set(values)) or changed
        return changed

    def _scope_state_fingerprint(
        self, scope: ScopeInfo, scope_context: ContextKey
    ) -> int:
        scope_key = (scope.name, scope_context)
        input_bindings = self.scope_inputs.get(scope_key, {})
        normalized_bindings = tuple(
            (
                name,
                tuple(sorted((value.kind, value.name) for value in values)),
            )
            for name, values in sorted(input_bindings.items())
        )
        # Coarse, monotonic side-effect stamps used to avoid redundant re-analysis.
        return hash(
            (
                normalized_bindings,
                self._global_module_stamp,
                self._global_heap_stamp,
                self._global_return_stamp,
            )
        )

    def _refine_name_binding(
        self,
        env: Mapping[str, Set[AbstractValue]],
        name: str,
        refined_values: Set[AbstractValue],
    ) -> Dict[str, Set[AbstractValue]]:
        updated = copy_env(env)
        updated[name] = set(refined_values)
        return updated

    def _refine_env_for_pattern(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        subject_values: Set[AbstractValue],
        pattern: ast.pattern,
        env: Mapping[str, Set[AbstractValue]],
    ) -> Dict[str, Set[AbstractValue]]:
        case_env = copy_env(env)

        if isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                case_env = self._refine_env_for_pattern(
                    scope, scope_context, subject_values, pattern.pattern, case_env
                )
            if pattern.name:
                case_env[pattern.name] = set(
                    case_env.get("__match_subject__", subject_values or {UNKNOWN_VALUE})
                )
            return case_env

        if isinstance(pattern, ast.MatchOr):
            merged = copy_env(env)
            for inner in pattern.patterns:
                inner_env = self._refine_env_for_pattern(
                    scope, scope_context, subject_values, inner, env
                )
                merged = join_envs(merged, inner_env)
            return merged

        if isinstance(pattern, ast.MatchValue):
            expected = self._eval_expr(
                scope,
                scope_context,
                pattern.value,
                case_env,
                set(),
                set(),
            )
            return self._refine_name_binding(
                case_env,
                "__match_subject__",
                self._refine_values_with_type_filter(subject_values, expected, True),
            )

        if isinstance(pattern, ast.MatchSingleton):
            expected = {NONE_VALUE} if pattern.value is None else set()
            if expected:
                return self._refine_name_binding(
                    case_env,
                    "__match_subject__",
                    self._refine_values_with_type_filter(subject_values, expected, True),
                )
            return case_env

        if isinstance(pattern, ast.MatchClass):
            type_values = self._resolve_type_expression_values(
                pattern.cls, scope.module, env=case_env
            )
            refined_subject = self._refine_values_with_type_filter(
                subject_values, type_values, True
            )
            case_env["__match_subject__"] = set(refined_subject)
            for index, inner in enumerate(pattern.patterns):
                attr_name = f"#{index}"
                attr_values = {
                    value
                    for subject in refined_subject
                    if subject.kind == "container"
                    for value in self.container_key_values.get(subject.name, {}).get(
                        attr_name, set()
                    )
                }
                case_env = self._refine_env_for_pattern(
                    scope, scope_context, attr_values or {UNKNOWN_VALUE}, inner, case_env
                )
            for attr_name, inner in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                attr_values: Set[AbstractValue] = set()
                for subject in refined_subject:
                    attr_values.update(self._resolve_attribute({subject}, attr_name))
                case_env = self._refine_env_for_pattern(
                    scope, scope_context, attr_values or {UNKNOWN_VALUE}, inner, case_env
                )
            return case_env

        if isinstance(pattern, ast.MatchSequence):
            for index, inner in enumerate(pattern.patterns):
                element_values: Set[AbstractValue] = set()
                for subject in subject_values:
                    if subject.kind == "container":
                        element_values.update(
                            self.container_key_values.get(subject.name, {}).get(
                                f"#{index}", set()
                            )
                        )
                case_env = self._refine_env_for_pattern(
                    scope,
                    scope_context,
                    element_values or {UNKNOWN_VALUE},
                    inner,
                    case_env,
                )
            return case_env

        if isinstance(pattern, ast.MatchMapping):
            for key_node, inner in zip(pattern.keys, pattern.patterns):
                key_names = self._resolve_string_expression_values(
                    key_node, scope.module, env=case_env
                )
                value_set: Set[AbstractValue] = set()
                for subject in subject_values:
                    if subject.kind != "container":
                        continue
                    key_map = self.container_key_values.get(subject.name, {})
                    for key_name in key_names:
                        value_set.update(key_map.get(key_name, set()))
                case_env = self._refine_env_for_pattern(
                    scope, scope_context, value_set or {UNKNOWN_VALUE}, inner, case_env
                )
            if pattern.rest:
                case_env[pattern.rest] = set(subject_values or {UNKNOWN_VALUE})
            return case_env

        if isinstance(pattern, ast.MatchStar):
            if pattern.name:
                case_env[pattern.name] = set(subject_values or {UNKNOWN_VALUE})
            return case_env

        return case_env

    def _exception_handler_values(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        handler: ast.ExceptHandler,
        env: Mapping[str, Set[AbstractValue]],
        callees: Set[str],
        input_changed_scope_contexts: Set[Tuple[str, ContextKey]],
    ) -> Set[AbstractValue]:
        if handler.type is None:
            return {UNKNOWN_VALUE}
        type_values = self._resolve_type_expression_values(
            handler.type,
            scope.module,
            env=env,
        )
        out: Set[AbstractValue] = set()
        for value in type_values:
            if value.kind == CLASS_KIND:
                out.add(make_instance(value.name))
        return out or {UNKNOWN_VALUE}

    def _static_truthiness(
        self,
        expr: ast.AST,
        env: Mapping[str, Set[AbstractValue]],
    ) -> bool | None:
        """Best-effort static truthiness for simple boolean guards."""
        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, bool):
                return expr.value
            return None
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            inner = self._static_truthiness(expr.operand, env)
            return None if inner is None else not inner
        if isinstance(expr, ast.BoolOp):
            values = [self._static_truthiness(value, env) for value in expr.values]
            if isinstance(expr.op, ast.And):
                if any(value is False for value in values):
                    return False
                if values and all(value is True for value in values):
                    return True
                return None
            if isinstance(expr.op, ast.Or):
                if any(value is True for value in values):
                    return True
                if values and all(value is False for value in values):
                    return False
                return None
        return None

    def _refine_env_for_test(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        test: ast.AST,
        env: Mapping[str, Set[AbstractValue]],
        positive: bool,
    ) -> Dict[str, Set[AbstractValue]]:
        if not self.options.refine_type_guards:
            return copy_env(env)

        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._refine_env_for_test(
                scope, scope_context, test.operand, env, not positive
            )

        if isinstance(test, ast.BoolOp):
            if positive and isinstance(test.op, ast.And):
                refined = copy_env(env)
                for value in test.values:
                    refined = self._refine_env_for_test(
                        scope, scope_context, value, refined, True
                    )
                return refined
            if not positive and isinstance(test.op, ast.Or):
                refined = copy_env(env)
                for value in test.values:
                    refined = self._refine_env_for_test(
                        scope, scope_context, value, refined, False
                    )
                return refined
            return copy_env(env)

        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Name)
            and test.func.id in {"isinstance", "issubclass"}
            and len(test.args) >= 2
            and isinstance(test.args[0], ast.Name)
        ):
            target_name = test.args[0].id
            current = set(env.get(target_name, set()))
            if not current:
                return copy_env(env)
            type_values = self._resolve_type_expression_values(
                test.args[1], scope.module, env=env
            )
            refined = self._refine_values_with_type_filter(
                current, type_values, positive
            )
            return self._refine_name_binding(env, target_name, refined)

        if (
            isinstance(test, ast.Call)
            and len(test.args) >= 1
            and isinstance(test.args[0], ast.Name)
        ):
            target_name = test.args[0].id
            guard_targets = self._eval_expr(
                scope,
                scope_context,
                test.func,
                copy_env(env),
                set(),
                set(),
            )
            current = set(env.get(target_name, set()))
            refinements: Set[AbstractValue] = set()
            for guard_target in guard_targets:
                if guard_target.kind != FUNC_KIND:
                    continue
                function_info = self.functions.get(guard_target.name)
                if function_info is None:
                    continue
                refinements.update(
                    self._type_guard_refinement(
                        function_info.return_annotation,
                        function_info.module,
                        env=env,
                    )
                )
            if positive and refinements:
                refined = self._refine_values_with_type_filter(
                    current, refinements, True
                )
                return self._refine_name_binding(env, target_name, refined)

        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Name)
            and test.func.id == "callable"
            and len(test.args) >= 1
            and isinstance(test.args[0], ast.Name)
        ):
            target_name = test.args[0].id
            current = set(env.get(target_name, set()))
            refined = {
                value
                for value in current
                if self._is_callable_value(value) == positive
                or value.kind == UNKNOWN_VALUE.kind
            }
            return self._refine_name_binding(env, target_name, refined)

        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Name)
            and test.func.id == "hasattr"
            and len(test.args) >= 2
            and isinstance(test.args[0], ast.Name)
        ):
            target_name = test.args[0].id
            attr_names = self._resolve_string_expression_values(
                test.args[1], scope.module, env=env
            )
            current = set(env.get(target_name, set()))
            refined: Set[AbstractValue] = set()
            for value in current:
                has_attr = any(self._resolve_attribute({value}, attr_name) for attr_name in attr_names)
                if (positive and has_attr) or (not positive and not has_attr):
                    refined.add(value)
                elif value.kind == UNKNOWN_VALUE.kind:
                    refined.add(value)
            return self._refine_name_binding(env, target_name, refined)

        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and len(test.comparators) == 1
            and isinstance(test.left, ast.Name)
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
        ):
            op = test.ops[0]
            if isinstance(op, ast.Is):
                target_name = test.left.id
                current = set(env.get(target_name, set()))
                refined = self._refine_values_with_type_filter(
                    current, {NONE_VALUE}, positive
                )
                return self._refine_name_binding(env, target_name, refined)
            if isinstance(op, ast.IsNot):
                target_name = test.left.id
                current = set(env.get(target_name, set()))
                refined = self._refine_values_with_type_filter(
                    current, {NONE_VALUE}, not positive
                )
                return self._refine_name_binding(env, target_name, refined)

        return copy_env(env)

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
            is_singledispatch = any(
                target.kind == FUNC_KIND and target.name == "functools.singledispatch"
                for target in targets
            ) or self._expr_qualname(decorator) in {
                "singledispatch",
                "functools.singledispatch",
            }
            if is_singledispatch:
                for value in env.get(name, initial_values):
                    if value.kind == FUNC_KIND:
                        self.singledispatch_functions.add(value.name)

            generic_names, dispatch_types = self._singledispatch_registration_payload(
                decorator,
                scope,
                scope_context,
                env,
                callees,
                input_changed_scope_contexts,
            )
            if generic_names:
                for generic_name in generic_names:
                    for callback in env.get(name, initial_values):
                        if callback.kind != FUNC_KIND:
                            continue
                        resolved_types = dispatch_types or self._singledispatch_registration_types(
                            callback.name
                        )
                        self._register_singledispatch_implementation(
                            generic_name,
                            callback.name,
                            resolved_types,
                        )

            registry_owner_values, registry_keys = self._registry_binding_payload(
                decorator,
                scope,
                scope_context,
                env,
                callees,
                input_changed_scope_contexts,
            )
            if registry_owner_values and registry_keys:
                self._assign_reflective_attribute(
                    registry_owner_values,
                    registry_keys,
                    set(env.get(name, initial_values)),
                )
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
            if is_singledispatch or generic_names:
                env[name] = set(initial_values)
            elif registry_owner_values and registry_keys:
                env[name] = set(decorated_values or set()) | set(initial_values)
                if not env[name]:
                    env[name] = {UNKNOWN_VALUE}
            else:
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
            class_info = self.classes.get(scope_name)
            if class_info is not None:
                return class_info.parent_scope is None
            function_info = self.functions.get(scope_name)
            if function_info is None:
                return True
            return function_info.parent_scope is None

        queue_fifo: deque[Tuple[str, ContextKey]] = deque()
        queue_priority: List[Tuple[Tuple[int, int, int, str, str], Tuple[str, ContextKey]]] = []
        queued_reason: Dict[Tuple[str, ContextKey], str] = {}
        in_queue: Set[Tuple[str, ContextKey]] = set()
        iterations = 0
        configured_max = self.options.fixpoint_max_iterations
        max_iterations = (
            max(1, int(configured_max))
            if configured_max is not None
            else max(256, len(self.scopes) * 256)
        )
        self.solver_stats = type(self.solver_stats)()
        self._state_input_fingerprints.clear()
        self._global_module_stamp = 0
        self._global_heap_stamp = 0
        self._global_return_stamp = 0

        def _enqueue(
            scope_name: str,
            scope_context: ContextKey,
            reason_weight: int,
            reason_tag: str,
        ) -> None:
            normalized = self._normalize_context_for_scope(scope_name, scope_context)
            key = (scope_name, normalized)
            if key in in_queue:
                return
            in_queue.add(key)
            queued_reason[key] = reason_tag
            self.solver_stats.states_requeued += 1
            if self.options.requeue_policy == "fifo":
                queue_fifo.append(key)
            else:
                priority = self._prioritize_scope_context(key, reason_weight=reason_weight)
                heapq.heappush(queue_priority, (priority, key))
            self.solver_stats.max_queue_size = max(
                self.solver_stats.max_queue_size, len(in_queue)
            )

        for scope_name in self.scopes:
            if _is_seed_scope(scope_name):
                _enqueue(
                    scope_name,
                    self._root_context(),
                    reason_weight=4,
                    reason_tag="seed",
                )

        def _has_pending() -> bool:
            return bool(queue_fifo) if self.options.requeue_policy == "fifo" else bool(queue_priority)

        while _has_pending() and iterations < max_iterations:
            iterations += 1
            if self.options.requeue_policy == "fifo":
                scope_name, scope_context = queue_fifo.popleft()
            else:
                _priority, (scope_name, scope_context) = heapq.heappop(queue_priority)
            reason_tag = queued_reason.pop((scope_name, scope_context), "unknown")
            in_queue.discard((scope_name, scope_context))
            self._analyzed_scope_contexts.add((scope_name, scope_context))
            scope = self.scopes[scope_name]

            fingerprint = self._scope_state_fingerprint(scope, scope_context)
            if (
                reason_tag == "inputs_changed"
                and self._state_input_fingerprints.get((scope_name, scope_context))
                == fingerprint
            ):
                continue
            self._state_input_fingerprints[(scope_name, scope_context)] = fingerprint
            self.solver_stats.states_analyzed += 1

            result = self._analyze_scope(scope, scope_context)
            scope_ctx_key = (scope_name, scope_context)

            previous_returns = self.scope_returns.get(scope_ctx_key, set())
            previous_callees = self.scope_callees.get(scope_ctx_key, set())
            capped_returns = self._cap_values(
                set(result.returns),
                preserve_callables=True,
            )
            returns_changed = previous_returns != capped_returns
            callees_changed = previous_callees != result.callees
            if returns_changed:
                self.scope_returns[scope_ctx_key] = set(capped_returns)
                self._global_return_stamp += 1
            if callees_changed:
                self.scope_callees[scope_ctx_key] = set(result.callees)

            for callee_scope, callee_context in result.input_changed_scope_contexts:
                _enqueue(
                    callee_scope,
                    callee_context,
                    reason_weight=5,
                    reason_tag="inputs_changed",
                )

            changed = (
                returns_changed
                or callees_changed
                or result.module_binding_changed
                or bool(result.changed_instance_fields)
                or bool(result.changed_class_fields)
                or result.changed_container_state
                or result.nonlocal_binding_changed
                or result.singledispatch_changed
            )
            if changed:
                impacted: Set[Tuple[str, ContextKey]] = set()
                if (
                    returns_changed
                    or callees_changed
                    or result.nonlocal_binding_changed
                ):
                    impacted.update(self.call_dependents.get(scope_ctx_key, set()))
                    if result.nonlocal_binding_changed:
                        self._global_module_stamp += 1
                if result.module_binding_changed:
                    self._global_module_stamp += 1
                    impacted.update(self.module_dependents.get(scope.module, set()))
                for field_key in result.changed_instance_fields:
                    impacted.update(
                        self.instance_field_dependents.get(field_key, set())
                    )
                for field_key in result.changed_class_fields:
                    impacted.update(self.class_field_dependents.get(field_key, set()))
                if (
                    result.changed_instance_fields
                    or result.changed_class_fields
                    or result.changed_container_state
                ):
                    self._global_heap_stamp += 1
                if result.changed_container_state:
                    impacted.update(self._known_scope_contexts())
                if result.singledispatch_changed:
                    impacted.update(self._known_scope_contexts())
                for candidate in impacted:
                    reason_weight = 1
                    if (
                        returns_changed
                        or callees_changed
                        or result.nonlocal_binding_changed
                    ):
                        reason_weight = max(reason_weight, 4)
                    if (
                        result.module_binding_changed
                        or result.changed_instance_fields
                        or result.changed_class_fields
                    ):
                        reason_weight = max(reason_weight, 3)
                    _enqueue(
                        candidate[0],
                        candidate[1],
                        reason_weight=reason_weight,
                        reason_tag=(
                            "global_invalidation"
                            if result.singledispatch_changed
                            else "state_changed"
                        ),
                    )

        self.fixpoint_iterations = iterations
        self.fixpoint_truncated = _has_pending()
        self.solver_stats.iterations = iterations
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
        previous_active_changed_instance_fields = self._active_changed_instance_fields
        previous_active_changed_class_fields = self._active_changed_class_fields
        previous_active_changed_container_state = self._active_changed_container_state
        previous_active_changed_closure_scopes = self._active_changed_closure_scopes
        previous_active_singledispatch_changed = self._active_singledispatch_changed
        self._active_scope_context = scope_ctx_key
        self._active_changed_instance_fields = set()
        self._active_changed_class_fields = set()
        self._active_changed_container_state = False
        self._active_changed_closure_scopes = set()
        self._active_singledispatch_changed = False
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
        class_definition_env = copy_env(env) if scope.class_owner else None

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
                class_definition_env=class_definition_env,
            )
            returns.update(block_returns)
            callees.update(block_callees)
            input_changed_scope_contexts.update(block_inputs)
            changed_instance_fields.update(self._active_changed_instance_fields)
            changed_class_fields.update(self._active_changed_class_fields)
            input_changed_scope_contexts.update(self._active_changed_closure_scopes)

            if scope.class_owner is not None:
                class_info = self.classes.get(scope.class_owner)
                class_bindings = self.class_fields[scope.class_owner]
                for name, values in env.items():
                    if (
                        name == "__match_subject__"
                        or name in scope.global_names
                        or name in scope.nonlocal_names
                        or (class_info is not None and name in class_info.methods)
                    ):
                        continue
                    if (
                        class_definition_env is not None
                        and values == class_definition_env.get(name, set())
                    ):
                        continue
                    current = class_bindings[name]
                    if self._merge_value_set(
                        current,
                        set(values),
                        preserve_callables=True,
                    ):
                        changed_class_fields.add((scope.class_owner, name))

            module_binding_changed = False
            if scope.name == scope.module:
                module_bindings = self.module_bindings.setdefault(scope.module, {})
                module_binding_changed = self._merge_bindings(module_bindings, env)
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
                changed_container_state=bool(self._active_changed_container_state),
                nonlocal_binding_changed=global_changed or nonlocal_changed,
                singledispatch_changed=self._active_singledispatch_changed,
            )
        finally:
            self._active_scope_context = previous_active_scope_context
            self._active_changed_instance_fields = previous_active_changed_instance_fields
            self._active_changed_class_fields = previous_active_changed_class_fields
            self._active_changed_container_state = previous_active_changed_container_state
            self._active_changed_closure_scopes = previous_active_changed_closure_scopes
            self._active_singledispatch_changed = previous_active_singledispatch_changed

    def _process_block(
        self,
        scope: ScopeInfo,
        scope_context: ContextKey,
        statements: Sequence[ast.stmt],
        env: Dict[str, Set[AbstractValue]],
        class_definition_env: Dict[str, Set[AbstractValue]] | None = None,
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

            elif isinstance(stmt, ast.While):
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

            elif isinstance(stmt, ast.Match):
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
                env = self._refine_env_for_test(
                    scope, scope_context, stmt.test, env, True
                )

            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if target.id in scope.global_names:
                            env.pop(target.id, None)
                            global_writes[target.id] = set()
                            continue
                        if target.id in scope.nonlocal_names:
                            env.pop(target.id, None)
                            nonlocal_writes[target.id] = set()
                            continue
                        env.pop(target.id, None)
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

            elif isinstance(stmt, (ast.Break, ast.Continue)):
                falls_through = False

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
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
                            if scope.class_owner is not None and class_definition_env is not None
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

            elif isinstance(stmt, ast.ClassDef):
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
                            if scope.class_owner is not None and class_definition_env is not None
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
