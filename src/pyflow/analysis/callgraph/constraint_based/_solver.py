"""Fixpoint solving, scope analysis, and environment refinement."""

from __future__ import annotations

import ast
import heapq
import operator
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


class _FixpointSolverMixin:
    """Fixpoint iteration and per-scope/block analysis."""

    def _is_stub_like_body(self, body: Sequence[ast.stmt]) -> bool:
        """Return whether a function body is only ``...``/``pass`` placeholders."""
        if not body:
            return False
        for stmt in body:
            if isinstance(stmt, ast.Pass):
                continue
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis
            ):
                continue
            return False
        return True

    def _return_annotation_is_type_object(self, annotation: ast.expr | None) -> bool:
        if not isinstance(annotation, ast.Subscript):
            return False
        return self._expr_qualname(annotation.value) in {
            "Type",
            "typing.Type",
            "type",
        }

    def _stub_return_values_from_annotation(
        self,
        scope: ScopeInfo,
    ) -> Set[AbstractValue]:
        """Seed return values for `.pyi`-style functions from return annotations."""
        function_info = self.functions.get(scope.name)
        if (
            function_info is None
            or function_info.return_annotation is None
            or not self._is_stub_like_body(scope.body)
        ):
            return set()

        type_values = self._resolve_type_expression_values(
            function_info.return_annotation,
            function_info.module,
        )
        if self._return_annotation_is_type_object(function_info.return_annotation):
            return set(type_values)

        out: Set[AbstractValue] = set()
        for value in type_values:
            if value.kind == CLASS_KIND:
                out.add(make_instance(value.name))
            else:
                out.add(value)
        return out

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
        flow_bindings = self.scope_flow_bindings.get(scope_key, {})
        normalized_bindings = tuple(
            (
                name,
                tuple(sorted((value.kind, value.name) for value in values)),
            )
            for name, values in sorted(input_bindings.items())
        )
        normalized_flow_bindings = tuple(
            (
                name,
                tuple(sorted((value.kind, value.name) for value in values)),
            )
            for name, values in sorted(flow_bindings.items())
        )
        # Coarse, monotonic side-effect stamps used to avoid redundant re-analysis.
        return hash(
            (
                normalized_bindings,
                normalized_flow_bindings,
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
                    self._refine_values_with_type_filter(
                        subject_values, expected, True
                    ),
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
                    scope,
                    scope_context,
                    attr_values or {UNKNOWN_VALUE},
                    inner,
                    case_env,
                )
            for attr_name, inner in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                attr_values: Set[AbstractValue] = set()
                for subject in refined_subject:
                    attr_values.update(self._resolve_attribute({subject}, attr_name))
                case_env = self._refine_env_for_pattern(
                    scope,
                    scope_context,
                    attr_values or {UNKNOWN_VALUE},
                    inner,
                    case_env,
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
            return bool(expr.value)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return bool(expr.elts)
        if isinstance(expr, ast.Dict):
            return bool(expr.keys)
        if (
            isinstance(expr, ast.Compare)
            and len(expr.ops) == 1
            and len(expr.comparators) == 1
        ):
            try:
                left = ast.literal_eval(expr.left)
                right = ast.literal_eval(expr.comparators[0])
            except (TypeError, ValueError):
                return None
            comparisons = {
                ast.Eq: operator.eq,
                ast.NotEq: operator.ne,
                ast.Lt: operator.lt,
                ast.LtE: operator.le,
                ast.Gt: operator.gt,
                ast.GtE: operator.ge,
                ast.Is: operator.is_,
                ast.IsNot: operator.is_not,
                ast.In: lambda left, right: operator.contains(right, left),
                ast.NotIn: lambda left, right: not operator.contains(right, left),
            }
            operation = next(
                (fn for kind, fn in comparisons.items() if isinstance(expr.ops[0], kind)),
                None,
            )
            if operation is None:
                return None
            try:
                return bool(operation(left, right))
            except (TypeError, ValueError):
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
                has_attr = any(
                    self._resolve_attribute({value}, attr_name)
                    for attr_name in attr_names
                )
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
                        resolved_types = (
                            dispatch_types
                            or self._singledispatch_registration_types(callback.name)
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
            if self.options.analyze_reachable_only:
                # ``main`` is the requested entry module.  Additional modules
                # are available for import/call resolution, but seeding every
                # one as an independent root defeats entry-rooted analysis and
                # makes large repositories converge over unrelated code.
                return scope_name == "main" or (
                    self.options.seed_entry_file_scopes
                    and self.scopes[scope_name].module == "main"
                )
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
        queue_priority: List[
            Tuple[Tuple[int, int, int, str, str], Tuple[str, ContextKey]]
        ] = []
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
                priority = self._prioritize_scope_context(
                    key, reason_weight=reason_weight
                )
                heapq.heappush(queue_priority, (priority, key))
            self.solver_stats.max_queue_size = max(
                self.solver_stats.max_queue_size, len(in_queue)
            )

        root_context = self._root_context()
        for scope_name in self.scopes:
            if _is_seed_scope(scope_name):
                scope = self.scopes[scope_name]
                if (
                    self.options.seed_entry_file_scopes
                    and scope.module == "main"
                    and (scope.method_self_param or scope.method_cls_param)
                ):
                    owner_class = self._owner_class_for_scope(scope_name)
                    if owner_class is not None:
                        normalized = self._normalize_context_for_scope(
                            scope_name, root_context
                        )
                        inputs = self.scope_inputs.setdefault(
                            (scope_name, normalized),
                            {param: set() for param in scope.params},
                        )
                        if scope.method_self_param:
                            self._merge_value_set(
                                inputs.setdefault(scope.method_self_param, set()),
                                {make_instance(owner_class)},
                            )
                        if scope.method_cls_param:
                            self._merge_value_set(
                                inputs.setdefault(scope.method_cls_param, set()),
                                {make_class(owner_class)},
                            )
                _enqueue(
                    scope_name,
                    root_context,
                    reason_weight=4,
                    reason_tag="seed",
                )

        def _has_pending() -> bool:
            return (
                bool(queue_fifo)
                if self.options.requeue_policy == "fifo"
                else bool(queue_priority)
            )

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
                or bool(result.changed_container_keys)
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
                    or result.changed_container_keys
                ):
                    self._global_heap_stamp += 1
                if result.changed_container_keys:
                    impacted.update(
                        self._container_impacted_scope_contexts(
                            result.changed_container_keys
                        )
                    )
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
                        or result.changed_container_keys
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
        scope_ctx_key = (scope.name, scope_context)
        env = copy_env(self.module_bindings.get(scope.module, {}))
        self._merge_bindings(
            env,
            self.scope_flow_bindings.get(scope_ctx_key, {}),
        )
        previous_active_scope_context = self._active_scope_context
        previous_active_changed_instance_fields = self._active_changed_instance_fields
        previous_active_changed_class_fields = self._active_changed_class_fields
        previous_active_changed_container_state = self._active_changed_container_state
        previous_active_changed_closure_scopes = self._active_changed_closure_scopes
        previous_active_singledispatch_changed = self._active_singledispatch_changed
        self._active_scope_context = scope_ctx_key
        self._active_changed_instance_fields = set()
        self._active_changed_class_fields = set()
        self._active_changed_container_state = set()
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
            self._merge_value_set(
                env.setdefault(param, set()),
                set(param_inputs.get(param, set())),
                preserve_callables=True,
            )
        for closure_var in scope.closure_vars:
            captured_values = set(param_inputs.get(closure_var, set()))
            if captured_values:
                self._merge_value_set(
                    env.setdefault(closure_var, set()),
                    captured_values,
                    preserve_callables=True,
                )
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
            if not returns:
                returns.update(self._stub_return_values_from_annotation(scope))
            callees.update(block_callees)
            input_changed_scope_contexts.update(block_inputs)
            changed_instance_fields.update(self._active_changed_instance_fields)
            changed_class_fields.update(self._active_changed_class_fields)
            input_changed_scope_contexts.update(self._active_changed_closure_scopes)

            flow_bindings = self.scope_flow_bindings.setdefault(scope_ctx_key, {})
            if self._merge_bindings(flow_bindings, env):
                input_changed_scope_contexts.add(scope_ctx_key)

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
                changed_container_keys=set(self._active_changed_container_state),
                nonlocal_binding_changed=global_changed or nonlocal_changed,
                singledispatch_changed=self._active_singledispatch_changed,
            )
        finally:
            self._active_scope_context = previous_active_scope_context
            self._active_changed_instance_fields = (
                previous_active_changed_instance_fields
            )
            self._active_changed_class_fields = previous_active_changed_class_fields
            self._active_changed_container_state = (
                previous_active_changed_container_state
            )
            self._active_changed_closure_scopes = previous_active_changed_closure_scopes
            self._active_singledispatch_changed = previous_active_singledispatch_changed
