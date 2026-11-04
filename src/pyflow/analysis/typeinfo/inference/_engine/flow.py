"""Execute statements, loops, assignments, and comprehension bindings."""

from __future__ import annotations

import ast
import contextlib
from dataclasses import replace
from typing import Iterable

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    NONE_TYPE,
    Instance,
    NeverType,
    ProperType,
    TupleType,
    TypeType,
    UnionType,
)
from pyflow.analysis.typeinfo.inference._engine.component import InferenceComponent
from pyflow.analysis.typeinfo.inference._engine.state import _FunctionInfo, _Outcome
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue, join_all
from pyflow.analysis.typeinfo.resolution.annotations import BuiltinTypeLookup


class FlowInference(InferenceComponent):
    """Execute statements, loops, assignments, and comprehension bindings."""

    def _execute_block(
        self,
        statements: Iterable[ast.stmt],
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        current = dict(environment)
        returns: list[AbstractTypeValue] = []
        yields: list[AbstractTypeValue] = []
        terminated = False
        breaks = False
        continues = False
        break_envs: list[dict[str, AbstractTypeValue]] = []
        continue_envs: list[dict[str, AbstractTypeValue]] = []
        for statement in statements:
            outcome = self._execute_statement(
                statement,
                current,
                scope=scope,
                current_function=current_function,
            )
            current = outcome.environment
            returns.extend(outcome.returns)
            yields.extend(outcome.yields)
            breaks = breaks or outcome.breaks
            continues = continues or outcome.continues
            break_envs.extend(outcome.break_envs)
            continue_envs.extend(outcome.continue_envs)
            if outcome.terminated:
                terminated = True
                break
        return _Outcome(
            current,
            returns,
            yields,
            terminated,
            breaks=breaks,
            continues=continues,
            break_envs=break_envs,
            continue_envs=continue_envs,
        )

    def _execute_statement(
        self,
        node: ast.stmt,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        result = dict(environment)
        if isinstance(node, getattr(ast, "TypeAlias", ())):
            previous_vars = dict(self.engine._type_vars)
            self.engine._type_vars.update(
                self.engine._declaration_rules._pep695_type_variables(node)
            )
            result[node.name.id] = self.engine._declaration_rules._annotation_value(node.value)
            self.engine._type_vars = previous_vars
            return _Outcome(result)
        if isinstance(node, ast.Assign):
            target = node.targets[0] if len(node.targets) == 1 else None
            if (
                isinstance(target, ast.Name)
                and target.id in self.engine._type_aliases
                and self.engine._declaration_rules._is_type_alias_expression(node.value)
            ):
                alias_val = self.engine._declaration_rules._annotation_value(node.value)
                if not alias_val.is_bottom and alias_val.types:
                    # ``Alias = SomeClass`` / ``Alias = list[int]`` are both
                    # typing aliases and runtime class-object values.
                    class_targets: frozenset[str] = frozenset()
                    if isinstance(node.value, (ast.Name, ast.Attribute)):
                        runtime = self.engine._expression_rules._evaluate_expression(
                            node.value,
                            result,
                            scope=scope,
                            current_function=current_function,
                        )
                        class_targets = runtime.class_targets
                        proxy = alias_val.public_type()
                        if (
                            not class_targets
                            and isinstance(proxy, Instance)
                            and isinstance(proxy.type.raw_type, type)
                        ):
                            class_targets = frozenset((proxy.type.full_name,))
                    elif isinstance(node.value, ast.Subscript) and isinstance(
                        node.value.value, ast.Name
                    ):
                        # ``list[int]`` / ``MyGeneric[int]`` used as a value is
                        # a class object; typing forms such as ``Union[...]``
                        # have no class target and must not be evaluated as
                        # runtime subscripts.
                        base_value = self.engine._member_rules._name_value(
                            node.value.value.id, result, scope
                        )
                        if base_value.class_targets:
                            runtime = self.engine._expression_rules._evaluate_expression(
                                node.value,
                                result,
                                scope=scope,
                                current_function=current_function,
                            )
                            class_targets = runtime.class_targets
                    if class_targets:
                        alias_val = replace(alias_val, class_targets=class_targets)
                    self._assign_target(target, alias_val, result, current_function)
                    return _Outcome(result)
            value = self.engine._expression_rules._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            if self.engine._value_rules._is_never_value(value):
                return _Outcome(result, terminated=True)
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(
                    node.value,
                    (
                        ast.Constant,
                        ast.List,
                        ast.Tuple,
                        ast.Set,
                        ast.Dict,
                        ast.JoinedStr,
                        ast.Name,
                    ),
                ):
                    # Only obvious rebindings are checked here.  Call results
                    # carry cross-module summary imprecision (overloads,
                    # third-party returns), which would turn into noise.
                    declaration = self.engine._declared_annotations.get(f"{scope}.{target.id}")
                    if declaration is not None and node.lineno >= declaration[0]:
                        self.engine._compatibility_rules._check_annotation_compatibility(
                            value,
                            AbstractTypeValue.from_type(declaration[1]),
                            node,
                            context=f"assignment to {target.id}",
                        )
                if isinstance(target, ast.Name):
                    if target.id in self.engine._type_vars:
                        tv_val = AbstractTypeValue.from_type(self.engine._type_vars[target.id])
                        self._assign_target(target, tv_val, result, current_function)
                        continue
                self._assign_target(target, value, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id in self.engine._type_aliases
                and self.engine._value_rules._qualified_callee_name(node.annotation)
                in {"typing.TypeAlias", "typing_extensions.TypeAlias"}
            ):
                result[node.target.id] = self.engine._declaration_rules._annotation_value(
                    node.value
                )
                return _Outcome(result)
            annotated = self.engine._declaration_rules._annotation_value(node.annotation)
            if isinstance(node.target, ast.Name):
                declared = annotated.public_type()
                if declared is not None and not annotated.unknown:
                    self.engine._declared_annotations[f"{scope}.{node.target.id}"] = (
                        node.lineno,
                        declared,
                    )
            inferred: AbstractTypeValue | None = None
            if node.value is not None:
                inferred = self.engine._expression_rules._evaluate_expression(
                    node.value,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
                if self.engine._value_rules._is_never_value(inferred):
                    return _Outcome(result, terminated=True)
                if not self.engine._compatibility_rules._is_substituted_type_variable_annotation(
                    node.annotation, annotated
                ):
                    self.engine._compatibility_rules._check_annotation_compatibility(
                        inferred, annotated, node, context="annotated assignment"
                    )
            is_bare_qualifier = (
                isinstance(node.annotation, ast.Name)
                and node.annotation.id in {"Final", "ClassVar"}
            ) or (
                isinstance(node.annotation, ast.Attribute)
                and node.annotation.attr in {"Final", "ClassVar"}
            )
            if inferred is not None and (
                annotated.unknown or not annotated.types or is_bare_qualifier
            ):
                # An unresolved annotation or bare qualifier is not evidence that the value has
                # no type.  Keep the value evidence instead of propagating a
                # synthetic placeholder for the missing annotation.
                self._assign_target(node.target, inferred, result, current_function)
            else:
                self._assign_target(node.target, annotated, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.AugAssign):
            left = self.engine._expression_rules._evaluate_expression(
                node.target, result, scope=scope, current_function=current_function
            )
            right = self.engine._expression_rules._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            if self.engine._value_rules._is_never_value(
                left
            ) or self.engine._value_rules._is_never_value(right):
                return _Outcome(result, terminated=True)
            value = self.engine._operator_rules._binary_result(left, right, node.op)
            self._assign_target(node.target, value, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.Expr):
            value = self.engine._expression_rules._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            return _Outcome(
                result,
                terminated=self.engine._value_rules._is_never_value(value),
            )

        if isinstance(node, ast.Return):
            value = (
                AbstractTypeValue.from_type(NONE_TYPE)
                if node.value is None
                else self.engine._expression_rules._evaluate_expression(
                    node.value,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
            )
            return _Outcome(result, returns=[value], terminated=True)

        if isinstance(node, ast.Assert):
            test = self.engine._expression_rules._evaluate_expression(
                node.test, result, scope=scope, current_function=current_function
            )
            if (
                self.engine._value_rules._is_never_value(test)
                or isinstance(node.test, ast.Constant)
                and not node.test.value
            ):
                return _Outcome(result, terminated=True)
            narrowed = self.engine._narrowing_rules._narrow_environment(
                node.test, result, truthy=True
            )
            return _Outcome(
                narrowed, terminated=any(value.is_bottom for value in narrowed.values())
            )

        if isinstance(node, ast.If):
            test = self.engine._expression_rules._evaluate_expression(
                node.test, result, scope=scope, current_function=current_function
            )
            if self.engine._value_rules._is_never_value(test):
                return _Outcome(result, terminated=True)
            true_env = self.engine._narrowing_rules._narrow_environment(
                node.test, result, truthy=True
            )
            false_env = self.engine._narrowing_rules._narrow_environment(
                node.test, result, truthy=False
            )
            true_outcome = (
                _Outcome(true_env, terminated=True)
                if any(value.is_bottom for value in true_env.values())
                else self._execute_block(
                    node.body,
                    true_env,
                    scope=scope,
                    current_function=current_function,
                )
            )
            false_outcome = (
                _Outcome(false_env, terminated=True)
                if any(value.is_bottom for value in false_env.values())
                else self._execute_block(
                    node.orelse,
                    false_env,
                    scope=scope,
                    current_function=current_function,
                )
            )
            self.engine._value_rules._fill_missing_attribute_joins(
                result, true_outcome.environment, false_outcome.environment
            )
            if true_outcome.terminated and not false_outcome.terminated:
                merged = false_outcome.environment
            elif false_outcome.terminated and not true_outcome.terminated:
                merged = true_outcome.environment
            else:
                merged = self.engine._value_rules._join_environments(
                    true_outcome.environment, false_outcome.environment
                )
            return _Outcome(
                merged,
                true_outcome.returns + false_outcome.returns,
                true_outcome.yields + false_outcome.yields,
                true_outcome.terminated and false_outcome.terminated,
                breaks=true_outcome.breaks or false_outcome.breaks,
                continues=true_outcome.continues or false_outcome.continues,
                break_envs=true_outcome.break_envs + false_outcome.break_envs,
                continue_envs=true_outcome.continue_envs + false_outcome.continue_envs,
            )

        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            return self._execute_loop(
                node,
                result,
                scope=scope,
                current_function=current_function,
            )

        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                context = self.engine._expression_rules._evaluate_expression(
                    item.context_expr,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
                if self.engine._value_rules._is_never_value(context):
                    return _Outcome(result, terminated=True)
                method = "__aenter__" if isinstance(node, ast.AsyncWith) else "__enter__"
                attribute = ast.copy_location(
                    ast.Attribute(value=item.context_expr, attr=method, ctx=ast.Load()),
                    item.context_expr,
                )
                alternatives = []
                for typ in context.types:
                    expected_context = (
                        contextlib.AbstractAsyncContextManager
                        if isinstance(node, ast.AsyncWith)
                        else contextlib.AbstractContextManager
                    )
                    if (
                        isinstance(typ, Instance)
                        and typ.type.raw_type is expected_context
                        and typ.args
                    ):
                        alternatives.append(AbstractTypeValue.from_type(typ.args[0]))
                        continue
                    base = AbstractTypeValue.from_type(typ)
                    value = self.engine._builtin_rules._call_attribute(
                        attribute, base, [], {}, result
                    )
                    if value is None:
                        value = self.engine._value_rules._callable_return_type(
                            self.engine._member_rules._attribute_value(base, method)
                        )
                    if isinstance(
                        node, ast.AsyncWith
                    ) and not self.engine._value_rules._is_never_value(value):
                        value = self.engine._value_rules._unwrap_single_generic(value)
                    alternatives.append(value)
                if context.unknown or not alternatives:
                    alternatives.append(AbstractTypeValue.unresolved())
                entered = join_all(
                    alternatives,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )
                if entered.unknown and item.optional_vars is not None:
                    self.engine._add_diagnostic(
                        "unmodeled-context-manager",
                        f"Cannot resolve context manager {method}; bound value remains unknown",
                        node=item.context_expr,
                        affects_completeness=True,
                    )
                if self.engine._value_rules._is_never_value(entered):
                    return _Outcome(result, terminated=True)
                if item.optional_vars is not None:
                    self._assign_target(
                        item.optional_vars,
                        entered,
                        result,
                        current_function,
                    )
            return self._execute_block(
                node.body,
                result,
                scope=scope,
                current_function=current_function,
            )

        if isinstance(node, ast.Try) or (hasattr(ast, "TryStar") and isinstance(node, ast.TryStar)):
            outcomes = [
                self._execute_block(
                    node.body,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
            ]
            for handler in node.handlers:
                handler_env = dict(result)
                if handler.name:
                    exception_type = (
                        self.engine._expression_rules._evaluate_type_expression(handler.type)
                        if handler.type is not None
                        else self.engine._value_rules._instance(BaseException)
                    )
                    handler_env[handler.name] = exception_type
                outcomes.append(
                    self._execute_block(
                        handler.body,
                        handler_env,
                        scope=scope,
                        current_function=current_function,
                    )
                )
            if node.orelse and not outcomes[0].terminated:
                body = outcomes[0]
                otherwise = self._execute_block(
                    node.orelse, body.environment, scope=scope, current_function=current_function
                )
                outcomes[0] = _Outcome(
                    otherwise.environment,
                    body.returns + otherwise.returns,
                    body.yields + otherwise.yields,
                    otherwise.terminated,
                    breaks=body.breaks or otherwise.breaks,
                    continues=body.continues or otherwise.continues,
                    break_envs=body.break_envs + otherwise.break_envs,
                    continue_envs=body.continue_envs + otherwise.continue_envs,
                )
            break_envs = [env for outcome in outcomes for env in outcome.break_envs]
            continue_envs = [env for outcome in outcomes for env in outcome.continue_envs]
            active = [outcome.environment for outcome in outcomes if not outcome.terminated]
            merged = self.engine._value_rules._join_many_environments(
                active if active else [outcome.environment for outcome in outcomes]
            )
            returns = [value for outcome in outcomes for value in outcome.returns]
            yields = [value for outcome in outcomes for value in outcome.yields]
            terminated = all(outcome.terminated for outcome in outcomes)
            breaks = any(outcome.breaks for outcome in outcomes)
            continues = any(outcome.continues for outcome in outcomes)
            if node.finalbody:
                final = self._execute_block(
                    node.finalbody, merged, scope=scope, current_function=current_function
                )
                merged = final.environment
                returns = final.returns if final.terminated else returns + final.returns
                yields.extend(final.yields)
                terminated = terminated or final.terminated
                breaks = breaks or final.breaks
                continues = continues or final.continues
                break_envs.extend(final.break_envs)
                continue_envs.extend(final.continue_envs)
            return _Outcome(
                merged,
                returns,
                yields,
                terminated,
                breaks=breaks,
                continues=continues,
                break_envs=break_envs,
                continue_envs=continue_envs,
            )

        if isinstance(node, ast.Match):
            subject = self.engine._expression_rules._evaluate_expression(
                node.subject,
                result,
                scope=scope,
                current_function=current_function,
            )
            if self.engine._value_rules._is_never_value(subject):
                return _Outcome(result, terminated=True)
            match_outcomes: list[_Outcome] = []
            for case in node.cases:
                case_environment = self.engine._narrowing_rules._narrow_pattern(
                    case.pattern,
                    node.subject,
                    subject,
                    result,
                    current_function,
                )
                if case.guard is not None:
                    self.engine._expression_rules._evaluate_expression(
                        case.guard,
                        case_environment,
                        scope=scope,
                        current_function=current_function,
                    )
                    case_environment = self.engine._narrowing_rules._narrow_environment(
                        case.guard, case_environment, truthy=True
                    )
                match_outcomes.append(
                    self._execute_block(
                        case.body,
                        case_environment,
                        scope=scope,
                        current_function=current_function,
                    )
                )
            if not match_outcomes:
                return _Outcome(result)
            return _Outcome(
                self.engine._value_rules._join_many_environments(
                    outcome.environment for outcome in match_outcomes
                ),
                [value for outcome in match_outcomes for value in outcome.returns],
                [value for outcome in match_outcomes for value in outcome.yields],
                all(outcome.terminated for outcome in match_outcomes),
            )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_target = self.engine._function_nodes.get(id(node))
            if function_target is not None:
                nested = self.engine._functions[function_target]
                if function_target.rpartition(".")[0] != self.engine._module_name:
                    for name, value in result.items():
                        old = nested.closure_evidence.get(name, AbstractTypeValue.bottom())
                        nested.closure_evidence[name] = self.engine._value_rules._join(old, value)
                result[node.name] = self.engine._function_rules._function_value(nested)
            return _Outcome(result)

        if isinstance(node, ast.ClassDef):
            qualified = f"{scope}.{node.name}"
            class_info = self.engine._classes.get(qualified)
            if class_info is not None:
                class_environment = dict(result)
                class_environment.update(class_info.attributes)
                enum_class = self.engine._member_rules._is_enum_class_info(class_info)
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        value = self.engine._expression_rules._evaluate_expression(
                            item.value,
                            class_environment,
                            scope=qualified,
                            current_function=current_function,
                        )
                        for target in item.targets:
                            self._assign_target(target, value, class_environment, current_function)
                            for name in ast.walk(target):
                                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                                    if enum_class and not name.id.startswith("_"):
                                        class_info.enum_values[name.id] = value
                                        member = AbstractTypeValue.from_type(class_info.instance)
                                    else:
                                        member = class_environment[name.id]
                                    class_info.attributes[name.id] = member
                                    class_info.instance.type.members[name.id] = (
                                        member.public_type() or ANY
                                    )
                    elif (
                        isinstance(item, ast.AnnAssign)
                        and isinstance(item.target, ast.Name)
                        and item.value is not None
                        and not self.engine._declaration_rules._is_dataclass_pseudo_annotation(
                            item.annotation
                        )
                    ):
                        value = self.engine._expression_rules._evaluate_expression(
                            item.value,
                            class_environment,
                            scope=qualified,
                            current_function=current_function,
                        )
                        annotated = self.engine._declaration_rules._annotation_value(
                            item.annotation
                        )
                        self.engine._compatibility_rules._check_annotation_compatibility(
                            value,
                            annotated,
                            item,
                            context="annotated assignment",
                        )
                        member = annotated if not annotated.unknown and annotated.types else value
                        self._assign_target(
                            item.target,
                            member,
                            class_environment,
                            current_function,
                        )
                        class_info.attributes[item.target.id] = member
                        class_info.instance.type.members[item.target.id] = (
                            member.public_type() or ANY
                        )
                result[node.name] = AbstractTypeValue.from_type(
                    class_info.instance, class_target=qualified
                )
            return _Outcome(result)

        if isinstance(node, ast.Delete):
            for target in node.targets:
                self._invalidate_refinements(result, target)
                if isinstance(target, ast.Name):
                    result.pop(target.id, None)
                else:
                    result.pop(ast.unparse(target), None)
            return _Outcome(result)

        if isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            return _Outcome(
                result,
                terminated=True,
                breaks=isinstance(node, ast.Break),
                continues=isinstance(node, ast.Continue),
                break_envs=[dict(result)] if isinstance(node, ast.Break) else [],
                continue_envs=[dict(result)] if isinstance(node, ast.Continue) else [],
            )

        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                qualified = self.engine._imports.get(local)
                if qualified is None:
                    module = node.module or ""
                    if node.level:
                        module = (
                            self.engine.project_context.resolve_import_name(
                                self.engine._module_name,
                                module or None,
                                node.level,
                                current_path=self.engine._filename,
                            )
                            or module
                        )
                    qualified = f"{module}.{alias.name}" if module else alias.name
                # Typing constructs are handled by their dedicated syntax
                # paths (cast/NewType/TypeVar/overload/aliases).  Binding them
                # as ordinary values would shadow those models.
                if qualified.split(".", 1)[0] in {"typing", "typing_extensions", "__future__"}:
                    continue
                if qualified in {
                    "sys.exit",
                    "os._exit",
                    "typing.assert_never",
                    "typing_extensions.assert_never",
                    "pytest.fail",
                    "pytest.skip",
                    "pytest.xfail",
                    "werkzeug.exceptions.abort",
                    "flask.abort",
                    "flask.helpers.abort",
                }:
                    # These are modelled as non-returning calls.  Binding the
                    # import would make the abort path look shadowed.
                    continue
                external = self.engine._member_rules._external_type(qualified)
                builtin_class = False
                if external is None:
                    external = BuiltinTypeLookup()(qualified)
                    builtin_class = external is not None
                if external is None:
                    global_value = self.engine._stdlib_rules._stdlib_global_value(qualified)
                    if global_value is not None:
                        result[local] = global_value
                        continue
                if external is None:
                    if self.engine.project_context.find_module(qualified) is not None:
                        # from . import submodule keeps the module itself
                        # unresolved; attribute access resolves through imports.
                        continue
                    result[local] = AbstractTypeValue.unresolved()
                    continue
                if isinstance(external, TypeType):
                    external = external.item
                result[local] = AbstractTypeValue.from_type(
                    external,
                    class_target=self.engine._member_rules._external_class_target(
                        external, alias.name, builtin_class=builtin_class
                    ),
                )
            return _Outcome(result)

        if not isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global, ast.Nonlocal)):
            self.engine._add_diagnostic(
                "unsupported-statement",
                f"No type model for {type(node).__name__}",
                node=node,
                affects_completeness=True,
            )
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    result[child.id] = AbstractTypeValue.unresolved()
        return _Outcome(result)

    def _execute_loop(
        self,
        node: ast.While | ast.For | ast.AsyncFor,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        entry = dict(environment)
        head = dict(environment)
        returns: list[AbstractTypeValue] = []
        yields: list[AbstractTypeValue] = []
        break_envs: list[dict[str, AbstractTypeValue]] = []
        continue_envs: list[dict[str, AbstractTypeValue]] = []
        for _ in range(self.engine.options.max_loop_iterations):
            body_env = dict(head)
            if isinstance(node, ast.While):
                test = self.engine._expression_rules._evaluate_expression(
                    node.test,
                    body_env,
                    scope=scope,
                    current_function=current_function,
                )
                if self.engine._value_rules._is_never_value(test):
                    return _Outcome(body_env, returns, yields, terminated=True)
                body_env = self.engine._narrowing_rules._narrow_environment(
                    node.test, body_env, truthy=True
                )
            else:
                iterable = self.engine._expression_rules._evaluate_expression(
                    node.iter,
                    body_env,
                    scope=scope,
                    current_function=current_function,
                )
                if self.engine._value_rules._is_never_value(iterable):
                    return _Outcome(body_env, returns, yields, terminated=True)
                self._assign_target(
                    node.target,
                    self.engine._value_rules._iterable_element(iterable),
                    body_env,
                    current_function,
                )
            outcome = self._execute_block(
                node.body,
                body_env,
                scope=scope,
                current_function=current_function,
            )
            returns.extend(outcome.returns)
            yields.extend(outcome.yields)
            break_envs.extend(outcome.break_envs)
            continue_envs.extend(outcome.continue_envs)
            next_head = self.engine._value_rules._join_environments(entry, outcome.environment)
            for continue_env in outcome.continue_envs:
                next_head = self.engine._value_rules._join_environments(next_head, continue_env)
            if next_head == head:
                head = next_head
                break
            head = next_head
        else:
            self.engine._add_diagnostic(
                "loop-widened",
                "Loop inference reached its local iteration limit",
                node=node,
                severity="information",
            )

        orelse = self._execute_block(
            node.orelse,
            head,
            scope=scope,
            current_function=current_function,
        )
        returns.extend(orelse.returns)
        yields.extend(orelse.yields)
        exit_env = orelse.environment
        for break_env in [*break_envs, *continue_envs]:
            exit_env = self.engine._value_rules._join_environments(exit_env, break_env)

        class BreakFinder(ast.NodeVisitor):
            found = False

            def visit_Break(self, child):
                self.found = True

            def visit_For(self, child):
                pass

            def visit_AsyncFor(self, child):
                pass

            def visit_While(self, child):
                pass

            def visit_FunctionDef(self, child):
                pass

            def visit_AsyncFunctionDef(self, child):
                pass

            def visit_ClassDef(self, child):
                pass

        finder = BreakFinder()
        for statement in node.body:
            finder.visit(statement)
        infinite = (
            isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and bool(node.test.value)
            and not finder.found
        )
        return _Outcome(exit_env, returns, yields, terminated=infinite)

    def _update_environment_receiver(
        self,
        environment: dict[str, AbstractTypeValue],
        receiver: ast.expr,
        new_value: AbstractTypeValue,
    ) -> None:
        """Widen a mutated container and every environment name aliasing it."""
        key = receiver.id if isinstance(receiver, ast.Name) else ast.unparse(receiver)
        old = environment.get(key)
        environment[key] = new_value
        if isinstance(receiver, ast.Name):
            current = self.engine._current_function_info
            if current is not None:
                name = receiver.id
                if name in current.closure_evidence:
                    current.closure_evidence[name] = new_value
                    current.mutated_closure_names.add(name)
                    parent = self._enclosing_function(current)
                    if parent is not None:
                        previous = parent.closure_evidence.get(name, AbstractTypeValue.bottom())
                        parent.closure_evidence[name] = self.engine._value_rules._join(
                            previous, new_value
                        )
                        parent.mutated_closure_names.add(name)
                if name in current.global_names:
                    self.engine._module_environment[name] = new_value
        if old is None:
            return
        # Abstract values are immutable, so an actual alias (``b = a``)
        # shares the same object.  Do not compare with ``==``: two distinct
        # empty list/set literals compare equal and widening one must not
        # silently change the inferred element type of the other.
        for name, value in list(environment.items()):
            if name != key and value is old:
                environment[name] = new_value

    def _enclosing_function(self, function: _FunctionInfo) -> _FunctionInfo | None:
        current = function.qualified_name
        while "." in current:
            current = current.rpartition(".")[0]
            parent = self.engine._functions.get(current)
            if parent is not None and parent is not function:
                return parent
        return None

    def _update_nested_closure_evidence(
        self,
        name: str,
        value: AbstractTypeValue,
        current_function: _FunctionInfo,
    ) -> None:
        """Propagate a later enclosing assignment into nested closures."""
        prefix = f"{current_function.qualified_name}."
        for function in self.engine._functions.values():
            if not function.qualified_name.startswith(prefix):
                continue
            previous = function.closure_evidence.get(name)
            if previous is None:
                continue
            function.closure_evidence[name] = self.engine._value_rules._join(previous, value)

    def _assign_starred_unpack(
        self,
        targets: list[ast.expr],
        value: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        star_index = next(
            index for index, target in enumerate(targets) if isinstance(target, ast.Starred)
        )
        tuple_args: list[ProperType] = []
        if len(value.types) == 1:
            only = next(iter(value.types))
            if isinstance(only, TupleType) and not only.unknown_size:
                tuple_args = list(only.args)
        if tuple_args:
            before = targets[:star_index]
            after = targets[star_index + 1 :]
            for target, element in zip(before, tuple_args[: len(before)]):
                self._assign_target(
                    target,
                    AbstractTypeValue.from_type(element),
                    environment,
                    current_function,
                )
            middle_end = len(tuple_args) - len(after)
            middle = tuple_args[len(before) : max(middle_end, len(before))]
            element = join_all(
                (AbstractTypeValue.from_type(item) for item in middle),
                self.engine.type_system,
                max_union_size=self.engine.options.max_union_size,
            )
            star_target = targets[star_index]
            if isinstance(star_target, ast.Starred):
                self._assign_target(
                    star_target.value,
                    self.engine._value_rules._instance(list, element.public_type() or ANY),
                    environment,
                    current_function,
                )
            for target, element in zip(after, tuple_args[-len(after) :] if after else ()):
                self._assign_target(
                    target,
                    AbstractTypeValue.from_type(element),
                    environment,
                    current_function,
                )
            return
        element = self.engine._value_rules._iterable_element(value)
        for index, target in enumerate(targets):
            if isinstance(target, ast.Starred):
                self._assign_target(
                    target.value,
                    self.engine._value_rules._instance(list, element.public_type() or ANY),
                    environment,
                    current_function,
                )
            else:
                self._assign_target(target, element, environment, current_function)

    def _assign_target(
        self,
        target: ast.expr,
        value: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        if isinstance(target, ast.Name):
            self._invalidate_refinements(environment, target)
            environment[target.id] = value
            self.engine._record_expression(target, value)
            if current_function is not None:
                if target.id in current_function.global_names:
                    self.engine._module_environment[target.id] = value
                if target.id in current_function.nonlocal_names:
                    parent = self._enclosing_function(current_function)
                    if parent is not None:
                        old = parent.closure_evidence.get(target.id, AbstractTypeValue.bottom())
                        parent.closure_evidence[target.id] = self.engine._value_rules._join(
                            old, value
                        )
                self._update_nested_closure_evidence(target.id, value, current_function)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if any(isinstance(child, ast.Starred) for child in target.elts):
                self._assign_starred_unpack(
                    target.elts,
                    value,
                    environment,
                    current_function,
                )
                return
            unpacked = self._unpack_value(value, len(target.elts))
            for child, child_value in zip(target.elts, unpacked):
                self._assign_target(child, child_value, environment, current_function)
            return
        if isinstance(target, ast.Attribute):
            key = ast.unparse(target)
            self._invalidate_refinements(environment, target)
            property_value = self._property_assignment_value(target, environment)
            if property_value is not None:
                # A property setter's parameter type does not change the
                # getter result type observed by subsequent reads.
                value = property_value
            environment[key] = value
            self.engine._record_expression(target, value)
            if (
                current_function is not None
                and current_function.owner is not None
                and isinstance(target.value, ast.Name)
                and current_function.parameter_names
                and target.value.id == current_function.parameter_names[0]
            ):
                key = (current_function.owner, target.attr)
                old = self.engine._pending_attributes.get(key, AbstractTypeValue.bottom())
                self.engine._pending_attributes[key] = self.engine._value_rules._join(old, value)
            return
        if isinstance(target, ast.Subscript):
            self._invalidate_refinements(environment, target)
            if not isinstance(target.slice, ast.Slice):
                environment[ast.unparse(target)] = value
            self.engine._record_expression(target, value)
            if not isinstance(target.value, ast.Name):
                return
            if isinstance(target.slice, ast.Slice):
                value = self.engine._value_rules._iterable_element(value)
            name = target.value.id
            base = environment.get(name, AbstractTypeValue.unresolved())
            updated: list[AbstractTypeValue] = []
            for typ in base.types:
                if isinstance(typ, Instance) and typ.type.raw_type is dict:
                    key_type = typ.args[0] if typ.args else ANY
                    old_value = typ.args[1] if len(typ.args) > 1 else ANY
                    if isinstance(target.slice, ast.Constant):
                        key_value = AbstractTypeValue.from_type(
                            self.engine._value_rules._proper_instance(type(target.slice.value))
                        )
                    else:
                        key_value = environment.get(ast.unparse(target.slice))
                    if key_value is not None and (key_value.types or not key_value.unknown):
                        new_key = key_value.public_type() or ANY
                        if isinstance(key_type, (AnyType, NeverType)):
                            key_type = new_key
                        else:
                            key_type = (
                                self.engine._value_rules._join(
                                    AbstractTypeValue.from_type(key_type),
                                    AbstractTypeValue.from_type(new_key),
                                ).public_type()
                                or ANY
                            )
                    if isinstance(old_value, (AnyType, NeverType)):
                        joined = value
                    else:
                        joined = self.engine._value_rules._join(
                            AbstractTypeValue.from_type(old_value), value
                        )
                    updated.append(
                        self.engine._value_rules._instance(
                            dict, key_type, joined.public_type() or ANY
                        )
                    )
                elif isinstance(typ, Instance) and typ.type.raw_type is list:
                    old_value = typ.args[0] if typ.args else ANY
                    joined = self.engine._value_rules._join(
                        AbstractTypeValue.from_type(old_value), value
                    )
                    updated.append(
                        self.engine._value_rules._instance(list, joined.public_type() or ANY)
                    )
            if updated:
                environment[name] = join_all(
                    updated,
                    self.engine.type_system,
                    max_union_size=self.engine.options.max_union_size,
                )

    def _property_assignment_value(
        self,
        target: ast.Attribute,
        environment: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        if not isinstance(target.value, ast.Name):
            return None
        base = environment.get(target.value.id)
        if base is None:
            return None
        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            info = self.engine._classes.get(typ.type.full_name)
            if info is None or target.attr not in info.properties:
                continue
            getter = self.engine._member_rules._class_property(info.qualified_name, target.attr)
            function = self.engine._functions.get(getter) if getter is not None else None
            if function is not None:
                if function.explicit_return is not None:
                    return function.explicit_return
                if function.summary is not None and function.summary.return_type is not None:
                    return AbstractTypeValue.from_type(function.summary.return_type)
        return None

    @staticmethod
    def _invalidate_refinements(environment, target):
        assigned = ast.unparse(target)
        for key in tuple(environment):
            if key.startswith((assigned + ".", assigned + "[")):
                environment.pop(key)
            elif "[" in key:
                if isinstance(target, ast.Subscript):
                    environment.pop(key)
                    continue
                try:
                    expression = ast.parse(key, mode="eval")
                except SyntaxError:
                    continue
                if any(
                    isinstance(child, (ast.Name, ast.Attribute)) and ast.unparse(child) == assigned
                    for child in ast.walk(expression)
                ):
                    environment.pop(key)

    def _unpack_value(self, value: AbstractTypeValue, count: int) -> list[AbstractTypeValue]:
        value = replace(
            value,
            types=frozenset(
                (
                    TupleType(
                        tuple(typ.type.members.get(name, ANY) for name in typ.type.tuple_fields)
                    )
                    if isinstance(typ, Instance) and typ.type.tuple_fields is not None
                    else typ
                )
                for typ in value.types
            ),
        )
        alternatives = [
            part
            for typ in value.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        tuples = [
            typ
            for typ in alternatives
            if isinstance(typ, TupleType) and (typ.unknown_size or len(typ.args) == count)
        ]
        if tuples and all(isinstance(typ, TupleType) for typ in alternatives):
            return [
                join_all(
                    (
                        AbstractTypeValue.from_type(
                            (typ.args[0] if typ.args else ANY)
                            if typ.unknown_size
                            else typ.args[position]
                        )
                        for typ in tuples
                    ),
                    self.engine.type_system,
                )
                for position in range(count)
            ]
        element = self.engine._value_rules._iterable_element(value)
        return [element] * count

    def _propagate_comprehension_walrus(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        local_environment: dict[str, AbstractTypeValue],
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        expressions: list[ast.expr] = []
        for generator in node.generators:
            expressions.extend(generator.ifs)
        if isinstance(node, ast.DictComp):
            expressions.extend((node.key, node.value))
        else:
            expressions.append(node.elt)
        for expression in expressions:
            for child in ast.walk(expression):
                if (
                    isinstance(child, ast.NamedExpr)
                    and isinstance(child.target, ast.Name)
                    and child.target.id in local_environment
                ):
                    self._assign_target(
                        child.target,
                        local_environment[child.target.id],
                        environment,
                        current_function,
                    )

    def _comprehension_environment(
        self,
        generators: list[ast.comprehension],
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> dict[str, AbstractTypeValue]:
        result = dict(environment)
        for generator in generators:
            iterable = self.engine._expression_rules._evaluate_expression(
                generator.iter,
                result,
                scope=scope,
                current_function=current_function,
            )
            self._assign_target(
                generator.target,
                self.engine._value_rules._iterable_element(iterable),
                result,
                current_function,
            )
            for condition in generator.ifs:
                if any(isinstance(child, ast.NamedExpr) for child in ast.walk(condition)):
                    # Comprehension filters are only narrowed today, so a
                    # walrus target would otherwise never receive its value.
                    self.engine._expression_rules._evaluate_expression(
                        condition,
                        result,
                        scope=scope,
                        current_function=current_function,
                    )
                result = self.engine._narrowing_rules._narrow_environment(
                    condition, result, truthy=True
                )
        return result
