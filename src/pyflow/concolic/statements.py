"""statement support for the AST executor."""

from __future__ import annotations

import ast

from typing import Any, Iterable

from .runtime import (
    ConcolicError,
    UnsupportedSyntaxError,
    _Break,
    _BoolValue,
    _Branch,
    _BuiltinFunction,
    _BytesValue,
    _ClassValue,
    _ContextManagerFactory,
    _Continue,
    _DequeValue,
    _DictValue,
    _EnumClass,
    _ExceptionType,
    _FloatValue,
    _FilterIteratorValue,
    _FunctionValue,
    _ImportlibFunction,
    _ImportlibModule,
    _InstanceValue,
    _IntValue,
    _ListValue,
    _MapIteratorValue,
    _NamedTupleClass,
    _NamedTupleValue,
    _OperatorAttrGetter,
    _OperatorItemGetter,
    _OperatorMethodCaller,
    _PartialValue,
    _RangeValue,
    _EnumerateIteratorValue,
    _ResumeKind,
    _ResumeOperation,
    _Returned,
    _ResumableFrame,
    _RegexModule,
    _Return,
    _SetValue,
    _StringValue,
    _SummaryFunction,
    _SummaryModule,
    _SuperValue,
    _TargetException,
    _TupleValue,
    _ZipIteratorValue,
)

from .support import _concrete, _exception_name, _handler_matches, _unique_values

from .module_loader import (
    _SUMMARY_MODULES,
    _import_local_module,
    _parameter_nodes,
    _resolve_local_module,
)


class _StatementMixin:
    def run(self) -> tuple[Any, tuple[_Branch, ...]]:
        result = self._call_function_value(
            self._function_value(self._function),
            [self.env[parameter.arg] for parameter in _parameter_nodes(self._function)],
            {},
        )
        if isinstance(result, _ResumableFrame) and result.is_coroutine:
            result = self._drive_coroutine(result)
        self._last_result = result
        return _concrete(result), tuple(self.path)

    def _execute_block(
        self, statements: Iterable[ast.stmt]
    ) -> _Return | _Break | _Continue | None:
        for statement in statements:
            outcome = self._execute_statement(statement)
            if outcome is not None:
                return outcome
        return None

    def _execute_statement(
        self, statement: ast.stmt
    ) -> _Return | _Break | _Continue | None:
        if isinstance(statement, ast.Import):
            self._execute_import(statement)
            return None
        if isinstance(statement, ast.ImportFrom):
            self._execute_import_from(statement)
            return None
        if isinstance(statement, ast.ClassDef):
            class_value = _ClassValue(
                statement, self._current_module, dict(self.env)
            )
            self._assign_name(
                statement.name,
                self._class_value(class_value),
            )
            return None
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            value: Any = _FunctionValue(statement, self.env)
            for decorator in reversed(statement.decorator_list):
                value = self._call_value(self._evaluate(decorator), [value], {})
            self._assign_name(statement.name, value)
            return None
        if isinstance(statement, ast.Global):
            self._global_names.update(statement.names)
            return None
        if isinstance(statement, ast.Nonlocal):
            if self._closure_env is None:
                raise ConcolicError("nonlocal declaration has no enclosing scope")
            self._nonlocal_names.update(statement.names)
            return None
        if isinstance(statement, ast.Assign):
            value = self._evaluate(statement.value)
            for target in statement.targets:
                self._assign(target, value)
            return None
        if isinstance(statement, ast.AnnAssign):
            if statement.value is None:
                return None
            self._assign(statement.target, self._evaluate(statement.value))
            return None
        if isinstance(statement, ast.AugAssign):
            previous = self._evaluate_target(statement.target)
            value = self._evaluate(statement.value)
            if (
                isinstance(statement.op, ast.BitOr)
                and isinstance(previous, _DictValue)
                and isinstance(value, _DictValue)
            ):
                previous.values.update(value.values)
                return None
            if isinstance(previous, _SetValue) and isinstance(
                statement.op, (ast.BitOr, ast.BitAnd, ast.Sub)
            ) and isinstance(value, _SetValue):
                previous.values[:] = self._binary(previous, statement.op, value).values
                return None
            self._assign(statement.target, self._binary(previous, statement.op, value))
            return None
        if isinstance(statement, ast.If):
            condition = self._truthy(self._evaluate(statement.test))
            self.path.append(_Branch(condition.symbolic, condition.concrete))
            return self._execute_block(
                statement.body if condition.concrete else statement.orelse
            )
        if isinstance(statement, ast.While):
            count = 0
            while True:
                if count >= self._max_loop_iterations:
                    raise ConcolicError(
                        "loop exceeded --max-loop-iterations "
                        f"({self._max_loop_iterations})"
                    )
                condition = self._truthy(self._evaluate(statement.test))
                self.path.append(_Branch(condition.symbolic, condition.concrete))
                if not condition.concrete:
                    break
                outcome = self._execute_block(statement.body)
                if isinstance(outcome, _Return):
                    return outcome
                if isinstance(outcome, _Break):
                    break
                count += 1
            if statement.orelse:
                return self._execute_block(statement.orelse)
            return None
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            iterator = self._as_iterator(self._evaluate(statement.iter))
            while True:
                resumed = self._resume_iterator(
                    iterator, _ResumeOperation(_ResumeKind.NEXT)
                )
                if isinstance(resumed, _Returned):
                    if statement.orelse:
                        return self._execute_block(statement.orelse)
                    break
                value = resumed.value
                self._assign(statement.target, value)
                outcome = self._execute_block(statement.body)
                if isinstance(outcome, _Return):
                    return outcome
                if isinstance(outcome, _Break):
                    break
                if isinstance(outcome, _Continue):
                    continue
            return None
        if isinstance(statement, ast.Match):
            return self._execute_match(statement)
        if isinstance(statement, ast.Try) or (
            hasattr(ast, "TryStar") and isinstance(statement, ast.TryStar)
        ):
            return self._execute_try(statement)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return self._execute_with(statement)
        if isinstance(statement, ast.Raise):
            if statement.exc is None:
                if self._active_exception is None:
                    raise _TargetException(
                        "RuntimeError", "No active exception to reraise"
                    )
                raise self._active_exception
            if statement.cause is not None:
                self._evaluate(statement.cause)
            raise self._raised_exception(statement)
        if isinstance(statement, ast.Return):
            return _Return(self._evaluate(statement.value) if statement.value else None)
        if isinstance(statement, ast.Pass):
            return None
        if isinstance(statement, ast.Break):
            return _Break()
        if isinstance(statement, ast.Continue):
            return _Continue()
        if isinstance(statement, ast.Expr):
            self._evaluate(statement.value)
            return None
        if isinstance(statement, ast.Assert):
            condition = self._truthy(self._evaluate(statement.test))
            self.path.append(_Branch(condition.symbolic, condition.concrete))
            if not condition.concrete:
                message = (
                    str(_concrete(self._evaluate(statement.msg)))
                    if statement.msg is not None
                    else ""
                )
                raise _TargetException("AssertionError", message)
            return None
        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                self._delete(target)
            return None
        raise UnsupportedSyntaxError(
            "unsupported statement "
            f"{type(statement).__name__} at line {statement.lineno}"
        )

    def _execute_import(self, statement: ast.Import) -> None:
        for alias in statement.names:
            if alias.name == "re":
                self._assign_name(alias.asname or "re", _RegexModule())
                continue
            if alias.name == "importlib":
                self._assign_name(
                    alias.asname or "importlib",
                    _ImportlibModule(self._current_module.path, self._module_cache),
                )
                continue
            if alias.name in {"os.path", "urllib.parse"}:
                bound_name = alias.asname or alias.name.split(".")[0]
                summary_name = alias.name if alias.asname else bound_name
                self._assign_name(bound_name, _SummaryModule(summary_name))
                continue
            if alias.name in _SUMMARY_MODULES:
                self._assign_name(
                    alias.asname or alias.name, _SummaryModule(alias.name)
                )
                continue
            resolved = _import_local_module(
                self._current_module.path, alias.name, self._module_cache
            )
            if resolved is None:
                raise UnsupportedSyntaxError(f"unsupported import {alias.name!r}")
            package, imported = resolved
            self._assign_name(
                alias.asname or alias.name.split(".")[0],
                imported if alias.asname else package,
            )

    def _execute_import_from(self, statement: ast.ImportFrom) -> None:
        module_name = statement.module
        if statement.level == 0 and module_name == "importlib":
            for alias in statement.names:
                if alias.name == "import_module":
                    self._assign_name(
                        alias.asname or alias.name,
                        _ImportlibFunction(
                            self._current_module.path, self._module_cache
                        ),
                    )
                else:
                    raise UnsupportedSyntaxError(
                        f"unsupported importlib member {alias.name!r}"
                    )
            return
        if statement.level == 0 and module_name in _SUMMARY_MODULES:
            for alias in statement.names:
                if alias.name == "*":
                    raise UnsupportedSyntaxError("star imports are not supported")
                self._assign_name(
                    alias.asname or alias.name,
                    _SummaryFunction(module_name, alias.name),
                )
            return
        if statement.level == 0 and module_name == "os":
            for alias in statement.names:
                if alias.name != "path":
                    raise UnsupportedSyntaxError(
                        f"unsupported os member {alias.name!r}"
                    )
                self._assign_name(alias.asname or alias.name, _SummaryModule("os.path"))
            return
        if statement.level == 0 and module_name == "urllib":
            for alias in statement.names:
                if alias.name != "parse":
                    raise UnsupportedSyntaxError(
                        f"unsupported urllib member {alias.name!r}"
                    )
                self._assign_name(
                    alias.asname or alias.name, _SummaryModule("urllib.parse")
                )
            return
        if module_name is not None:
            imported = _resolve_local_module(
                self._current_module.path,
                module_name,
                self._module_cache,
                statement.level,
            )
            if imported is None:
                raise UnsupportedSyntaxError(
                    f"unsupported import from {module_name!r}"
                )
            for alias in statement.names:
                if alias.name == "*":
                    for name, function in imported.functions.items():
                        self._assign_name(
                            name, _FunctionValue(function, {}, imported)
                        )
                    self._classes.update(imported.classes)
                    self._globals.update(imported.globals)
                elif alias.name in imported.functions:
                    self._assign_name(
                        alias.asname or alias.name,
                        _FunctionValue(imported.functions[alias.name], {}, imported),
                    )
                elif alias.name in imported.classes:
                    self._classes[alias.asname or alias.name] = imported.classes[
                        alias.name
                    ]
                elif alias.name in imported.globals:
                    self._assign_name(
                        alias.asname or alias.name,
                        self._constant_value(imported.globals[alias.name]),
                    )
                else:
                    resolved = _import_local_module(
                        imported.path, alias.name, self._module_cache
                    )
                    if resolved is None:
                        raise UnsupportedSyntaxError(
                            f"unknown local import {alias.name!r}"
                        )
                    self._assign_name(alias.asname or alias.name, resolved[1])
            return
        if not statement.level:
            raise UnsupportedSyntaxError("from imports require a module name")
        for alias in statement.names:
            imported = _resolve_local_module(
                self._current_module.path,
                alias.name,
                self._module_cache,
                statement.level,
            )
            if imported is None:
                raise UnsupportedSyntaxError(f"unknown local import {alias.name!r}")
            self._assign_name(alias.asname or alias.name, imported)

    def _execute_match(
        self, statement: ast.Match
    ) -> _Return | _Break | _Continue | None:
        subject = self._evaluate(statement.subject)
        for case in statement.cases:
            bindings: dict[str, Any] = {}
            if not self._match_pattern(subject, case.pattern, bindings):
                continue
            previous_values = {
                name: self.env[name] for name in bindings if name in self.env
            }
            missing = set(bindings) - set(previous_values)
            self.env.update(bindings)
            if case.guard is not None:
                condition = self._truthy(self._evaluate(case.guard))
                self.path.append(_Branch(condition.symbolic, condition.concrete))
                if not condition.concrete:
                    for name in missing:
                        self.env.pop(name, None)
                    self.env.update(previous_values)
                    continue
            return self._execute_block(case.body)
        return None

    def _match_pattern(
        self, value: Any, pattern: ast.pattern, bindings: dict[str, Any]
    ) -> bool:
        if isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None and not self._match_pattern(
                value, pattern.pattern, bindings
            ):
                return False
            if pattern.name is not None:
                bindings[pattern.name] = value
            return True
        if isinstance(pattern, ast.MatchSingleton):
            if pattern.value is None:
                return value is None
            equality = self._equals(value, self._literal(pattern.value))
            self.path.append(_Branch(equality.symbolic, equality.concrete))
            return equality.concrete
        if isinstance(pattern, ast.MatchValue):
            equality = self._equals(value, self._evaluate(pattern.value))
            self.path.append(_Branch(equality.symbolic, equality.concrete))
            return equality.concrete
        if isinstance(pattern, ast.MatchOr):
            for alternative in pattern.patterns:
                trial = dict(bindings)
                if self._match_pattern(value, alternative, trial):
                    bindings.update(trial)
                    return True
            return False
        if isinstance(pattern, ast.MatchSequence):
            if not isinstance(value, (_ListValue, _TupleValue)):
                return False
            values = value.values
            star_indices = [
                index
                for index, item in enumerate(pattern.patterns)
                if isinstance(item, ast.MatchStar)
            ]
            if len(star_indices) > 1:
                raise UnsupportedSyntaxError("multiple starred match patterns")
            if not star_indices and len(values) != len(pattern.patterns):
                return False
            if star_indices and len(values) < len(pattern.patterns) - 1:
                return False
            star_index = star_indices[0] if star_indices else None
            before = pattern.patterns[:star_index]
            after = pattern.patterns[star_index + 1 :] if star_index is not None else ()
            for item, child in zip(values, before):
                if not self._match_pattern(item, child, bindings):
                    return False
            if star_index is not None:
                star = pattern.patterns[star_index]
                if star.name is not None:
                    bindings[star.name] = _ListValue(
                        list(values[len(before) : len(values) - len(after)])
                    )
            for item, child in zip(values[len(values) - len(after) :], after):
                if not self._match_pattern(item, child, bindings):
                    return False
            return True
        if isinstance(pattern, ast.MatchMapping):
            if not isinstance(value, _DictValue):
                return False
            keys = [self._key(self._evaluate(key)) for key in pattern.keys]
            if any(key not in value.values for key in keys):
                return False
            for key, child in zip(keys, pattern.patterns):
                if not self._match_pattern(value.values[key], child, bindings):
                    return False
            if pattern.rest is not None:
                bindings[pattern.rest] = _DictValue(
                    {key: item for key, item in value.values.items() if key not in keys}
                )
            return True
        if isinstance(pattern, ast.MatchClass):
            class_value = self._evaluate(pattern.cls)
            if not isinstance(value, _InstanceValue) or not isinstance(
                class_value, _ClassValue
            ):
                return False
            if class_value not in self._mro(value.class_value):
                return False
            positional_names = self._match_args(class_value)
            if len(pattern.patterns) > len(positional_names):
                raise ConcolicError(
                    f"{class_value.definition.name}() accepts at most "
                    f"{len(positional_names)} positional sub-patterns"
                )
            names = (*positional_names[: len(pattern.patterns)], *pattern.kwd_attrs)
            if len(set(names)) != len(names):
                raise ConcolicError(
                    "match pattern specifies an attribute more than once"
                )
            children = (*pattern.patterns, *pattern.kwd_patterns)
            for name, child in zip(names, children):
                try:
                    attribute = self._attribute(value, name)
                except UnsupportedSyntaxError:
                    return False
                if not self._match_pattern(attribute, child, bindings):
                    return False
            return True
        raise UnsupportedSyntaxError(
            f"unsupported match pattern {type(pattern).__name__}"
        )

    def _execute_try(self, statement: ast.Try) -> _Return | _Break | _Continue | None:
        outcome: _Return | _Break | _Continue | None = None
        try:
            outcome = self._execute_block(statement.body)
        except (ConcolicError, IndexError, KeyError, ValueError) as error:
            handler = self._matching_handler(statement.handlers, error)
            if handler is None:
                raise
            outcome = self._execute_handler(handler, error)
        except _TargetException as error:
            handler = self._matching_handler(statement.handlers, error)
            if handler is None:
                raise
            outcome = self._execute_handler(handler, error)
        else:
            if outcome is None and statement.orelse:
                outcome = self._execute_block(statement.orelse)
        finally:
            final_outcome = self._execute_block(statement.finalbody)
            if final_outcome is not None:
                outcome = final_outcome
        return outcome

    def _execute_handler(
        self, handler: ast.ExceptHandler, error: Exception
    ) -> _Return | _Break | _Continue | None:
        previous_exception = self._active_exception
        self._active_exception = error
        try:
            return self._execute_block(handler.body)
        finally:
            self._active_exception = previous_exception

    def _execute_with(
        self, statement: ast.With | ast.AsyncWith
    ) -> _Return | _Break | _Continue | None:
        contexts: list[Any] = []
        enter_name = (
            "__aenter__" if isinstance(statement, ast.AsyncWith) else "__enter__"
        )
        exit_name = "__aexit__" if isinstance(statement, ast.AsyncWith) else "__exit__"
        try:
            for item in statement.items:
                context = self._evaluate(item.context_expr)
                entered = self._call_attribute(context, enter_name, [], {})
                contexts.append(context)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, entered)
            outcome = self._execute_block(statement.body)
        except Exception as error:
            suppressed = False
            for context in reversed(contexts):
                result = self._call_attribute(
                    context,
                    exit_name,
                    [
                        _StringValue(
                            _exception_name(error),
                            self._z3.StringVal(_exception_name(error)),
                        ),
                        _StringValue(str(error), self._z3.StringVal(str(error))),
                        None,
                    ],
                    {},
                )
                suppressed = self._truthy(result).concrete or suppressed
            if not suppressed:
                raise
            return None
        for context in reversed(contexts):
            self._call_attribute(context, exit_name, [None, None, None], {})
        return outcome

    def _matching_handler(
        self, handlers: list[ast.ExceptHandler], error: Exception
    ) -> ast.ExceptHandler | None:
        error_name = _exception_name(error)
        for handler in handlers:
            if _handler_matches(handler.type, error_name):
                if handler.name:
                    self.env[handler.name] = _StringValue(
                        str(error), self._z3.StringVal(str(error))
                    )
                return handler
        return None

    def _raised_exception(self, statement: ast.Raise) -> _TargetException:
        if isinstance(statement.exc, ast.Name):
            return _TargetException(statement.exc.id)
        if isinstance(statement.exc, ast.Call) and isinstance(
            statement.exc.func, ast.Name
        ):
            message = ""
            if statement.exc.args:
                message = str(_concrete(self._evaluate(statement.exc.args[0])))
            return _TargetException(statement.exc.func.id, message)
        return _TargetException("RuntimeError", "unsupported raised expression")

    def _evaluate(self, expression: ast.expr) -> Any:
        if isinstance(expression, ast.Constant):
            if isinstance(expression.value, bool):
                return _BoolValue(expression.value, self._z3.BoolVal(expression.value))
            if isinstance(expression.value, int):
                return _IntValue(expression.value, self._z3.IntVal(expression.value))
            if isinstance(expression.value, float):
                return _FloatValue(
                    expression.value, self._z3.RealVal(str(expression.value))
                )
            if isinstance(expression.value, str):
                return _StringValue(
                    expression.value, self._z3.StringVal(expression.value)
                )
            if isinstance(expression.value, bytes):
                return _BytesValue(expression.value)
            if expression.value is None:
                return None
            raise UnsupportedSyntaxError(
                "only integer, Boolean, string, and None literals are supported"
            )
        if isinstance(expression, ast.Name):
            return self._lookup(expression.id)
        if isinstance(expression, ast.NamedExpr):
            value = self._evaluate(expression.value)
            self._assign(expression.target, value)
            return value
        if isinstance(expression, ast.JoinedStr):
            values = [self._evaluate_fstring_part(value) for value in expression.values]
            concrete = "".join(value.concrete for value in values)
            symbolic = (
                self._z3.StringVal("")
                if not values
                else values[0].symbolic
                if len(values) == 1
                else self._z3.Concat(*(value.symbolic for value in values))
            )
            return _StringValue(
                concrete, symbolic
            )
        if isinstance(expression, ast.Await):
            return self._evaluate(expression.value)
        if isinstance(expression, ast.Yield):
            if self._yielded_values is None:
                raise UnsupportedSyntaxError(
                    "yield is only valid in generator functions"
                )
            value = self._evaluate(expression.value) if expression.value else None
            self._yielded_values.append(value)
            return None
        if isinstance(expression, ast.YieldFrom):
            if self._yielded_values is None:
                raise UnsupportedSyntaxError(
                    "yield from is only valid in generators"
                )
            self._yielded_values.extend(
                self._iter_values(self._evaluate(expression.value))
            )
            return None
        if isinstance(expression, ast.Lambda):
            return _FunctionValue(expression, self.env)
        if isinstance(expression, ast.List):
            return _ListValue(self._evaluate_unpacked_elements(expression.elts))
        if isinstance(expression, ast.Tuple):
            return _TupleValue(
                tuple(self._evaluate_unpacked_elements(expression.elts))
            )
        if isinstance(expression, ast.Set):
            return _SetValue(
                _unique_values(self._evaluate_unpacked_elements(expression.elts))
            )
        if isinstance(expression, ast.Dict):
            values: dict[int | str | bool, Any] = {}
            for key, value in zip(expression.keys, expression.values):
                if key is None:
                    unpacked = self._evaluate(value)
                    if not isinstance(unpacked, _DictValue):
                        raise UnsupportedSyntaxError(
                            "dictionary unpacking requires a dictionary"
                        )
                    values.update(unpacked.values)
                else:
                    values[self._key(self._evaluate(key))] = self._evaluate(value)
            return _DictValue(values)
        if isinstance(expression, ast.ListComp):
            return _ListValue(
                self._evaluate_comprehension(expression.generators, expression.elt)
            )
        if isinstance(expression, ast.SetComp):
            return _SetValue(
                _unique_values(
                    self._evaluate_comprehension(expression.generators, expression.elt)
                )
            )
        if isinstance(expression, ast.DictComp):
            pairs = self._evaluate_comprehension(
                expression.generators, (expression.key, expression.value)
            )
            return _DictValue({self._key(key): value for key, value in pairs})
        if isinstance(expression, ast.GeneratorExp):
            return self._make_generator_expression(expression)
        if isinstance(expression, ast.Subscript):
            return self._subscript(self._evaluate(expression.value), expression.slice)
        if isinstance(expression, ast.Attribute):
            return self._attribute(self._evaluate(expression.value), expression.attr)
        if isinstance(expression, ast.IfExp):
            condition = self._truthy(self._evaluate(expression.test))
            self.path.append(_Branch(condition.symbolic, condition.concrete))
            return self._evaluate(
                expression.body if condition.concrete else expression.orelse
            )
        if isinstance(expression, ast.BinOp):
            return self._binary(
                self._evaluate(expression.left),
                expression.op,
                self._evaluate(expression.right),
            )
        if isinstance(expression, ast.UnaryOp):
            operand = self._evaluate(expression.operand)
            if isinstance(expression.op, ast.USub):
                if isinstance(operand, _FloatValue):
                    return _FloatValue(-operand.concrete, -operand.symbolic)
                integer = self._as_int(operand)
                return _IntValue(-integer.concrete, -integer.symbolic)
            if isinstance(expression.op, ast.UAdd):
                return self._as_int(operand)
            if isinstance(expression.op, ast.Not):
                boolean = self._truthy(operand)
                return _BoolValue(not boolean.concrete, self._z3.Not(boolean.symbolic))
            raise UnsupportedSyntaxError(
                f"unsupported unary operator at line {expression.lineno}"
            )
        if isinstance(expression, ast.Compare):
            return self._compare(expression)
        if isinstance(expression, ast.BoolOp):
            last_index = len(expression.values) - 1
            for index, node in enumerate(expression.values):
                value = self._evaluate(node)
                if index == last_index:
                    return value
                condition = self._truthy(value)
                self.path.append(_Branch(condition.symbolic, condition.concrete))
                if isinstance(expression.op, ast.And) and not condition.concrete:
                    return value
                if isinstance(expression.op, ast.Or) and condition.concrete:
                    return value
        if isinstance(expression, ast.Call):
            return self._call(expression)
        raise UnsupportedSyntaxError(
            "unsupported expression "
            f"{type(expression).__name__} at line {expression.lineno}"
        )

    def _evaluate_unpacked_elements(self, elements: list[ast.expr]) -> list[Any]:
        values: list[Any] = []
        for element in elements:
            if isinstance(element, ast.Starred):
                values.extend(self._iter_values(self._evaluate(element.value)))
            else:
                values.append(self._evaluate(element))
        return values

    def _evaluate_fstring_part(self, node: ast.expr) -> _StringValue:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _StringValue(node.value, self._z3.StringVal(node.value))
        if isinstance(node, ast.FormattedValue):
            if node.conversion not in {-1, ord("s"), ord("r"), ord("a")}:
                raise UnsupportedSyntaxError("unsupported f-string conversion")
            value = self._evaluate(node.value)
            if node.format_spec is not None:
                specification = self._to_string(
                    self._evaluate(node.format_spec)
                ).concrete
                return self._format_value(value, specification)
            if node.conversion == ord("r"):
                if isinstance(value, _InstanceValue):
                    method_with_owner = self._method_with_owner(
                        value.class_value, "__repr__"
                    )
                    if method_with_owner is not None:
                        method, owner = method_with_owner
                        return self._to_string(
                            self._call_method(method, owner, value, [], {})
                        )
                concrete = repr(_concrete(value))
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if node.conversion == ord("a"):
                concrete = ascii(_concrete(value))
                return _StringValue(concrete, self._z3.StringVal(concrete))
            return self._to_string(value)
        raise UnsupportedSyntaxError("unsupported f-string component")

    def _call(self, call: ast.Call) -> Any:
        args: list[Any] = []
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                args.extend(self._iter_values(self._evaluate(argument.value)))
            else:
                args.append(self._evaluate(argument))
        keywords: dict[str, Any] = {}
        for keyword in call.keywords:
            value = self._evaluate(keyword.value)
            if keyword.arg is None:
                if not isinstance(value, _DictValue):
                    raise UnsupportedSyntaxError("**kwargs requires a dictionary")
                keywords.update({str(key): item for key, item in value.values.items()})
            else:
                keywords[keyword.arg] = value
        return self._call_prepared(call, args, keywords)

    def _call_prepared(
        self, call: ast.Call, args: list[Any], keywords: dict[str, Any]
    ) -> Any:
        if isinstance(call.func, ast.Name):
            name = call.func.id
            if name == "abs" and len(args) == 1:
                if isinstance(args[0], _FloatValue):
                    value = args[0]
                    return _FloatValue(
                        abs(value.concrete),
                        self._z3.If(
                            value.symbolic >= 0, value.symbolic, -value.symbolic
                        ),
                    )
                value = self._as_int(args[0])
                return _IntValue(
                    abs(value.concrete),
                    self._z3.If(value.symbolic >= 0, value.symbolic, -value.symbolic),
                )
            if name == "hash" and len(args) == 1:
                return self._hash(args[0])
            if name == "len" and len(args) == 1:
                return self._length(args[0])
            if name == "iter" and len(args) == 1:
                return self._as_iterator(args[0])
            if name == "next" and 1 <= len(args) <= 2:
                iterator = self._as_iterator(args[0])
                resumed = self._resume_iterator(
                    iterator, _ResumeOperation(_ResumeKind.NEXT)
                )
                if not isinstance(resumed, _Returned):
                    return resumed.value
                if len(args) == 2:
                    return args[1]
                raise _TargetException("StopIteration")
            if name == "bool" and len(args) == 1:
                return self._truthy(args[0])
            if name == "int" and len(args) == 1:
                return self._to_int(args[0])
            if name == "float" and len(args) == 1:
                return self._to_float(args[0])
            if name == "str" and len(args) == 1:
                return self._to_string(args[0])
            if name in {"repr", "ascii"} and len(args) == 1:
                if isinstance(args[0], _InstanceValue):
                    method_with_owner = self._method_with_owner(
                        args[0].class_value, "__repr__"
                    )
                    if method_with_owner is not None:
                        method, owner = method_with_owner
                        result = self._to_string(
                            self._call_method(method, owner, args[0], [], {})
                        )
                        if name == "repr":
                            return result
                        concrete = ascii(result.concrete)
                        return _StringValue(concrete, self._z3.StringVal(concrete))
                concrete = (
                    repr(_concrete(args[0]))
                    if name == "repr"
                    else ascii(_concrete(args[0]))
                )
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "format" and 1 <= len(args) <= 2:
                specification = (
                    self._to_string(args[1]).concrete if len(args) == 2 else ""
                )
                return self._format_value(args[0], specification)
            if name == "bytes" and len(args) == 1:
                return self._to_bytes(args[0])
            if name == "ord" and len(args) == 1:
                string = self._to_string(args[0])
                if len(string.concrete) != 1:
                    raise ConcolicError("ord() expected a character")
                concrete = ord(string.concrete)
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name == "chr" and len(args) == 1:
                try:
                    concrete = chr(self._as_int(args[0]).concrete)
                except ValueError as error:
                    raise ConcolicError(str(error)) from error
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "divmod" and len(args) == 2:
                return _TupleValue(
                    (
                        self._binary(args[0], ast.FloorDiv(), args[1]),
                        self._binary(args[0], ast.Mod(), args[1]),
                    )
                )
            if name == "pow" and 2 <= len(args) <= 3:
                values = [self._numeric_concrete(argument) for argument in args]
                try:
                    concrete = pow(*values)
                except ValueError as error:
                    raise ConcolicError(str(error)) from error
                return self._constant_value(concrete)
            if name == "round" and 1 <= len(args) <= 2:
                number = self._numeric_concrete(args[0])
                digits = self._as_int(args[1]).concrete if len(args) == 2 else None
                concrete = (
                    round(number, digits) if digits is not None else round(number)
                )
                return self._constant_value(concrete)
            if name == "type" and len(args) == 1:
                if isinstance(args[0], _InstanceValue):
                    return args[0].class_value
                type_name = next(
                    (
                        name
                        for value_type, name in (
                            (_BoolValue, "bool"),
                            (_IntValue, "int"),
                            (_FloatValue, "float"),
                            (_StringValue, "str"),
                            (_BytesValue, "bytes"),
                            (_ListValue, "list"),
                            (_TupleValue, "tuple"),
                            (_DictValue, "dict"),
                            (_SetValue, "set"),
                            (_RangeValue, "range"),
                        )
                        if isinstance(args[0], value_type)
                    ),
                    None,
                )
                if type_name is None:
                    raise UnsupportedSyntaxError("type() requires a supported value")
                return _BuiltinFunction(type_name)
            if name == "isinstance" and len(args) == 2:
                return self._isinstance(args[0], args[1])
            if name == "getattr" and 2 <= len(args) <= 3:
                return self._getattr(
                    args[0], args[1], args[2] if len(args) == 3 else None
                )
            if name == "hasattr" and len(args) == 2:
                try:
                    self._getattr(args[0], args[1])
                except UnsupportedSyntaxError:
                    return _BoolValue(False, self._z3.BoolVal(False))
                return _BoolValue(True, self._z3.BoolVal(True))
            if name == "setattr" and len(args) == 3:
                self._setattr(args[0], args[1], args[2])
                return None
            if name == "delattr" and len(args) == 2:
                self._delattr(args[0], args[1])
                return None
            if name == "list" and len(args) <= 1:
                return _ListValue([] if not args else list(self._iter_values(args[0])))
            if name == "tuple" and len(args) <= 1:
                return _TupleValue(
                    () if not args else tuple(self._iter_values(args[0]))
                )
            if name == "set" and len(args) <= 1:
                return _SetValue(
                    [] if not args else _unique_values(self._iter_values(args[0]))
                )
            if name == "dict" and len(args) <= 1:
                values: dict[int | str | bool, Any] = {}
                if args:
                    if isinstance(args[0], _DictValue):
                        values.update(args[0].values)
                    else:
                        for pair in self._iter_values(args[0]):
                            if not isinstance(pair, (_ListValue, _TupleValue)) or len(
                                pair.values
                            ) != 2:
                                raise UnsupportedSyntaxError(
                                    "dict() iterable items must have two values"
                                )
                            values[self._key(pair.values[0])] = pair.values[1]
                values.update(keywords)
                return _DictValue(values)
            if name == "range" and 1 <= len(args) <= 3:
                return self._range(args)
            if name == "reversed" and len(args) == 1:
                return _ListValue(list(reversed(self._iter_values(args[0]))))
            if name == "sorted" and len(args) == 1:
                allowed = {"key", "reverse"}
                if set(keywords) - allowed:
                    raise UnsupportedSyntaxError("unsupported sorted() keyword")
                key_function = keywords.get("key")
                reverse = (
                    self._truthy(keywords["reverse"]).concrete
                    if "reverse" in keywords
                    else False
                )
                return _ListValue(
                    sorted(
                        self._iter_values(args[0]),
                        key=(
                            _concrete
                            if key_function is None
                            else lambda value: _concrete(
                                self._call_value(key_function, [value], {})
                            )
                        ),
                        reverse=reverse,
                    )
                )
            if name == "map" and len(args) >= 2:
                return _MapIteratorValue(
                    args[0], tuple(self._as_iterator(value) for value in args[1:])
                )
            if name == "filter" and len(args) == 2:
                return _FilterIteratorValue(args[0], self._as_iterator(args[1]))
            if name == "enumerate" and 1 <= len(args) <= 2:
                start = self._as_int(args[1]).concrete if len(args) == 2 else 0
                return _EnumerateIteratorValue(self._as_iterator(args[0]), start)
            if name == "zip":
                strict = False
                if set(keywords) - {"strict"}:
                    raise UnsupportedSyntaxError("unsupported zip() keyword")
                if "strict" in keywords:
                    strict = self._truthy(keywords["strict"]).concrete
                return _ZipIteratorValue(
                    tuple(self._as_iterator(argument) for argument in args), strict
                )
            if name in {"any", "all"} and len(args) == 1:
                iterator = self._as_iterator(args[0])
                tested = []
                while True:
                    resumed = self._resume_iterator(
                        iterator, _ResumeOperation(_ResumeKind.NEXT)
                    )
                    if isinstance(resumed, _Returned):
                        concrete = name == "all"
                        symbolic = (
                            self._z3.Or(*(item.symbolic for item in tested))
                            if name == "any"
                            else self._z3.And(*(item.symbolic for item in tested))
                        )
                        return _BoolValue(concrete, symbolic)
                    condition = self._truthy(resumed.value)
                    tested.append(condition)
                    self.path.append(_Branch(condition.symbolic, condition.concrete))
                    if name == "any" and condition.concrete:
                        return _BoolValue(
                            True,
                            self._z3.Or(*(item.symbolic for item in tested)),
                        )
                    if name == "all" and not condition.concrete:
                        return _BoolValue(
                            False,
                            self._z3.And(*(item.symbolic for item in tested)),
                        )
            if name in {"sum", "min", "max"} and args:
                return self._aggregate(name, args)
            if name == "super" and not args and not keywords:
                if self._current_class is None or self._current_instance is None:
                    raise ConcolicError("super() requires an instance method context")
                return _SuperValue(self._current_instance, self._current_class)
            if name in self._functions:
                return self._call_value(
                    self._function_value(self._functions[name]), args, keywords
                )
            if name in self._classes:
                class_value = self._class_value(self._classes[name])
                if isinstance(class_value, _ClassValue):
                    return self._construct(class_value, args, keywords)
                return self._call_value(class_value, args, keywords)
            callee = self._lookup(name)
            if isinstance(callee, _FunctionValue):
                return self._call_function_value(callee, args, keywords)
            if isinstance(callee, _ClassValue):
                return self._construct(callee, args, keywords)
            if isinstance(callee, _NamedTupleClass):
                return self._construct_namedtuple(callee, args, keywords)
            if isinstance(callee, _EnumClass):
                return self._construct_enum(callee, args, keywords)
            if isinstance(callee, _PartialValue):
                return self._call_value(callee, args, keywords)
            if isinstance(callee, _SummaryFunction):
                return self._call_summary(callee.module, callee.name, args, keywords)
            if isinstance(callee, _ImportlibFunction):
                return self._import_local_by_name(
                    callee.path, callee.cache, args, keywords
                )
            if isinstance(callee, _ContextManagerFactory):
                return self._call_value(callee, args, keywords)
            if isinstance(callee, _ExceptionType):
                return self._call_value(callee, args, keywords)
            if isinstance(
                callee,
                (_OperatorItemGetter, _OperatorAttrGetter, _OperatorMethodCaller),
            ):
                return self._call_value(callee, args, keywords)
        if isinstance(call.func, ast.Attribute):
            return self._call_attribute(
                self._evaluate(call.func.value), call.func.attr, args, keywords
            )
        callee = self._evaluate(call.func)
        if isinstance(callee, _FunctionValue):
            return self._call_function_value(callee, args, keywords)
        if isinstance(callee, _ClassValue):
            return self._construct(callee, args, keywords)
        if isinstance(callee, _NamedTupleClass):
            return self._construct_namedtuple(callee, args, keywords)
        if isinstance(callee, _EnumClass):
            return self._construct_enum(callee, args, keywords)
        if isinstance(callee, _PartialValue):
            return self._call_value(callee, args, keywords)
        if isinstance(callee, _ContextManagerFactory):
            return self._call_value(callee, args, keywords)
        if isinstance(callee, _ExceptionType):
            return self._call_value(callee, args, keywords)
        if isinstance(
            callee, (_OperatorItemGetter, _OperatorAttrGetter, _OperatorMethodCaller)
        ):
            return self._call_value(callee, args, keywords)
        raise UnsupportedSyntaxError(f"unsupported call at line {call.lineno}")

    def _isinstance(self, value: Any, expected: Any) -> _BoolValue:
        classes = (
            expected.values
            if isinstance(expected, _TupleValue)
            else (expected,)
        )
        concrete = any(
            (
                isinstance(class_value, _ClassValue)
                and isinstance(value, _InstanceValue)
                and class_value in self._mro(value.class_value)
            )
            or (
                isinstance(class_value, _BuiltinFunction)
                and self._is_builtin_instance(value, class_value.name)
            )
            for class_value in classes
        )
        return _BoolValue(concrete, self._z3.BoolVal(concrete))

    @staticmethod
    def _is_builtin_instance(value: Any, name: str) -> bool:
        if name == "list":
            return isinstance(value, _ListValue) and not isinstance(value, _DequeValue)
        types = {
            "bool": (_BoolValue,),
            "int": (_IntValue,),
            "float": (_FloatValue,),
            "str": (_StringValue,),
            "bytes": (_BytesValue,),
            "tuple": (_TupleValue, _NamedTupleValue),
            "dict": (_DictValue,),
            "set": (_SetValue,),
            "range": (_RangeValue,),
        }
        return isinstance(value, types.get(name, ()))

    def _getattr(self, value: Any, name: Any, default: Any = None) -> Any:
        attribute = self._to_string(name).concrete
        try:
            return self._attribute(value, attribute)
        except UnsupportedSyntaxError:
            if default is not None:
                return default
            raise

    def _setattr(self, value: Any, name: Any, attribute: Any) -> None:
        if isinstance(value, _InstanceValue):
            attribute_name = self._to_string(name).concrete
            setter = self._property_setter_with_owner(
                value.class_value, attribute_name
            )
            if setter is not None:
                method, owner = setter
                self._call_method(method, owner, value, [attribute], {})
                return
            value.fields[attribute_name] = attribute
            return
        if isinstance(value, _ClassValue):
            self._materialize_class_attributes(value)[
                self._to_string(name).concrete
            ] = attribute
            return
        raise UnsupportedSyntaxError("setattr() requires a supported object")

    def _delattr(self, value: Any, name: Any) -> None:
        attribute_name = self._to_string(name).concrete
        if isinstance(value, _InstanceValue):
            if attribute_name not in value.fields:
                raise ConcolicError(f"attribute not found: {attribute_name!r}")
            del value.fields[attribute_name]
            return
        if isinstance(value, _ClassValue):
            attributes = self._materialize_class_attributes(value)
            if attribute_name not in attributes:
                raise ConcolicError(f"attribute not found: {attribute_name!r}")
            del attributes[attribute_name]
            return
        raise UnsupportedSyntaxError("delattr() requires a supported object")
