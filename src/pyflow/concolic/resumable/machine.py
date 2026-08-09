"""Suspended generator and coroutine execution for the concolic interpreter."""

from __future__ import annotations

import ast
from typing import Any, Generator, Iterable

from .cfg import _SuspensionPoint, _contains_suspension
from ..runtime import (
    ConcolicError,
    FunctionNode,
    UnsupportedSyntaxError,
    _BoolValue,
    _Break,
    _Continue,
    _ResumeKind,
    _ResumeOperation,
    _Return,
    _Returned,
    _StringValue,
    _ListValue,
    _SetValue,
    _TupleValue,
    _DictValue,
    _TargetException,
)


class _ResumableMachineMixin:
    def _resumable_function(
        self, function: FunctionNode
    ) -> Generator[_SuspensionPoint, Any, Any]:
        outcome = yield from self._resumable_block(function.body)
        return outcome.value if isinstance(outcome, _Return) else None

    def _resumable_block(
        self, statements: Iterable[ast.stmt]
    ) -> Generator[_SuspensionPoint, Any, _Return | _Break | _Continue | None]:
        for statement in statements:
            outcome = yield from self._resumable_statement(statement)
            if outcome is not None:
                return outcome
        return None

    def _resumable_statement(
        self, statement: ast.stmt
    ) -> Generator[_SuspensionPoint, Any, _Return | _Break | _Continue | None]:
        self._cover_node(statement)
        if not _contains_suspension(statement):
            return self._execute_statement(statement)
        if isinstance(statement, ast.Expr):
            yield from self._resumable_evaluate(statement.value)
            return None
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value_node = statement.value
            if value_node is None:
                return None
            value = yield from self._resumable_evaluate(value_node)
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    self._assign(target, value)
            else:
                self._assign(statement.target, value)
            return None
        if isinstance(statement, ast.AugAssign):
            previous = self._evaluate(statement.target)
            value = yield from self._resumable_evaluate(statement.value)
            self._assign(statement.target, self._binary(previous, statement.op, value))
            return None
        if isinstance(statement, ast.Return):
            value = None
            if statement.value is not None:
                value = yield from self._resumable_evaluate(statement.value)
            return _Return(value)
        if isinstance(statement, ast.If):
            condition = self._truthy(
                (yield from self._resumable_evaluate(statement.test))
            )
            self._record_branch(condition.symbolic, condition.concrete, statement.test, "if")
            return (
                yield from self._resumable_block(
                    statement.body if condition.concrete else statement.orelse
                )
            )
        if isinstance(statement, ast.While):
            count = 0
            while True:
                if count >= self._max_loop_iterations:
                    raise ConcolicError(
                        "loop exceeded --max-loop-iterations "
                        f"({self._max_loop_iterations})"
                    )
                condition = self._truthy(
                    (yield from self._resumable_evaluate(statement.test))
                )
                self._record_branch(
                    condition.symbolic, condition.concrete, statement.test, "while"
                )
                if not condition.concrete:
                    if statement.orelse:
                        return (yield from self._resumable_block(statement.orelse))
                    return None
                outcome = yield from self._resumable_block(statement.body)
                if isinstance(outcome, _Return):
                    return outcome
                if isinstance(outcome, _Break):
                    return None
                count += 1
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            source = yield from self._resumable_evaluate(statement.iter)
            iterator = (
                (yield from self._prepare_async_iterator(source, statement))
                if isinstance(statement, ast.AsyncFor)
                else self._as_iterator(source)
            )
            while True:
                resumed = (
                    (yield from self._resume_async_next(iterator, statement))
                    if isinstance(statement, ast.AsyncFor)
                    else self._resume_iterator(
                        iterator, _ResumeOperation(_ResumeKind.NEXT)
                    )
                )
                if isinstance(resumed, _Returned):
                    if statement.orelse:
                        return (yield from self._resumable_block(statement.orelse))
                    return None
                self._assign(statement.target, resumed.value)
                outcome = yield from self._resumable_block(statement.body)
                if isinstance(outcome, _Return):
                    return outcome
                if isinstance(outcome, _Break):
                    return None
        if isinstance(statement, ast.Try) or (
            hasattr(ast, "TryStar") and isinstance(statement, ast.TryStar)
        ):
            return (yield from self._resumable_try(statement))
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return (yield from self._resumable_with(statement))
        if isinstance(statement, ast.Match):
            return (yield from self._resumable_match(statement))
        raise UnsupportedSyntaxError(
            "unsupported suspending statement "
            f"{type(statement).__name__} at line {statement.lineno}"
        )

    def _resumable_try(self, statement):
        outcome = None
        try:
            try:
                outcome = yield from self._resumable_block(statement.body)
            except (ConcolicError, IndexError, KeyError, ValueError, _TargetException) as error:
                handler = self._matching_handler(statement.handlers, error)
                if handler is None:
                    raise
                previous_exception = self._active_exception
                self._active_exception = error
                try:
                    outcome = yield from self._resumable_block(handler.body)
                finally:
                    self._active_exception = previous_exception
            else:
                if outcome is None and statement.orelse:
                    outcome = yield from self._resumable_block(statement.orelse)
        finally:
            final_outcome = yield from self._resumable_block(statement.finalbody)
            if final_outcome is not None:
                outcome = final_outcome
        return outcome

    def _resumable_with(self, statement):
        contexts = []
        enter_name = "__aenter__" if isinstance(statement, ast.AsyncWith) else "__enter__"
        exit_name = "__aexit__" if isinstance(statement, ast.AsyncWith) else "__exit__"
        try:
            for item in statement.items:
                context = yield from self._resumable_evaluate(item.context_expr)
                entered = self._call_attribute(context, enter_name, [], {})
                if isinstance(statement, ast.AsyncWith):
                    entered = yield from self._await_runtime_value(entered, statement)
                contexts.append(context)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, entered)
            outcome = yield from self._resumable_block(statement.body)
        except Exception as error:
            suppressed = False
            for context in reversed(contexts):
                result = self._call_attribute(
                    context,
                    exit_name,
                    [
                        self._literal_name(type(error).__name__),
                        self._literal_name(str(error)),
                        None,
                    ],
                    {},
                )
                if isinstance(statement, ast.AsyncWith):
                    result = yield from self._await_runtime_value(result, statement)
                suppressed = self._truthy(result).concrete or suppressed
            if not suppressed:
                raise
            return None
        for context in reversed(contexts):
            result = self._call_attribute(context, exit_name, [None, None, None], {})
            if isinstance(statement, ast.AsyncWith):
                yield from self._await_runtime_value(result, statement)
        return outcome

    def _literal_name(self, value: str):
        return _StringValue(value, self._z3.StringVal(value))

    def _resumable_match(self, statement: ast.Match):
        subject = yield from self._resumable_evaluate(statement.subject)
        for case in statement.cases:
            bindings = {}
            if not self._match_pattern(subject, case.pattern, bindings):
                continue
            previous_values = {
                name: self.env[name] for name in bindings if name in self.env
            }
            missing = set(bindings) - set(previous_values)
            self.env.update(bindings)
            if case.guard is not None:
                condition = self._truthy(
                    (yield from self._resumable_evaluate(case.guard))
                )
                self._record_branch(
                    condition.symbolic, condition.concrete, case.guard, "match_guard"
                )
                if not condition.concrete:
                    for name in missing:
                        self.env.pop(name, None)
                    self.env.update(previous_values)
                    continue
            return (yield from self._resumable_block(case.body))
        return None

    def _resumable_evaluate(
        self, expression: ast.expr
    ) -> Generator[_SuspensionPoint, Any, Any]:
        self._cover_node(expression)
        if not _contains_suspension(expression):
            return self._evaluate(expression)
        if isinstance(expression, ast.Yield):
            value = None
            if expression.value is not None:
                value = yield from self._resumable_evaluate(expression.value)
            return (yield _SuspensionPoint(value, expression))
        if isinstance(expression, ast.YieldFrom):
            source = yield from self._resumable_evaluate(expression.value)
            iterator = self._as_iterator(source)
            operation = _ResumeOperation(_ResumeKind.NEXT)
            while True:
                resumed = self._resume_iterator(iterator, operation)
                if isinstance(resumed, _Returned):
                    return resumed.value
                try:
                    sent = yield _SuspensionPoint(resumed.value, expression)
                except GeneratorExit:
                    self._resume_iterator(
                        iterator, _ResumeOperation(_ResumeKind.CLOSE)
                    )
                    raise
                except BaseException as error:
                    operation = _ResumeOperation(_ResumeKind.THROW, error)
                else:
                    operation = _ResumeOperation(
                        _ResumeKind.NEXT if sent is None else _ResumeKind.SEND,
                        sent,
                    )
        if isinstance(expression, ast.Await):
            awaitable = yield from self._resumable_evaluate(expression.value)
            return (yield from self._await_runtime_value(awaitable, expression))
        if isinstance(expression, ast.NamedExpr):
            value = yield from self._resumable_evaluate(expression.value)
            self._assign(expression.target, value)
            return value
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            values = []
            for element in expression.elts:
                if isinstance(element, ast.Starred):
                    unpacked = yield from self._resumable_evaluate(element.value)
                    values.extend(self._iter_values(unpacked))
                else:
                    values.append((yield from self._resumable_evaluate(element)))
            if isinstance(expression, ast.List):
                return _ListValue(values)
            if isinstance(expression, ast.Tuple):
                return _TupleValue(tuple(values))
            from ..support import _unique_values

            return _SetValue(_unique_values(values))
        if isinstance(expression, ast.Dict):
            values = {}
            for key_node, value_node in zip(expression.keys, expression.values):
                value = yield from self._resumable_evaluate(value_node)
                if key_node is None:
                    if not isinstance(value, _DictValue):
                        raise UnsupportedSyntaxError(
                            "dictionary unpacking requires a dictionary"
                        )
                    values.update(value.values)
                else:
                    key = yield from self._resumable_evaluate(key_node)
                    values[self._key(key)] = value
            return _DictValue(values)
        if isinstance(expression, (ast.ListComp, ast.SetComp, ast.DictComp)):
            result = []
            projected = (
                (expression.key, expression.value)
                if isinstance(expression, ast.DictComp)
                else expression.elt
            )
            yield from self._resumable_comprehension_collect(
                expression.generators, projected, 0, result
            )
            if isinstance(expression, ast.ListComp):
                return _ListValue(result)
            if isinstance(expression, ast.SetComp):
                from ..support import _unique_values

                return _SetValue(_unique_values(result))
            return _DictValue({self._key(key): value for key, value in result})
        if isinstance(expression, ast.Attribute):
            value = yield from self._resumable_evaluate(expression.value)
            return self._attribute(value, expression.attr)
        if isinstance(expression, ast.Subscript):
            value = yield from self._resumable_evaluate(expression.value)
            if _contains_suspension(expression.slice):
                raise UnsupportedSyntaxError("suspending subscript indices are unsupported")
            return self._subscript(value, expression.slice)
        if isinstance(expression, ast.IfExp):
            condition = self._truthy(
                (yield from self._resumable_evaluate(expression.test))
            )
            self._record_branch(
                condition.symbolic, condition.concrete, expression.test, "if_expression"
            )
            return (
                yield from self._resumable_evaluate(
                    expression.body if condition.concrete else expression.orelse
                )
            )
        if isinstance(expression, ast.BinOp):
            left = yield from self._resumable_evaluate(expression.left)
            right = yield from self._resumable_evaluate(expression.right)
            return self._binary(left, expression.op, right)
        if isinstance(expression, ast.UnaryOp):
            operand = yield from self._resumable_evaluate(expression.operand)
            if isinstance(expression.op, ast.USub):
                if hasattr(operand, "symbolic") and isinstance(
                    getattr(operand, "concrete", None), float
                ):
                    return type(operand)(-operand.concrete, -operand.symbolic)
                integer = self._as_int(operand)
                return type(integer)(-integer.concrete, -integer.symbolic)
            if isinstance(expression.op, ast.UAdd):
                return self._as_int(operand)
            if isinstance(expression.op, ast.Not):
                boolean = self._truthy(operand)
                return _BoolValue(
                    not boolean.concrete, self._z3.Not(boolean.symbolic)
                )
        if isinstance(expression, ast.Compare):
            left = yield from self._resumable_evaluate(expression.left)
            pairs = []
            for operator, comparator in zip(
                expression.ops, expression.comparators
            ):
                right = yield from self._resumable_evaluate(comparator)
                pairs.append((operator, right))
            return self._compare_values(left, pairs)
        if isinstance(expression, ast.Call):
            args = []
            for argument in expression.args:
                if isinstance(argument, ast.Starred):
                    value = yield from self._resumable_evaluate(argument.value)
                    args.extend(self._iter_values(value))
                else:
                    args.append((yield from self._resumable_evaluate(argument)))
            keywords = {}
            for keyword in expression.keywords:
                value = yield from self._resumable_evaluate(keyword.value)
                if keyword.arg is None:
                    if not isinstance(value, _DictValue):
                        raise UnsupportedSyntaxError("**kwargs requires a dictionary")
                    keywords.update(
                        {str(key): item for key, item in value.values.items()}
                    )
                else:
                    keywords[keyword.arg] = value
            return self._call_prepared(expression, args, keywords)
        if isinstance(expression, ast.BoolOp):
            last_index = len(expression.values) - 1
            for index, node in enumerate(expression.values):
                value = yield from self._resumable_evaluate(node)
                if index == last_index:
                    return value
                condition = self._truthy(value)
                self._record_branch(
                    condition.symbolic, condition.concrete, node, "boolean_operand"
                )
                if isinstance(expression.op, ast.And) and not condition.concrete:
                    return value
                if isinstance(expression.op, ast.Or) and condition.concrete:
                    return value
        raise UnsupportedSyntaxError(
            "unsupported suspending expression "
            f"{type(expression).__name__} at line {expression.lineno}"
        )

    def _comprehension_machine(self, generators, expression, owner):
        yield from self._comprehension_level(generators, expression, owner, 0)

    def _comprehension_level(self, generators, expression, owner, index):
        generator = generators[index]
        source = self._evaluate(generator.iter)
        iterator = (
            (yield from self._prepare_async_iterator(source, owner))
            if generator.is_async
            else self._as_iterator(source)
        )
        while True:
            resumed = (
                (yield from self._resume_async_next(iterator, owner))
                if generator.is_async
                else self._resume_iterator(
                    iterator, _ResumeOperation(_ResumeKind.NEXT)
                )
            )
            if isinstance(resumed, _Returned):
                return
            self._assign(generator.target, resumed.value)
            accepted = True
            for condition_node in generator.ifs:
                condition = self._truthy(self._evaluate(condition_node))
                self._record_branch(
                    condition.symbolic,
                    condition.concrete,
                    condition_node,
                    "comprehension_filter",
                )
                if not condition.concrete:
                    accepted = False
                    break
            if not accepted:
                continue
            if index + 1 < len(generators):
                yield from self._comprehension_level(
                    generators, expression, owner, index + 1
                )
            else:
                yield _SuspensionPoint(self._evaluate(expression), owner)

    def _resumable_comprehension_collect(
        self, generators, expression, index, output
    ):
        generator = generators[index]
        source = yield from self._resumable_evaluate(generator.iter)
        iterator = (
            (yield from self._prepare_async_iterator(source, generator))
            if generator.is_async
            else self._as_iterator(source)
        )
        while True:
            resumed = (
                (yield from self._resume_async_next(iterator, generator))
                if generator.is_async
                else self._resume_iterator(
                    iterator, _ResumeOperation(_ResumeKind.NEXT)
                )
            )
            if isinstance(resumed, _Returned):
                return
            self._assign(generator.target, resumed.value)
            accepted = True
            for condition_node in generator.ifs:
                condition = self._truthy(
                    (yield from self._resumable_evaluate(condition_node))
                )
                self._record_branch(
                    condition.symbolic,
                    condition.concrete,
                    condition_node,
                    "comprehension_filter",
                )
                if not condition.concrete:
                    accepted = False
                    break
            if not accepted:
                continue
            if index + 1 < len(generators):
                yield from self._resumable_comprehension_collect(
                    generators, expression, index + 1, output
                )
            elif isinstance(expression, tuple):
                pair = []
                for item in expression:
                    pair.append((yield from self._resumable_evaluate(item)))
                output.append(tuple(pair))
            else:
                output.append((yield from self._resumable_evaluate(expression)))
