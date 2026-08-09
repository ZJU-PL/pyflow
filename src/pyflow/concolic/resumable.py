"""Suspended generator and coroutine execution for the concolic interpreter."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Generator, Iterable

from .runtime import (
    ConcolicError,
    FunctionNode,
    UnsupportedSyntaxError,
    _BoolValue,
    _Awaiting,
    _AsyncContextOperation,
    _Branch,
    _Break,
    _Continue,
    _Raised,
    _ResumeKind,
    _ResumeOperation,
    _ResumeOutcome,
    _ResumableFrame,
    _Return,
    _Returned,
    _StringValue,
    _ListValue,
    _SetValue,
    _GatherValue,
    _GeneratorFrame,
    _CoroutineFrame,
    _IteratorValue,
    _SchedulerYield,
    _TaskValue,
    _TaskWait,
    _TupleValue,
    _DictValue,
    _TargetException,
    _Yielded,
)


@dataclass(frozen=True)
class _SuspensionPoint:
    value: Any
    node: ast.AST
    kind: str = "yield"


@dataclass(frozen=True)
class _ResumableCFGPoint:
    identifier: int
    line: int
    kind: str


@dataclass(frozen=True)
class _ResumableCFG:
    """Control-flow graph used to identify and resume suspension points."""

    points: tuple[_ResumableCFGPoint, ...]
    edges: tuple[tuple[int, int, str], ...]
    entry: int
    exit: int
    node_points: dict[int, int]

    @classmethod
    def from_function(
        cls, function: FunctionNode | ast.GeneratorExp
    ) -> "_ResumableCFG":
        builder = _ResumableCFGBuilder()
        return builder.build(function)

    def point_for(self, node: ast.AST) -> int | None:
        return self.node_points.get(id(node))


class _ResumableCFGBuilder:
    def __init__(self) -> None:
        self.points: list[_ResumableCFGPoint] = []
        self.edges: list[tuple[int, int, str]] = []
        self.node_points: dict[int, int] = {}

    def _point(self, node: ast.AST | None, kind: str) -> int:
        identifier = len(self.points)
        self.points.append(
            _ResumableCFGPoint(
                identifier, getattr(node, "lineno", 0) if node is not None else 0, kind
            )
        )
        if node is not None:
            self.node_points[id(node)] = identifier
        return identifier

    def build(self, function: FunctionNode | ast.GeneratorExp) -> _ResumableCFG:
        entry = self._point(function, "entry")
        exit_point = self._point(None, "exit")
        if isinstance(function, ast.GeneratorExp):
            body_entry = self._point(function, "generator_expression")
            self.edges.extend(
                ((entry, body_entry, "normal"), (body_entry, exit_point, "exhausted"))
            )
        else:
            body_entry = self._block(function.body, exit_point)
            self.edges.append((entry, body_entry, "normal"))
        return _ResumableCFG(
            tuple(self.points),
            tuple(self.edges),
            entry,
            exit_point,
            dict(self.node_points),
        )

    def _block(self, statements: Iterable[ast.stmt], successor: int) -> int:
        next_point = successor
        for statement in reversed(tuple(statements)):
            next_point = self._statement(statement, next_point)
        return next_point

    def _statement(self, statement: ast.stmt, successor: int) -> int:
        point = self._point(statement, type(statement).__name__)
        suspensions = [
            node
            for node in ast.walk(statement)
            if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await))
        ]
        for suspension in suspensions:
            suspension_point = self._point(suspension, type(suspension).__name__)
            self.edges.append((point, suspension_point, "suspend"))
            self.edges.append((suspension_point, successor, "resume"))
        if isinstance(statement, ast.If):
            body = self._block(statement.body, successor)
            orelse = self._block(statement.orelse, successor)
            self.edges.extend(((point, body, "true"), (point, orelse, "false")))
        elif isinstance(statement, (ast.While, ast.For, ast.AsyncFor)):
            body = self._block(statement.body, point)
            orelse = self._block(statement.orelse, successor)
            self.edges.extend(((point, body, "body"), (point, orelse, "exit")))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            body = self._block(statement.body, successor)
            self.edges.append((point, body, "enter"))
        elif isinstance(statement, ast.Try) or (
            hasattr(ast, "TryStar") and isinstance(statement, ast.TryStar)
        ):
            final_entry = self._block(statement.finalbody, successor)
            normal_entry = self._block(statement.orelse, final_entry)
            body = self._block(statement.body, normal_entry)
            self.edges.append((point, body, "try"))
            for index, handler in enumerate(statement.handlers):
                handler_entry = self._block(handler.body, final_entry)
                self.edges.append((point, handler_entry, f"except:{index}"))
        elif isinstance(statement, ast.Match):
            for index, case in enumerate(statement.cases):
                case_entry = self._block(case.body, successor)
                self.edges.append((point, case_entry, f"case:{index}"))
            self.edges.append((point, successor, "no_match"))
        elif not suspensions:
            self.edges.append((point, successor, "normal"))
        return point


class _SuspensionFinder(ast.NodeVisitor):
    found = False

    def visit_Yield(self, node: ast.Yield) -> None:  # noqa: N802
        self.found = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:  # noqa: N802
        self.found = True

    def visit_Await(self, node: ast.Await) -> None:  # noqa: N802
        self.found = True

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self.found = True

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:  # noqa: N802
        self.found = True

    def visit_comprehension(self, node: ast.comprehension) -> None:
        if node.is_async:
            self.found = True
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return


def _contains_suspension(node: ast.AST) -> bool:
    if isinstance(
        node, (ast.Yield, ast.YieldFrom, ast.Await, ast.AsyncFor, ast.AsyncWith)
    ):
        return True
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        if any(generator.is_async for generator in node.generators):
            return True
    finder = _SuspensionFinder()
    for child in ast.iter_child_nodes(node):
        finder.visit(child)
        if finder.found:
            return True
    return finder.found


def _has_yield(function: FunctionNode) -> bool:
    class Finder(ast.NodeVisitor):
        found = False

        def visit_Yield(self, node):  # noqa: N802
            self.found = True

        def visit_YieldFrom(self, node):  # noqa: N802
            self.found = True

        def visit_FunctionDef(self, node):  # noqa: N802
            return

        def visit_AsyncFunctionDef(self, node):  # noqa: N802
            return

        def visit_Lambda(self, node):  # noqa: N802
            return

    finder = Finder()
    for statement in function.body:
        finder.visit(statement)
    return finder.found


class _ResumableMixin:
    def _make_generator_expression(self, expression: ast.GeneratorExp):
        environment = dict(self.env)
        frame = _GeneratorFrame(
            machine=self._comprehension_machine(
                expression.generators, expression.elt, expression
            ),
            environment=environment,
            function=expression,
            module=self._current_module,
            functions=self._functions,
            classes=self._classes,
            globals=self._globals,
            closure=self._closure_env,
            current_class=self._current_class,
            current_instance=self._current_instance,
        )
        frame.cfg = _ResumableCFG.from_function(expression)
        frame.program_counter = None
        return frame

    def _make_resumable_frame(
        self,
        function: FunctionNode,
        environment: dict[str, Any],
        *,
        closure: dict[str, Any] | None = None,
        current_class=None,
        current_instance=None,
    ) -> _ResumableFrame:
        machine = self._resumable_function(function)
        async_generator = isinstance(function, ast.AsyncFunctionDef) and _has_yield(
            function
        )
        frame_type = _CoroutineFrame if isinstance(
            function, ast.AsyncFunctionDef
        ) and not async_generator else _GeneratorFrame
        frame = frame_type(
            machine=machine,
            environment=environment,
            function=function,
            module=self._current_module,
            functions=self._functions,
            classes=self._classes,
            globals=self._globals,
            closure=closure,
            current_class=current_class,
            current_instance=current_instance,
            is_coroutine=isinstance(function, ast.AsyncFunctionDef)
            and not async_generator,
            is_async_generator=async_generator,
        )
        frame.cfg = _ResumableCFG.from_function(function)
        frame.program_counter = None
        return frame

    def _drive_coroutine(self, frame: _ResumableFrame) -> Any:
        main_task = _TaskValue(frame, "<entry>")
        self._tasks.insert(0, main_task)
        try:
            while not main_task.done:
                candidates = [
                    task
                    for task in self._tasks
                    if not task.done
                    and (
                        task.cancel_requested
                        or task.blocked_on is None
                        or task.blocked_on.done
                    )
                ]
                if not candidates:
                    raise _TargetException(
                        "RuntimeError", "async task scheduler deadlocked"
                    )
                task = candidates[self._choose_task_index(len(candidates))]
                self._step_task(task)
                self._task_switches += 1
                if self._task_switches > self._max_task_switches:
                    raise ConcolicError(
                        "task scheduling exceeded --max-task-switches "
                        f"({self._max_task_switches})"
                    )
            if main_task.exception is not None:
                raise main_task.exception
            return main_task.result
        finally:
            for task in self._tasks:
                if not task.done:
                    task.frame.resume(
                        self, _ResumeOperation(_ResumeKind.CLOSE)
                    )
            self._tasks.clear()

    def _choose_task_index(self, count: int) -> int:
        if self._scheduler_mode == "nondeterministic":
            if count <= 1:
                chosen = 0
            else:
                position = len(self._schedule_choices)
                chosen = (
                    self._schedule_prefix[position] % count
                    if position < len(self._schedule_prefix)
                    else 0
                )
        else:
            chosen = self._scheduler_cursor % count
            self._scheduler_cursor += 1
        self._schedule_choices.append((count, chosen))
        return chosen

    def _step_task(self, task: _TaskValue) -> None:
        task.blocked_on = None
        operation = _ResumeOperation(_ResumeKind.NEXT)
        if task.cancel_requested:
            task.cancel_requested = False
            operation = _ResumeOperation(
                _ResumeKind.THROW, _TargetException("CancelledError")
            )
        try:
            resumed = self._resume_iterator(task.frame, operation)
        except BaseException as error:
            task.done = True
            task.exception = error
            return
        if isinstance(resumed, _Returned):
            task.done = True
            task.result = resumed.value
            return
        if isinstance(resumed.value, _TaskWait):
            task.blocked_on = resumed.value.task

    def _create_task(self, value: Any, name: str | None = None) -> _TaskValue:
        if isinstance(value, _TaskValue):
            return value
        if not isinstance(value, _ResumableFrame) or not value.is_coroutine:
            raise _TargetException("TypeError", "a coroutine was expected")
        task = _TaskValue(value, name)
        self._tasks.append(task)
        return task

    def _create_gather(self, values, return_exceptions: bool) -> _GatherValue:
        return _GatherValue(
            tuple(self._create_task(value) for value in values), return_exceptions
        )

    def _resume_frame(
        self, frame: _ResumableFrame, operation: _ResumeOperation
    ) -> _ResumeOutcome:
        if frame.state == "closed":
            return _Returned(frame.return_value)
        if frame.state == "running":
            return _Raised(_TargetException("ValueError", "generator already executing"))
        if (
            frame.state == "created"
            and operation.kind is _ResumeKind.SEND
            and operation.value is not None
        ):
            return _Raised(
                _TargetException(
                    "TypeError", "can't send non-None value to a just-started generator"
                )
            )

        previous_env = self.env
        previous_functions = self._functions
        previous_classes = self._classes
        previous_globals = self._globals
        previous_module = self._current_module
        previous_global_names = self._global_names
        previous_nonlocal_names = self._nonlocal_names
        previous_closure_env = self._closure_env
        previous_class = self._current_class
        previous_instance = self._current_instance
        self.env = frame.environment
        self._functions = frame.functions
        self._classes = frame.classes
        self._globals = frame.globals
        self._current_module = frame.module
        self._global_names = set()
        self._nonlocal_names = set()
        self._closure_env = frame.closure
        self._current_class = frame.current_class
        self._current_instance = frame.current_instance
        frame.state = "running"
        try:
            if operation.kind is _ResumeKind.CLOSE:
                frame.machine.close()
                frame.state = "closed"
                return _Returned(frame.return_value)
            if operation.kind is _ResumeKind.THROW:
                exception = operation.value
                if not isinstance(exception, BaseException):
                    exception = _TargetException(
                        "TypeError", "exceptions must derive from BaseException"
                    )
                suspended = frame.machine.throw(exception)
            else:
                sent = operation.value if operation.kind is _ResumeKind.SEND else None
                suspended = frame.machine.send(sent)
            if not isinstance(suspended, _SuspensionPoint):
                raise ConcolicError("resumable frame produced an invalid suspension")
            frame.program_counter = frame.cfg.point_for(suspended.node)
            frame.state = "suspended"
            return (
                _Awaiting(suspended.value)
                if suspended.kind == "await"
                else _Yielded(suspended.value)
            )
        except StopIteration as stopped:
            frame.return_value = stopped.value
            frame.state = "closed"
            return _Returned(stopped.value)
        except BaseException as error:
            frame.state = "closed"
            if isinstance(error, RuntimeError):
                error = _TargetException("RuntimeError", str(error))
            return _Raised(error)
        finally:
            frame.environment = self.env
            self.env = previous_env
            self._functions = previous_functions
            self._classes = previous_classes
            self._globals = previous_globals
            self._current_module = previous_module
            self._global_names = previous_global_names
            self._nonlocal_names = previous_nonlocal_names
            self._closure_env = previous_closure_env
            self._current_class = previous_class
            self._current_instance = previous_instance

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
            self.path.append(_Branch(condition.symbolic, condition.concrete))
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
                self.path.append(_Branch(condition.symbolic, condition.concrete))
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
                self.path.append(_Branch(condition.symbolic, condition.concrete))
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
            from .support import _unique_values

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
                from .support import _unique_values

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
            self.path.append(_Branch(condition.symbolic, condition.concrete))
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
                self.path.append(_Branch(condition.symbolic, condition.concrete))
                if isinstance(expression.op, ast.And) and not condition.concrete:
                    return value
                if isinstance(expression.op, ast.Or) and condition.concrete:
                    return value
        raise UnsupportedSyntaxError(
            "unsupported suspending expression "
            f"{type(expression).__name__} at line {expression.lineno}"
        )

    def _await_runtime_value(self, awaitable, node):
        if isinstance(awaitable, _AsyncContextOperation):
            return (
                yield from self._resume_async_context_operation(awaitable, node)
            )
        if isinstance(awaitable, _SchedulerYield):
            yield _SuspensionPoint(awaitable, node, "await")
            return awaitable.result
        if isinstance(awaitable, _TaskValue):
            while not awaitable.done:
                yield _SuspensionPoint(_TaskWait(awaitable), node, "await")
            if awaitable.exception is not None:
                raise awaitable.exception
            return awaitable.result
        if isinstance(awaitable, _GatherValue):
            results = []
            for task in awaitable.tasks:
                try:
                    results.append((yield from self._await_runtime_value(task, node)))
                except BaseException as error:
                    if not awaitable.return_exceptions:
                        raise
                    results.append(error)
            return _ListValue(results)
        if isinstance(awaitable, _ResumableFrame) and awaitable.is_coroutine:
            operation = _ResumeOperation(_ResumeKind.NEXT)
            while True:
                resumed = self._resume_iterator(awaitable, operation)
                if isinstance(resumed, _Returned):
                    return resumed.value
                try:
                    sent = yield _SuspensionPoint(resumed.value, node, "await")
                except GeneratorExit:
                    self._resume_iterator(
                        awaitable, _ResumeOperation(_ResumeKind.CLOSE)
                    )
                    raise
                except BaseException as error:
                    operation = _ResumeOperation(_ResumeKind.THROW, error)
                else:
                    operation = _ResumeOperation(
                        _ResumeKind.NEXT if sent is None else _ResumeKind.SEND,
                        sent,
                    )
        raise _TargetException(
            "TypeError", f"object {type(awaitable).__name__} can't be used in await"
        )

    def _resume_async_context_operation(self, operation, node):
        context = operation.context
        if operation.entering:
            if context.entered:
                raise _TargetException(
                    "RuntimeError", "generator context manager cannot be re-entered"
                )
            context.entered = True
            while True:
                resumed = self._resume_iterator(
                    context.iterator, _ResumeOperation(_ResumeKind.NEXT)
                )
                if isinstance(resumed, _Awaiting):
                    yield _SuspensionPoint(resumed.value, node, "await")
                    continue
                if isinstance(resumed, _Returned):
                    raise _TargetException(
                        "RuntimeError", "contextmanager generator did not yield"
                    )
                return resumed.value
        if context.exited:
            return _BoolValue(False, self._z3.BoolVal(False))
        context.exited = True
        args = operation.args
        resume_operation = (
            _ResumeOperation(_ResumeKind.NEXT)
            if args[0] is None
            else _ResumeOperation(
                _ResumeKind.THROW,
                _TargetException(
                    self._to_string(args[0]).concrete,
                    self._to_string(args[1]).concrete,
                ),
            )
        )
        while True:
            try:
                resumed = self._resume_iterator(context.iterator, resume_operation)
            except _TargetException as error:
                if args[0] is not None and error.name == self._to_string(args[0]).concrete:
                    return _BoolValue(False, self._z3.BoolVal(False))
                raise
            if isinstance(resumed, _Awaiting):
                yield _SuspensionPoint(resumed.value, node, "await")
                resume_operation = _ResumeOperation(_ResumeKind.NEXT)
                continue
            if not isinstance(resumed, _Returned):
                raise _TargetException(
                    "RuntimeError", "contextmanager generator did not stop"
                )
            suppressed = args[0] is not None
            return _BoolValue(suppressed, self._z3.BoolVal(suppressed))

    def _prepare_async_iterator(self, value, node):
        if isinstance(value, _ResumableFrame) and value.is_async_generator:
            return value
        try:
            iterator = self._call_attribute(value, "__aiter__", [], {})
        except UnsupportedSyntaxError:
            return self._as_iterator(value)
        if isinstance(iterator, _ResumableFrame) and iterator.is_coroutine:
            iterator = yield from self._await_runtime_value(iterator, node)
        return iterator

    def _resume_async_next(self, iterator, node):
        if isinstance(iterator, _IteratorValue):
            sent = None
            while True:
                resumed = self._resume_iterator(
                    iterator,
                    _ResumeOperation(
                        _ResumeKind.NEXT if sent is None else _ResumeKind.SEND,
                        sent,
                    ),
                )
                if isinstance(resumed, _Awaiting):
                    sent = yield _SuspensionPoint(resumed.value, node, "await")
                    continue
                return resumed
        try:
            awaitable = self._call_attribute(iterator, "__anext__", [], {})
            value = yield from self._await_runtime_value(awaitable, node)
            return _Yielded(value)
        except _TargetException as error:
            if error.name == "StopAsyncIteration":
                return _Returned()
            raise

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
                self.path.append(_Branch(condition.symbolic, condition.concrete))
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
                self.path.append(_Branch(condition.symbolic, condition.concrete))
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
