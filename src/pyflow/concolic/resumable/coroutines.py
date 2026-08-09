"""Await, async iteration, and async context operations."""

from __future__ import annotations

from .cfg import _SuspensionPoint
from .protocol import _ResumableExecutorProtocol
from ..core.runtime import (
    UnsupportedSyntaxError,
    _AsyncContextOperation,
    _AsyncGeneratorOperation,
    _Awaiting,
    _BoolValue,
    _GatherValue,
    _IteratorValue,
    _ListValue,
    _ResumeKind,
    _ResumeOperation,
    _ResumableFrame,
    _Returned,
    _SchedulerYield,
    _TargetException,
    _TaskValue,
    _TaskWait,
    _Yielded,
)


class _ResumableCoroutineMixin:
    def _await_runtime_value(self: _ResumableExecutorProtocol, awaitable, node):
        if isinstance(awaitable, _AsyncContextOperation):
            return (yield from self._resume_async_context_operation(awaitable, node))
        if isinstance(awaitable, _AsyncGeneratorOperation):
            return (yield from self._resume_async_generator_operation(awaitable, node))
        if isinstance(awaitable, _SchedulerYield):
            yield _SuspensionPoint(awaitable, node, "await")
            return awaitable.result
        if isinstance(awaitable, _TaskValue):
            while not awaitable.done:
                try:
                    yield _SuspensionPoint(_TaskWait(awaitable), node, "await")
                except BaseException as error:
                    if isinstance(error, _TargetException) and (error.name == "CancelledError"):
                        awaitable.cancel_requested = True
                        continue
                    raise
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
                    self._resume_iterator(awaitable, _ResumeOperation(_ResumeKind.CLOSE))
                    raise
                except BaseException as error:
                    operation = _ResumeOperation(_ResumeKind.THROW, error)
                else:
                    operation = _ResumeOperation(
                        _ResumeKind.NEXT if sent is None else _ResumeKind.SEND,
                        sent,
                    )
        try:
            iterator = self._call_attribute(awaitable, "__await__", [], {})
        except UnsupportedSyntaxError:
            iterator = None
        if iterator is not None:
            return (yield from self._drive_await_iterator(iterator, node))
        raise _TargetException(
            "TypeError", f"object {type(awaitable).__name__} can't be used in await"
        )

    def _resume_async_generator_operation(
        self: _ResumableExecutorProtocol,
        operation: _AsyncGeneratorOperation,
        node,
    ):
        if operation.consumed:
            raise _TargetException(
                "RuntimeError", "cannot reuse an already awaited async generator operation"
            )
        resume_operation = operation.operation
        while True:
            try:
                resumed = self._resume_iterator(operation.frame, resume_operation)
            except GeneratorExit:
                operation.consumed = True
                if operation.closing:
                    return None
                raise
            except _TargetException as error:
                operation.consumed = True
                if operation.closing and error.name == "GeneratorExit":
                    return None
                raise
            if isinstance(resumed, _Awaiting):
                try:
                    sent = yield _SuspensionPoint(resumed.value, node, "await")
                except GeneratorExit:
                    resume_operation = _ResumeOperation(_ResumeKind.CLOSE)
                except BaseException as error:
                    resume_operation = _ResumeOperation(_ResumeKind.THROW, error)
                else:
                    resume_operation = _ResumeOperation(
                        _ResumeKind.NEXT if sent is None else _ResumeKind.SEND,
                        sent,
                    )
                continue
            operation.consumed = True
            if isinstance(resumed, _Returned):
                if operation.closing:
                    return None
                raise _TargetException("StopAsyncIteration")
            if operation.closing:
                raise _TargetException("RuntimeError", "async generator ignored GeneratorExit")
            return resumed.value

    def _drive_await_iterator(self: _ResumableExecutorProtocol, iterator, node):
        iterator = self._as_iterator(iterator)
        resume_operation = _ResumeOperation(_ResumeKind.NEXT)
        while True:
            resumed = self._resume_iterator(iterator, resume_operation)
            if isinstance(resumed, _Returned):
                return resumed.value
            try:
                sent = yield _SuspensionPoint(resumed.value, node, "await")
            except GeneratorExit:
                self._resume_iterator(iterator, _ResumeOperation(_ResumeKind.CLOSE))
                raise
            except BaseException as error:
                resume_operation = _ResumeOperation(_ResumeKind.THROW, error)
            else:
                resume_operation = _ResumeOperation(
                    _ResumeKind.NEXT if sent is None else _ResumeKind.SEND,
                    sent,
                )

    def _resume_async_context_operation(self: _ResumableExecutorProtocol, operation, node):
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
                    raise _TargetException("RuntimeError", "contextmanager generator did not yield")
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
                raise _TargetException("RuntimeError", "contextmanager generator did not stop")
            suppressed = args[0] is not None
            return _BoolValue(suppressed, self._z3.BoolVal(suppressed))

    def _prepare_async_iterator(self: _ResumableExecutorProtocol, value, node):
        if isinstance(value, _ResumableFrame) and value.is_async_generator:
            return value
        try:
            iterator = self._call_attribute(value, "__aiter__", [], {})
        except UnsupportedSyntaxError:
            return self._as_iterator(value)
        if isinstance(iterator, _ResumableFrame) and iterator.is_coroutine:
            iterator = yield from self._await_runtime_value(iterator, node)
        return iterator

    def _resume_async_next(self: _ResumableExecutorProtocol, iterator, node):
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
