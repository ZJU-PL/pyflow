"""Creation and resumption of concolic generator and coroutine frames."""

from __future__ import annotations

import ast
from typing import Any

from .resumable_cfg import _ResumableCFG, _SuspensionPoint, _has_yield
from .resumable_protocol import _ResumableExecutorProtocol
from .runtime import (
    ConcolicError,
    FunctionNode,
    _Awaiting,
    _CoroutineFrame,
    _GeneratorFrame,
    _Raised,
    _ResumeKind,
    _ResumeOperation,
    _ResumeOutcome,
    _ResumableFrame,
    _Returned,
    _TargetException,
    _Yielded,
)


class _ResumableFrameMixin:
    def _make_generator_expression(
        self: _ResumableExecutorProtocol, expression: ast.GeneratorExp
    ):
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
        self: _ResumableExecutorProtocol,
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

    def _resume_frame(
        self: _ResumableExecutorProtocol,
        frame: _ResumableFrame,
        operation: _ResumeOperation,
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
