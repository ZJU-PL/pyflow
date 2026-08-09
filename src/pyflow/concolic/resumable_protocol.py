"""Structural host contract shared by resumable interpreter components."""

from __future__ import annotations

import ast
from typing import Any, Generator, Protocol

from .resumable_cfg import _SuspensionPoint
from .runtime import (
    FunctionNode,
    _BoolValue,
    _ClassValue,
    _IteratorValue,
    _ModuleValue,
    _ResumeOperation,
    _ResumableFrame,
    _TaskValue,
)


class _ResumableExecutorProtocol(Protocol):
    """Capabilities supplied by the composed concolic executor."""

    env: dict[str, Any]
    path: list[Any]
    _z3: Any
    _functions: dict[str, FunctionNode]
    _classes: dict[str, _ClassValue]
    _globals: dict[str, Any]
    _current_module: _ModuleValue | None
    _global_names: set[str]
    _nonlocal_names: set[str]
    _closure_env: dict[str, Any] | None
    _current_class: _ClassValue | None
    _current_instance: Any
    _tasks: list[_TaskValue]
    _task_switches: int
    _max_task_switches: int
    _scheduler_mode: str
    _scheduler_clock: int
    _schedule_prefix: tuple[int, ...]
    _schedule_choices: list[tuple[int, int]]

    def _comprehension_machine(
        self, generators: Any, expression: ast.expr, owner: ast.AST
    ) -> Generator[_SuspensionPoint, Any, None]: ...

    def _resumable_function(
        self, function: FunctionNode
    ) -> Generator[_SuspensionPoint, Any, Any]: ...

    def _resume_iterator(
        self, iterator: _IteratorValue, operation: _ResumeOperation
    ) -> Any: ...

    def _call_attribute(
        self, value: Any, name: str, args: list[Any], keywords: dict[str, Any]
    ) -> Any: ...

    def _as_iterator(self, value: Any) -> _IteratorValue: ...

    def _to_string(self, value: Any) -> Any: ...

    def _truthy(self, value: Any) -> _BoolValue: ...

    def _create_task(self, value: Any, name: str | None = None) -> _TaskValue: ...

    def _choose_task_index(self, candidates: list[_TaskValue]) -> int: ...

    def _mark_task_ready(self, task: _TaskValue) -> None: ...

    def _step_task(self, task: _TaskValue) -> None: ...

    def _await_runtime_value(
        self, awaitable: Any, node: ast.AST
    ) -> Generator[_SuspensionPoint, Any, Any]: ...

    def _resume_frame(
        self, frame: _ResumableFrame, operation: _ResumeOperation
    ) -> Any: ...

    def _resume_async_context_operation(
        self, operation: Any, node: ast.AST
    ) -> Generator[_SuspensionPoint, Any, Any]: ...

    def _resume_async_generator_operation(
        self, operation: Any, node: ast.AST
    ) -> Generator[_SuspensionPoint, Any, Any]: ...

    def _drive_await_iterator(
        self, iterator: Any, node: ast.AST
    ) -> Generator[_SuspensionPoint, Any, Any]: ...

    def _prepare_async_iterator(
        self, value: Any, node: ast.AST
    ) -> Generator[_SuspensionPoint, Any, Any]: ...

    def _resume_async_next(
        self, iterator: Any, node: ast.AST
    ) -> Generator[_SuspensionPoint, Any, Any]: ...
