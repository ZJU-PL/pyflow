"""Cooperative and nondeterministic task scheduling for concolic execution."""

from __future__ import annotations

from typing import Any

from .protocol import _ResumableExecutorProtocol
from ..runtime import (
    ConcolicError,
    _GatherValue,
    _ResumeKind,
    _ResumeOperation,
    _ResumableFrame,
    _Returned,
    _TargetException,
    _TaskValue,
    _TaskWait,
)


class _ResumableSchedulerMixin:
    def _drive_coroutine(
        self: _ResumableExecutorProtocol, frame: _ResumableFrame
    ) -> Any:
        main_task = _TaskValue(frame, "<entry>")
        self._mark_task_ready(main_task)
        self._tasks.insert(0, main_task)
        try:
            while not main_task.done:
                self._check_execution_budget()
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
                task = candidates[self._choose_task_index(candidates)]
                self._step_task(task)
                if not task.done and task.blocked_on is None:
                    self._mark_task_ready(task)
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

    def _choose_task_index(
        self: _ResumableExecutorProtocol, candidates: list[_TaskValue]
    ) -> int:
        count = len(candidates)
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
            chosen = min(
                range(count),
                key=lambda index: (
                    not candidates[index].cancel_requested,
                    candidates[index].ready_order,
                ),
            )
        self._schedule_choices.append((count, chosen))
        return chosen

    def _mark_task_ready(
        self: _ResumableExecutorProtocol, task: _TaskValue
    ) -> None:
        task.ready_order = self._scheduler_clock
        self._scheduler_clock += 1

    def _step_task(
        self: _ResumableExecutorProtocol, task: _TaskValue
    ) -> None:
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

    def _create_task(
        self: _ResumableExecutorProtocol,
        value: Any,
        name: str | None = None,
    ) -> _TaskValue:
        if isinstance(value, _TaskValue):
            return value
        if not isinstance(value, _ResumableFrame) or not value.is_coroutine:
            raise _TargetException("TypeError", "a coroutine was expected")
        task = _TaskValue(value, name)
        self._mark_task_ready(task)
        self._tasks.append(task)
        return task

    def _create_gather(
        self: _ResumableExecutorProtocol,
        values,
        return_exceptions: bool,
    ) -> _GatherValue:
        return _GatherValue(
            tuple(self._create_task(value) for value in values), return_exceptions
        )
