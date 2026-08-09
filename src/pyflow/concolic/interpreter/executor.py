"""Composition root for one concrete/symbolic AST execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..module_loader import _parameter_nodes, _required_positional_count
from ..resumable import _ResumableMixin
from ..runtime import (
    BranchCoverage,
    FunctionNode,
    SourceLocation,
    _Branch,
    _ClassValue,
    _InstanceValue,
    _ModuleValue,
    _TaskValue,
)
from .calls import _CallMixin
from .collections import _CollectionMethodMixin
from .coverage import _CoverageMixin
from .objects import _ObjectMixin
from .semantics import _SemanticMixin
from .statements import _StatementMixin
from .summaries import _SummaryMixin
from .values import _ValueMixin


class _Executor(
    _CoverageMixin,
    _ResumableMixin,
    _StatementMixin,
    _ValueMixin,
    _CallMixin,
    _SummaryMixin,
    _ObjectMixin,
    _CollectionMethodMixin,
    _SemanticMixin,
):
    def __init__(
        self,
        function: FunctionNode,
        z3: Any,
        inputs: tuple[Any, ...],
        max_loop_iterations: int,
        max_resume_steps: int,
        scheduler_mode: str,
        max_task_switches: int,
        schedule_prefix: tuple[int, ...],
        functions: dict[str, FunctionNode],
        classes: dict[str, _ClassValue],
        globals: dict[str, Any],
        module: _ModuleValue,
        module_cache: dict[Path, _ModuleValue],
    ) -> None:
        self._function = function
        self._z3 = z3
        self._max_loop_iterations = max_loop_iterations
        self._max_resume_steps = max_resume_steps
        self._resume_steps = 0
        self._scheduler_mode = scheduler_mode
        self._max_task_switches = max_task_switches
        self._task_switches = 0
        self._schedule_prefix = schedule_prefix
        self._schedule_choices: list[tuple[int, int]] = []
        self._scheduler_clock = 0
        self._tasks: list[_TaskValue] = []
        self._functions = functions
        self._classes = classes
        self._globals = globals
        self._current_module = module
        self._module_cache = module_cache
        self._global_values: dict[str, Any] = {}
        self._global_names: set[str] = set()
        self._nonlocal_names: set[str] = set()
        self._closure_env: dict[str, Any] | None = None
        self._current_class: _ClassValue | None = None
        self._current_instance: _InstanceValue | None = None
        self._yielded_values: list[Any] | None = None
        self._active_exception: Exception | None = None
        self._decorated_functions: dict[tuple[int, int], Any] = {}
        self._decorated_classes: dict[tuple[int, int], Any] = {}
        self._class_attributes: dict[int, dict[str, Any]] = {}
        self._covered_nodes: set[SourceLocation] = set()
        self._covered_branches: set[BranchCoverage] = set()
        self.path: list[_Branch] = []
        self.env: dict[str, Any] = {}

        parameters = _parameter_nodes(function)
        required = _required_positional_count(function)
        if not required <= len(inputs) <= len(parameters):
            raise ValueError(
                f"{function.name} expects {required} to {len(parameters)} inputs, "
                f"received {len(inputs)}"
            )
        initial_args = [
            self._input_value(parameter.arg, value)
            for parameter, value in zip(parameters, inputs)
        ]
        self.env = self._bind_arguments(function, initial_args, {})
