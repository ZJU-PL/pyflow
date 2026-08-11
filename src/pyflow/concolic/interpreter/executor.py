"""Composition root for one concrete/symbolic AST execution."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from ..core.modules import _parameter_nodes, _required_positional_count
from ..resumable import _ResumableMixin
from ..core.runtime import (
    BranchCoverage,
    FunctionNode,
    OperationObservation,
    SourceLocation,
    _Branch,
    _ClassValue,
    _HeapRefValue,
    _InstanceValue,
    _ModuleValue,
    _TaskValue,
)
from .calls import _CallMixin
from .collections import _CollectionMethodMixin
from .coverage import _CoverageMixin
from .model_registry import OpaqueRefinementStore
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
        execution_deadline: float | None = None,
        execution_timeout_reason: str = "per_run_timeout",
        max_symbolic_container_size: int = 3,
        entry_owner: _ClassValue | None = None,
        entry_kind: str = "function",
        refine_opaque_calls: bool = False,
        opaque_refinements: OpaqueRefinementStore | None = None,
        max_opaque_refinements: int = 1000,
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
        self._execution_deadline = execution_deadline
        self._execution_timeout_reason = execution_timeout_reason
        self._max_symbolic_container_size = max_symbolic_container_size
        self._entry_owner = entry_owner
        self._entry_kind = entry_kind
        self._refine_opaque_calls = refine_opaque_calls
        self._opaque_refinements = opaque_refinements or OpaqueRefinementStore()
        self._max_opaque_refinements = max_opaque_refinements
        self._opaque_functions: dict[str, Any] = {}
        self._operation_observations: list[OperationObservation] = []
        self.input_constraints: list[Any] = []
        self.guidance_constraints: list[Any] = []
        self._input_memo: dict[int, Any] = {}
        self._heap_references: dict[int, _HeapRefValue] = {}
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
        implicit_parameter_count = 1 if entry_kind in {"method", "classmethod"} else 0
        exposed_parameters = parameters[implicit_parameter_count:]
        required = max(0, _required_positional_count(function) - implicit_parameter_count)
        if not required <= len(inputs) <= len(exposed_parameters):
            raise ValueError(
                f"{function.name} expects {required} to {len(exposed_parameters)} inputs, "
                f"received {len(inputs)}"
            )
        initial_args = [
            self._input_value(parameter.arg, value)
            for parameter, value in zip(exposed_parameters, inputs)
        ]
        if entry_kind == "classmethod":
            assert entry_owner is not None
            bound_args = [entry_owner, *initial_args]
        elif entry_kind == "method":
            assert entry_owner is not None
            bound_args = [self._construct(entry_owner, [], {}), *initial_args]
        else:
            bound_args = initial_args
        self.input_values = tuple(initial_args)
        self.env = self._bind_arguments(function, bound_args, {})
        self.pre_env = copy.deepcopy(self.env)

    def _heap_reference(self, value: Any) -> _HeapRefValue:
        identity = id(value)
        reference = self._heap_references.get(identity)
        if reference is None:
            token = len(self._heap_references) + 1
            reference = _HeapRefValue(token, self._z3.IntVal(token))
            self._heap_references[identity] = reference
        return reference
