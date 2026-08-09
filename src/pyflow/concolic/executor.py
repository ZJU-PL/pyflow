"""Execution orchestration for PyFlow's AST-level concolic engine."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any, Iterable

from .calls import _CallMixin
from .collection_methods import _CollectionMethodMixin
from .contracts import Postcondition, parse_postconditions
from .module_loader import _load_module, _parameter_nodes, _required_positional_count
from .objects import _ObjectMixin
from .runtime import (
    ConcolicError,
    ContractCounterexample,
    ExplorationResult,
    FunctionNode,
    RunRecord,
    _Branch,
    _ClassValue,
    _InstanceValue,
    _ModuleValue,
    _TaskValue,
    _TargetException,
)
from .resumable import _ResumableMixin
from .semantics import _SemanticMixin
from .statements import _StatementMixin
from .summaries import _SummaryMixin
from .support import _input_key, _valid_input
from .values import _ValueMixin


class _Executor(
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
        self._scheduler_cursor = 0
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


def explore_file(
    path: str | Path,
    *,
    entry: str = "main",
    initial_inputs: Iterable[Any] | None = None,
    max_iterations: int = 50,
    max_loop_iterations: int = 100,
    max_resume_steps: int = 1000,
    scheduler: str = "fifo",
    max_task_switches: int = 1000,
    check_contracts: bool = False,
) -> ExplorationResult:
    """Explore feasible branches in ``entry`` and return generated inputs.

    Z3 is imported only when exploration is requested so PyFlow remains usable
    without the optional ``z3-solver`` dependency.  When ``check_contracts``
    is enabled, supported PEP 316 ``post:`` clauses are also solved for a
    counterexample.
    """
    if max_iterations < 1:
        raise ValueError("max_iterations must be at least one")
    if max_loop_iterations < 1:
        raise ValueError("max_loop_iterations must be at least one")
    if max_resume_steps < 1:
        raise ValueError("max_resume_steps must be at least one")
    if scheduler not in {"fifo", "nondeterministic"}:
        raise ValueError("scheduler must be 'fifo' or 'nondeterministic'")
    if max_task_switches < 1:
        raise ValueError("max_task_switches must be at least one")
    try:
        import z3
    except ImportError as error:  # pragma: no cover - depends on installation
        raise ConcolicError(
            "concolic exploration requires the optional 'z3-solver' dependency"
        ) from error

    source_path = Path(path).resolve()
    module_cache: dict[Path, _ModuleValue] = {}
    module = _load_module(source_path, module_cache)
    function = module.functions.get(entry)
    if function is None:
        raise ValueError(f"entry function {entry!r} was not found")
    postconditions = parse_postconditions(function) if check_contracts else ()
    parameters = _parameter_nodes(function)
    initial = (
        tuple(initial_inputs)
        if initial_inputs is not None
        else (0,) * _required_positional_count(function)
    )
    if not all(_valid_input(value) for value in initial):
        raise ValueError(
            "initial_inputs must contain integers, strings, Booleans, or lists of them"
        )
    if len(initial) > len(parameters):
        raise ValueError(f"{entry} received too many initial inputs")
    parameter_names = tuple(parameter.arg for parameter in parameters[: len(initial)])
    functions = module.functions
    classes = module.classes

    pending: deque[tuple[tuple[Any, ...], tuple[int, ...]]] = deque([(initial, ())])
    queued_inputs = {_input_key(initial)}
    queued_executions: set[tuple[Any, tuple[int, ...]]] = {
        (_input_key(initial), ())
    }
    queued_paths: set[tuple[tuple[str, bool], ...]] = set()
    observed_path_prefixes: set[tuple[tuple[str, bool], ...]] = set()
    observed_schedules: set[tuple[Any, tuple[int, ...]]] = set()
    runs: list[RunRecord] = []
    unsatisfiable_paths = 0
    counterexamples: list[ContractCounterexample] = []
    seen_counterexamples: set[tuple[str, Any]] = set()
    queued_contract_targets: set[tuple[Any, ...]] = set()

    while pending and len(runs) < max_iterations:
        inputs, schedule_prefix = pending.popleft()
        executor = _Executor(
            function,
            z3,
            inputs,
            max_loop_iterations,
            max_resume_steps,
            scheduler,
            max_task_switches,
            schedule_prefix,
            functions,
            classes,
            module.globals,
            module,
            module_cache,
        )
        try:
            result, path_constraints = executor.run()
            contract_conditions = _evaluate_postconditions(
                executor, postconditions
            )
        except (ConcolicError, _TargetException):
            if inputs == initial and not schedule_prefix:
                raise
            continue
        schedule = tuple(chosen for _, chosen in executor._schedule_choices)
        schedule_key = (_input_key(inputs), schedule)
        if schedule_key in observed_schedules:
            continue
        observed_schedules.add(schedule_key)
        runs.append(RunRecord(inputs, result, len(path_constraints), schedule))
        observed_path_prefixes.update(
            tuple(branch.key() for branch in path_constraints[: index + 1])
            for index in range(len(path_constraints))
        )

        if scheduler == "nondeterministic":
            prior_choices: list[int] = []
            for candidate_count, chosen in executor._schedule_choices:
                if candidate_count > 1:
                    for alternative in range(candidate_count):
                        if alternative == chosen:
                            continue
                        alternative_prefix = tuple((*prior_choices, alternative))
                        execution_key = (_input_key(inputs), alternative_prefix)
                        if execution_key not in queued_executions:
                            queued_executions.add(execution_key)
                            pending.append((inputs, alternative_prefix))
                prior_choices.append(chosen)

        for clause, condition in contract_conditions:
            if not condition.concrete:
                key = (clause.source, _input_key(inputs))
                if key not in seen_counterexamples:
                    seen_counterexamples.add(key)
                    counterexamples.append(
                        ContractCounterexample(
                            clause.source, inputs, result, len(path_constraints)
                        )
                    )
                continue
            target = (
                tuple(branch.key() for branch in path_constraints),
                clause.source,
                condition.symbolic.sexpr(),
            )
            if target in queued_contract_targets:
                continue
            queued_contract_targets.add(target)
            model_inputs = _solve_path(
                z3, parameter_names, initial, path_constraints, _Branch(condition.symbolic, True)
            )
            if model_inputs is not None and _input_key(model_inputs) not in queued_inputs:
                queued_inputs.add(_input_key(model_inputs))
                execution_key = (_input_key(model_inputs), ())
                queued_executions.add(execution_key)
                pending.append((model_inputs, ()))

        for index, branch in enumerate(path_constraints):
            target = tuple(prior.key() for prior in path_constraints[:index]) + (
                (branch.expression.sexpr(), not branch.taken),
            )
            if target in observed_path_prefixes or target in queued_paths:
                continue
            queued_paths.add(target)
            model_inputs = _solve_path(
                z3, parameter_names, initial, path_constraints[:index], branch
            )
            if model_inputs is None:
                unsatisfiable_paths += 1
            elif _input_key(model_inputs) not in queued_inputs:
                queued_inputs.add(_input_key(model_inputs))
                execution_key = (_input_key(model_inputs), ())
                queued_executions.add(execution_key)
                pending.append((model_inputs, ()))

    return ExplorationResult(
        entry,
        parameter_names,
        tuple(runs),
        unsatisfiable_paths,
        tuple(counterexamples),
    )


def _evaluate_postconditions(
    executor: _Executor, clauses: tuple[Postcondition, ...]
) -> tuple[tuple[Postcondition, Any], ...]:
    """Evaluate clauses in the post-state without leaking ``__return__``."""

    if not clauses:
        return ()
    previous_env = executor.env
    executor.env = {**previous_env, "__return__": executor._last_result}
    try:
        return tuple(
            (clause, executor._truthy(executor._evaluate(clause.expression)))
            for clause in clauses
        )
    finally:
        executor.env = previous_env


def _solve_path(
    z3: Any,
    parameter_names: tuple[str, ...],
    input_kinds: tuple[Any, ...],
    prefix: tuple[_Branch, ...],
    flipped: _Branch,
) -> tuple[Any, ...] | None:
    solver = z3.Solver()
    for branch in prefix:
        solver.add(branch.expression if branch.taken else z3.Not(branch.expression))
    solver.add(flipped.expression if not flipped.taken else z3.Not(flipped.expression))
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    return tuple(
        _model_value(model, z3, name, kind)
        for name, kind in zip(parameter_names, input_kinds)
    )


def _model_value(model: Any, z3: Any, name: str, kind: Any) -> Any:
    if isinstance(kind, list):
        return [
            _model_value(model, z3, f"{name}_{index}", item)
            for index, item in enumerate(kind)
        ]
    if isinstance(kind, dict):
        return {
            key: _model_value(model, z3, f"{name}_{key}", item)
            for key, item in kind.items()
        }
    if isinstance(kind, bool):
        return z3.is_true(model.eval(z3.Bool(name), model_completion=True))
    if isinstance(kind, str):
        return model.eval(z3.String(name), model_completion=True).as_string()
    if isinstance(kind, float):
        value = model.eval(z3.Real(name), model_completion=True)
        return value.numerator_as_long() / value.denominator_as_long()
    return model.eval(z3.Int(name), model_completion=True).as_long()
