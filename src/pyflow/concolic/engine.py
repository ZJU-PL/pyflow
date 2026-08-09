"""Public exploration workflow for PyFlow's AST-level concolic engine."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from pathlib import Path
from time import monotonic
from typing import Any, Iterable

from .contracts import Postcondition, parse_postconditions
from .interpreter import _Executor
from .module_loader import _load_module, _parameter_nodes, _required_positional_count
from .runtime import (
    BranchCoverage,
    ConcolicError,
    ContractCounterexample,
    CoverageSnapshot,
    ExecutionOutcome,
    ExecutionTimeoutError,
    ExplorationResult,
    ExplorationStatistics,
    OutcomeKind,
    RunRecord,
    SourceLocation,
    UnsupportedSyntaxError,
    _Branch,
    _ModuleValue,
    _TargetException,
)
from .search import _ExplorationQueue, _ExplorationState
from .support import _concrete, _input_key, _valid_input


@dataclass
class _Counters:
    executions: int = 0
    returned: int = 0
    target_exceptions: int = 0
    unsupported: int = 0
    resource_limits: int = 0
    engine_errors: int = 0
    solver_calls: int = 0
    satisfiable_queries: int = 0
    unsatisfiable_queries: int = 0
    solver_timeouts: int = 0
    states_enqueued: int = 1
    states_dropped: int = 0
    maximum_queue_size: int = 1
    coverage_discoveries: int = 0
    iterations_without_discovery: int = 0
    per_run_timeouts: int = 0
    execution_seconds: float = 0.0
    solver_seconds: float = 0.0

    def note_outcome(self, outcome: ExecutionOutcome) -> None:
        if outcome.kind is OutcomeKind.RETURNED:
            self.returned += 1
        elif outcome.kind is OutcomeKind.TARGET_EXCEPTION:
            self.target_exceptions += 1
        elif outcome.kind is OutcomeKind.UNSUPPORTED:
            self.unsupported += 1
        elif outcome.kind is OutcomeKind.RESOURCE_LIMIT:
            self.resource_limits += 1
        else:
            self.engine_errors += 1

    def snapshot(
        self, stop_reason: str, total_seconds: float
    ) -> ExplorationStatistics:
        return ExplorationStatistics(
            executions=self.executions,
            returned=self.returned,
            target_exceptions=self.target_exceptions,
            unsupported=self.unsupported,
            resource_limits=self.resource_limits,
            engine_errors=self.engine_errors,
            solver_calls=self.solver_calls,
            satisfiable_queries=self.satisfiable_queries,
            unsatisfiable_queries=self.unsatisfiable_queries,
            solver_timeouts=self.solver_timeouts,
            states_enqueued=self.states_enqueued,
            states_dropped=self.states_dropped,
            maximum_queue_size=self.maximum_queue_size,
            coverage_discoveries=self.coverage_discoveries,
            iterations_without_discovery=self.iterations_without_discovery,
            per_run_timeouts=self.per_run_timeouts,
            total_seconds=total_seconds,
            execution_seconds=self.execution_seconds,
            solver_seconds=self.solver_seconds,
            stop_reason=stop_reason,
        )


@dataclass(frozen=True)
class _Budgets:
    total_deadline: float | None
    per_run_timeout: float | None
    solver_timeout: float | None
    max_solver_calls: int | None
    max_pending_states: int


@dataclass(frozen=True)
class _SolveResult:
    inputs: tuple[Any, ...] | None = None
    stop_reason: str | None = None


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
    max_schedule_states: int = 1000,
    search_strategy: str = "coverage",
    max_uninteresting_iterations: int | None = None,
    total_timeout: float | None = None,
    per_run_timeout: float | None = None,
    solver_timeout: float | None = None,
    max_solver_calls: int | None = None,
    max_pending_states: int = 10000,
    check_contracts: bool = False,
) -> ExplorationResult:
    """Explore feasible branches in ``entry`` and return generated inputs."""
    _validate_options(
        max_iterations,
        max_loop_iterations,
        max_resume_steps,
        scheduler,
        max_task_switches,
        max_schedule_states,
        search_strategy,
        max_uninteresting_iterations,
        total_timeout,
        per_run_timeout,
        solver_timeout,
        max_solver_calls,
        max_pending_states,
    )
    try:
        import z3  # type: ignore[import-untyped]
    except ImportError as error:  # pragma: no cover - depends on installation
        raise ConcolicError(
            "concolic exploration requires the optional 'z3-solver' dependency"
        ) from error

    started_at = monotonic()
    budgets = _Budgets(
        total_deadline=(
            started_at + total_timeout if total_timeout is not None else None
        ),
        per_run_timeout=per_run_timeout,
        solver_timeout=solver_timeout,
        max_solver_calls=max_solver_calls,
        max_pending_states=max_pending_states,
    )
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
    pending = _ExplorationQueue(
        search_strategy, _ExplorationState(initial, ())
    )
    counters = _Counters()
    covered_nodes: set[SourceLocation] = set()
    covered_branches: set[BranchCoverage] = set()
    queued_inputs = {_input_key(initial)}
    queued_executions: set[tuple[Any, tuple[int, ...]]] = {
        (_input_key(initial), ())
    }
    schedule_state_counts: dict[Any, int] = {_input_key(initial): 1}
    queued_paths: set[tuple[tuple[str, bool], ...]] = set()
    observed_path_prefixes: set[tuple[tuple[str, bool], ...]] = set()
    observed_schedules: set[tuple[Any, tuple[int, ...]]] = set()
    runs: list[RunRecord] = []
    unsatisfiable_paths = 0
    counterexamples: list[ContractCounterexample] = []
    seen_counterexamples: set[tuple[str, Any]] = set()
    queued_contract_targets: set[tuple[Any, ...]] = set()
    stop_reason = "exhausted"
    budget_stop_reason: str | None = None
    queue_was_truncated = False

    def enqueue(state: _ExplorationState) -> None:
        nonlocal queue_was_truncated
        if len(pending) >= budgets.max_pending_states:
            counters.states_dropped += 1
            queue_was_truncated = True
            return
        pending.append(state)
        counters.states_enqueued += 1
        counters.maximum_queue_size = max(counters.maximum_queue_size, len(pending))

    while pending and counters.executions < max_iterations:
        if (
            budgets.total_deadline is not None
            and monotonic() >= budgets.total_deadline
        ):
            budget_stop_reason = "total_timeout"
            break
        state = pending.pop(covered_branches)
        inputs = state.inputs
        schedule_prefix = state.schedule_prefix
        execution_started = monotonic()
        execution_deadline, timeout_reason = _execution_deadline(
            execution_started, budgets
        )
        executor = _Executor(
            function,
            z3,
            inputs,
            max_loop_iterations,
            max_resume_steps,
            scheduler,
            max_task_switches,
            schedule_prefix,
            module.functions,
            module.classes,
            module.globals,
            module,
            module_cache,
            execution_deadline,
            timeout_reason,
        )
        counters.executions += 1
        result: Any = None
        contract_conditions: tuple[tuple[Postcondition, Any], ...] = ()
        try:
            result, path_constraints = executor.run()
            contract_conditions = _evaluate_postconditions(executor, postconditions)
            outcome = ExecutionOutcome(OutcomeKind.RETURNED)
        except (ConcolicError, _TargetException) as error:
            path_constraints = tuple(executor.path)
            outcome = _error_outcome(error)
            if isinstance(error, ExecutionTimeoutError):
                if error.reason == "per_run_timeout":
                    counters.per_run_timeouts += 1
                else:
                    budget_stop_reason = error.reason
        except Exception as error:  # Keep one bad state from aborting the search.
            path_constraints = tuple(executor.path)
            outcome = ExecutionOutcome(
                OutcomeKind.ENGINE_ERROR,
                type(error).__name__,
                str(error) or None,
            )
        finally:
            counters.execution_seconds += monotonic() - execution_started
        counters.note_outcome(outcome)

        coverage = executor._coverage_snapshot()
        discovered = bool(
            coverage.nodes - covered_nodes
            or coverage.branches - covered_branches
        )
        covered_nodes.update(coverage.nodes)
        covered_branches.update(coverage.branches)
        if discovered:
            counters.coverage_discoveries += 1
            counters.iterations_without_discovery = 0
        else:
            counters.iterations_without_discovery += 1

        schedule = tuple(chosen for _, chosen in executor._schedule_choices)
        post_inputs = tuple(
            _concrete(executor.env[name]) for name in parameter_names
        )
        schedule_key = (_input_key(inputs), schedule)
        if schedule_key not in observed_schedules:
            observed_schedules.add(schedule_key)
            runs.append(
                RunRecord(
                    inputs,
                    result,
                    len(path_constraints),
                    schedule,
                    outcome,
                    coverage,
                    post_inputs,
                )
            )
        observed_path_prefixes.update(
            tuple(branch.key() for branch in path_constraints[: index + 1])
            for index in range(len(path_constraints))
        )
        if budget_stop_reason is not None:
            break

        if scheduler == "nondeterministic":
            prior_choices: list[int] = []
            for candidate_count, chosen in executor._schedule_choices:
                if candidate_count > 1:
                    for alternative in range(candidate_count):
                        if alternative == chosen:
                            continue
                        alternative_prefix = tuple((*prior_choices, alternative))
                        execution_key = (_input_key(inputs), alternative_prefix)
                        input_key = _input_key(inputs)
                        if (
                            execution_key not in queued_executions
                            and schedule_state_counts.get(input_key, 0)
                            < max_schedule_states
                        ):
                            queued_executions.add(execution_key)
                            schedule_state_counts[input_key] = (
                                schedule_state_counts.get(input_key, 0) + 1
                            )
                            enqueue(_ExplorationState(inputs, alternative_prefix))
                prior_choices.append(chosen)

        if outcome.kind is OutcomeKind.RETURNED:
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
                solved = _solve_path(
                    z3,
                    parameter_names,
                    initial,
                    path_constraints,
                    _Branch(condition.symbolic, True),
                    counters,
                    budgets,
                )
                if solved.stop_reason is not None:
                    budget_stop_reason = solved.stop_reason
                    break
                model_inputs = solved.inputs
                if (
                    model_inputs is not None
                    and _input_key(model_inputs) not in queued_inputs
                ):
                    queued_inputs.add(_input_key(model_inputs))
                    queued_executions.add((_input_key(model_inputs), ()))
                    schedule_state_counts.setdefault(_input_key(model_inputs), 1)
                    enqueue(_ExplorationState(model_inputs, ()))

        if budget_stop_reason is not None:
            break

        for index, branch in enumerate(path_constraints):
            target = tuple(prior.key() for prior in path_constraints[:index]) + (
                (branch.expression.sexpr(), not branch.taken),
            )
            if target in observed_path_prefixes or target in queued_paths:
                continue
            queued_paths.add(target)
            solved = _solve_path(
                z3,
                parameter_names,
                initial,
                path_constraints[:index],
                branch,
                counters,
                budgets,
            )
            if solved.stop_reason is not None:
                budget_stop_reason = solved.stop_reason
                break
            model_inputs = solved.inputs
            if model_inputs is None:
                unsatisfiable_paths += 1
            elif _input_key(model_inputs) not in queued_inputs:
                queued_inputs.add(_input_key(model_inputs))
                queued_executions.add((_input_key(model_inputs), ()))
                schedule_state_counts.setdefault(_input_key(model_inputs), 1)
                target_branch = BranchCoverage(
                    branch.location, branch.kind, not branch.taken
                )
                enqueue(_ExplorationState(model_inputs, (), target_branch))

        if budget_stop_reason is not None:
            break

        if (
            pending
            and max_uninteresting_iterations is not None
            and counters.iterations_without_discovery >= max_uninteresting_iterations
        ):
            stop_reason = "max_uninteresting_iterations"
            break

    if budget_stop_reason is not None:
        stop_reason = budget_stop_reason
    elif stop_reason != "max_uninteresting_iterations":
        if pending:
            stop_reason = "max_iterations"
        elif queue_was_truncated:
            stop_reason = "max_pending_states"
        else:
            stop_reason = "exhausted"
    aggregate_coverage = CoverageSnapshot(
        frozenset(covered_nodes), frozenset(covered_branches)
    )
    return ExplorationResult(
        entry=entry,
        parameter_names=parameter_names,
        runs=tuple(runs),
        unsatisfiable_paths=unsatisfiable_paths,
        counterexamples=tuple(counterexamples),
        coverage=aggregate_coverage,
        statistics=counters.snapshot(stop_reason, monotonic() - started_at),
    )


def _validate_options(
    max_iterations: int,
    max_loop_iterations: int,
    max_resume_steps: int,
    scheduler: str,
    max_task_switches: int,
    max_schedule_states: int,
    search_strategy: str,
    max_uninteresting_iterations: int | None,
    total_timeout: float | None,
    per_run_timeout: float | None,
    solver_timeout: float | None,
    max_solver_calls: int | None,
    max_pending_states: int,
) -> None:
    positive_options = {
        "max_iterations": max_iterations,
        "max_loop_iterations": max_loop_iterations,
        "max_resume_steps": max_resume_steps,
        "max_task_switches": max_task_switches,
        "max_schedule_states": max_schedule_states,
        "max_pending_states": max_pending_states,
    }
    for name, value in positive_options.items():
        if value < 1:
            raise ValueError(f"{name} must be at least one")
    if scheduler not in {"fifo", "nondeterministic"}:
        raise ValueError("scheduler must be 'fifo' or 'nondeterministic'")
    if search_strategy not in {"fifo", "coverage"}:
        raise ValueError("search_strategy must be 'fifo' or 'coverage'")
    if (
        max_uninteresting_iterations is not None
        and max_uninteresting_iterations < 1
    ):
        raise ValueError("max_uninteresting_iterations must be at least one")
    optional_positive = {
        "total_timeout": total_timeout,
        "per_run_timeout": per_run_timeout,
        "solver_timeout": solver_timeout,
        "max_solver_calls": max_solver_calls,
    }
    for name, optional_value in optional_positive.items():
        if optional_value is not None and optional_value <= 0:
            raise ValueError(f"{name} must be greater than zero")


def _error_outcome(error: ConcolicError | _TargetException) -> ExecutionOutcome:
    if isinstance(error, _TargetException):
        return ExecutionOutcome(
            OutcomeKind.TARGET_EXCEPTION, error.name, error.message or None
        )
    if isinstance(error, UnsupportedSyntaxError):
        return ExecutionOutcome(
            OutcomeKind.UNSUPPORTED, type(error).__name__, str(error) or None
        )
    if isinstance(error, ExecutionTimeoutError):
        return ExecutionOutcome(
            OutcomeKind.RESOURCE_LIMIT,
            type(error).__name__,
            error.reason,
        )
    message = str(error)
    if "exceeded" in message or "deadlocked" in message or "limit" in message:
        kind = OutcomeKind.RESOURCE_LIMIT
    else:
        kind = OutcomeKind.ENGINE_ERROR
    return ExecutionOutcome(kind, type(error).__name__, message or None)


def _execution_deadline(
    started_at: float, budgets: _Budgets
) -> tuple[float | None, str]:
    candidates: list[tuple[float, str]] = []
    if budgets.total_deadline is not None:
        candidates.append((budgets.total_deadline, "total_timeout"))
    if budgets.per_run_timeout is not None:
        candidates.append(
            (started_at + budgets.per_run_timeout, "per_run_timeout")
        )
    if not candidates:
        return None, "per_run_timeout"
    return min(candidates, key=lambda candidate: candidate[0])


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
    counters: _Counters,
    budgets: _Budgets,
) -> _SolveResult:
    now = monotonic()
    if budgets.total_deadline is not None and now >= budgets.total_deadline:
        return _SolveResult(stop_reason="total_timeout")
    if (
        budgets.max_solver_calls is not None
        and counters.solver_calls >= budgets.max_solver_calls
    ):
        return _SolveResult(stop_reason="max_solver_calls")
    counters.solver_calls += 1
    solver = z3.Solver()
    timeout_reason: str | None = None
    effective_timeout = budgets.solver_timeout
    if budgets.total_deadline is not None:
        remaining = max(0.0, budgets.total_deadline - now)
        if effective_timeout is None or remaining < effective_timeout:
            effective_timeout = remaining
            timeout_reason = "total_timeout"
    if effective_timeout is not None:
        if timeout_reason is None:
            timeout_reason = "solver_timeout"
        solver.set(timeout=max(1, ceil(effective_timeout * 1000)))
    for branch in prefix:
        solver.add(branch.expression if branch.taken else z3.Not(branch.expression))
    solver.add(flipped.expression if not flipped.taken else z3.Not(flipped.expression))
    solver_started = monotonic()
    result = solver.check()
    counters.solver_seconds += monotonic() - solver_started
    if (
        budgets.total_deadline is not None
        and monotonic() >= budgets.total_deadline
    ):
        return _SolveResult(stop_reason="total_timeout")
    if result == z3.unknown:
        if "timeout" in solver.reason_unknown().lower() or timeout_reason is not None:
            counters.solver_timeouts += 1
            return _SolveResult(stop_reason=timeout_reason or "solver_timeout")
        return _SolveResult(stop_reason="solver_unknown")
    if result != z3.sat:
        counters.unsatisfiable_queries += 1
        return _SolveResult()
    counters.satisfiable_queries += 1
    model = solver.model()
    return _SolveResult(
        tuple(
            _model_value(model, z3, name, kind)
            for name, kind in zip(parameter_names, input_kinds)
        )
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
