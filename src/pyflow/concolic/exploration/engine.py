"""Public exploration workflow for PyFlow's AST-level concolic engine."""

from __future__ import annotations

import ast

from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Any, Iterable

from .contracts import (
    FunctionContracts,
    Postcondition,
    Precondition,
    merge_contracts,
    parse_class_invariants,
    parse_contracts,
    registered_contracts,
    with_invariants,
)
from ..core.modules import _load_module, _parameter_nodes, _required_positional_count
from ..core.runtime import (
    BranchCoverage,
    ConcolicError,
    ContractCounterexample,
    CoverageSnapshot,
    ExecutionOutcome,
    ExecutionTimeoutError,
    ExplorationResult,
    ExplorationStatistics,
    FunctionNode,
    OutcomeKind,
    RunRecord,
    SourceLocation,
    UnsupportedSyntaxError,
    _Branch,
    _BoolValue,
    _ClassValue,
    _DictValue,
    _FloatValue,
    _IntValue,
    _ListValue,
    _ModuleValue,
    _SetValue,
    _TargetException,
    _StringValue,
    _TupleValue,
)
from ..core.support import _deep_concrete, _input_key, _valid_input
from ..interpreter import _Executor
from .search import _ExplorationQueue, _ExplorationState, _PathTree
from .state_space import SolverResultCache, SolverStateSpace


@dataclass
class _Counters:
    executions: int = 0
    returned: int = 0
    target_exceptions: int = 0
    precondition_rejected: int = 0
    unsupported: int = 0
    resource_limits: int = 0
    engine_errors: int = 0
    solver_calls: int = 0
    satisfiable_queries: int = 0
    unsatisfiable_queries: int = 0
    solver_timeouts: int = 0
    solver_unknowns: int = 0
    solver_cache_hits: int = 0
    states_enqueued: int = 1
    states_dropped: int = 0
    maximum_queue_size: int = 1
    path_tree_nodes: int = 1
    coverage_discoveries: int = 0
    iterations_without_discovery: int = 0
    per_run_timeouts: int = 0
    execution_seconds: float = 0.0
    solver_seconds: float = 0.0
    solver_diagnostics: list[str] = field(default_factory=list)

    def note_outcome(self, outcome: ExecutionOutcome) -> None:
        if outcome.kind is OutcomeKind.RETURNED:
            self.returned += 1
        elif outcome.kind is OutcomeKind.TARGET_EXCEPTION:
            self.target_exceptions += 1
        elif outcome.kind is OutcomeKind.PRECONDITION_REJECTED:
            self.precondition_rejected += 1
        elif outcome.kind is OutcomeKind.UNSUPPORTED:
            self.unsupported += 1
        elif outcome.kind is OutcomeKind.RESOURCE_LIMIT:
            self.resource_limits += 1
        else:
            self.engine_errors += 1

    def snapshot(self, stop_reason: str, total_seconds: float) -> ExplorationStatistics:
        return ExplorationStatistics(
            executions=self.executions,
            returned=self.returned,
            target_exceptions=self.target_exceptions,
            precondition_rejected=self.precondition_rejected,
            unsupported=self.unsupported,
            resource_limits=self.resource_limits,
            engine_errors=self.engine_errors,
            solver_calls=self.solver_calls,
            satisfiable_queries=self.satisfiable_queries,
            unsatisfiable_queries=self.unsatisfiable_queries,
            solver_timeouts=self.solver_timeouts,
            solver_unknowns=self.solver_unknowns,
            solver_cache_hits=self.solver_cache_hits,
            states_enqueued=self.states_enqueued,
            states_dropped=self.states_dropped,
            maximum_queue_size=self.maximum_queue_size,
            path_tree_nodes=self.path_tree_nodes,
            coverage_discoveries=self.coverage_discoveries,
            iterations_without_discovery=self.iterations_without_discovery,
            per_run_timeouts=self.per_run_timeouts,
            total_seconds=total_seconds,
            execution_seconds=self.execution_seconds,
            solver_seconds=self.solver_seconds,
            stop_reason=stop_reason,
            solver_diagnostics=tuple(self.solver_diagnostics),
        )


@dataclass(frozen=True)
class _Budgets:
    total_deadline: float | None
    per_run_timeout: float | None
    solver_timeout: float | None
    solver_rlimit: int | None
    max_solver_calls: int | None
    max_pending_states: int


@dataclass(frozen=True)
class _SolveResult:
    inputs: tuple[Any, ...] | None = None
    stop_reason: str | None = None
    inconclusive_reason: str | None = None


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
    solver_rlimit: int | None = None,
    max_solver_calls: int | None = None,
    max_pending_states: int = 10000,
    max_symbolic_container_size: int = 3,
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
        solver_rlimit,
        max_solver_calls,
        max_pending_states,
        max_symbolic_container_size,
    )
    try:
        import z3  # type: ignore[import-untyped]
    except ImportError as error:  # pragma: no cover - depends on installation
        raise ConcolicError(
            "concolic exploration requires the optional 'z3-solver' dependency"
        ) from error

    started_at = monotonic()
    budgets = _Budgets(
        total_deadline=(started_at + total_timeout if total_timeout is not None else None),
        per_run_timeout=per_run_timeout,
        solver_timeout=solver_timeout,
        solver_rlimit=solver_rlimit,
        max_solver_calls=max_solver_calls,
        max_pending_states=max_pending_states,
    )
    source_path = Path(path).resolve()
    module_cache: dict[Path, _ModuleValue] = {}
    module = _load_module(source_path, module_cache)
    function, entry_owner, entry_kind = _resolve_entry(module, entry)
    contracts = FunctionContracts()
    if check_contracts:
        contracts = parse_contracts(function)
        if entry_owner is not None and entry_kind == "method":
            contracts = with_invariants(
                contracts,
                _class_invariants(module, entry_owner),
                function.name,
            )
        contracts = merge_contracts(
            contracts,
            registered_contracts(entry, f"{source_path.stem}:{entry}"),
        )
    postconditions = contracts.postconditions
    all_parameters = _parameter_nodes(function)
    implicit_parameter_count = 1 if entry_kind in {"method", "classmethod"} else 0
    parameters = all_parameters[implicit_parameter_count:]
    required_input_count = max(0, _required_positional_count(function) - implicit_parameter_count)
    initial = tuple(initial_inputs) if initial_inputs is not None else (0,) * required_input_count
    if not all(_valid_input(value) for value in initial):
        raise ValueError("initial_inputs contain unsupported values")
    if len(initial) > len(parameters):
        raise ValueError(f"{entry} received too many initial inputs")

    parameter_names = tuple(parameter.arg for parameter in parameters[: len(initial)])
    pending = _ExplorationQueue(search_strategy, _ExplorationState(initial, ()))
    path_tree = _PathTree()
    counters = _Counters()
    covered_nodes: set[SourceLocation] = set()
    covered_branches: set[BranchCoverage] = set()
    queued_inputs = {_input_key(initial)}
    queued_executions: set[tuple[Any, tuple[int, ...]]] = {(_input_key(initial), ())}
    schedule_state_counts: dict[Any, int] = {_input_key(initial): 1}
    observed_schedules: set[tuple[Any, tuple[int, ...]]] = set()
    runs: list[RunRecord] = []
    unsatisfiable_paths = 0
    counterexamples: list[ContractCounterexample] = []
    seen_counterexamples: set[tuple[str, Any]] = set()
    queued_contract_targets: set[tuple[Any, ...]] = set()
    solver_cache = SolverResultCache()
    stop_reason = "exhausted"
    budget_stop_reason: str | None = None
    queue_was_truncated = False

    def enqueue(state: _ExplorationState) -> bool:
        nonlocal queue_was_truncated
        if len(pending) >= budgets.max_pending_states:
            counters.states_dropped += 1
            queue_was_truncated = True
            return False
        pending.append(state)
        counters.states_enqueued += 1
        counters.maximum_queue_size = max(counters.maximum_queue_size, len(pending))
        return True

    while pending and counters.executions < max_iterations:
        if budgets.total_deadline is not None and monotonic() >= budgets.total_deadline:
            budget_stop_reason = "total_timeout"
            break
        state = pending.pop(covered_branches)
        inputs = state.inputs
        schedule_prefix = state.schedule_prefix
        execution_started = monotonic()
        execution_deadline, timeout_reason = _execution_deadline(execution_started, budgets)
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
            max_symbolic_container_size,
            entry_owner,
            entry_kind,
        )
        counters.executions += 1
        result: Any = None
        contract_conditions: tuple[tuple[Postcondition, Any], ...] = ()
        try:
            preconditions_satisfied = _evaluate_preconditions(executor, contracts.preconditions)
            if preconditions_satisfied:
                result, path_constraints = executor.run()
                contract_conditions = _evaluate_postconditions(executor, postconditions)
                outcome = ExecutionOutcome(OutcomeKind.RETURNED)
            else:
                path_constraints = tuple(executor.path)
                outcome = ExecutionOutcome(OutcomeKind.PRECONDITION_REJECTED)
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
        if (
            outcome.kind is OutcomeKind.TARGET_EXCEPTION
            and contracts.expected_exceptions
            and outcome.exception_type not in contracts.expected_exceptions
        ):
            clause = "raises: " + ", ".join(contracts.expected_exceptions)
            key = (clause, _input_key(inputs))
            if key not in seen_counterexamples:
                seen_counterexamples.add(key)
                counterexamples.append(
                    ContractCounterexample(clause, inputs, None, len(path_constraints))
                )

        coverage = executor._coverage_snapshot()
        discovered = bool(coverage.nodes - covered_nodes or coverage.branches - covered_branches)
        covered_nodes.update(coverage.nodes)
        covered_branches.update(coverage.branches)
        if discovered:
            counters.coverage_discoveries += 1
            counters.iterations_without_discovery = 0
        else:
            counters.iterations_without_discovery += 1

        schedule = tuple(chosen for _, chosen in executor._schedule_choices)
        realization_memo: dict[int, Any] = {}
        post_inputs = tuple(
            _deep_concrete(executor.env[name], realization_memo) for name in parameter_names
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
        path_tree.observe(path_constraints)
        counters.path_tree_nodes = path_tree.node_count
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
                            and schedule_state_counts.get(input_key, 0) < max_schedule_states
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
                contract_target = (
                    tuple(branch.key() for branch in path_constraints),
                    clause.source,
                    condition.symbolic.sexpr(),
                )
                if contract_target in queued_contract_targets:
                    continue
                queued_contract_targets.add(contract_target)
                solved = _solve_path(
                    z3,
                    parameter_names,
                    executor.input_values,
                    tuple(executor.input_constraints),
                    path_constraints,
                    _Branch(condition.symbolic, True),
                    counters,
                    budgets,
                    solver_cache,
                )
                if solved.stop_reason is not None:
                    budget_stop_reason = solved.stop_reason
                    break
                model_inputs = solved.inputs
                if model_inputs is not None and _input_key(model_inputs) not in queued_inputs:
                    queued_inputs.add(_input_key(model_inputs))
                    queued_executions.add((_input_key(model_inputs), ()))
                    schedule_state_counts.setdefault(_input_key(model_inputs), 1)
                    enqueue(_ExplorationState(model_inputs, ()))

        if budget_stop_reason is not None:
            break

        for index, branch in enumerate(path_constraints):
            prefix = path_constraints[:index]
            target_metadata = path_tree.reserve(prefix, branch)
            if target_metadata is None:
                continue
            solved = _solve_path(
                z3,
                parameter_names,
                executor.input_values,
                tuple(executor.input_constraints),
                path_constraints[:index],
                branch,
                counters,
                budgets,
                solver_cache,
            )
            if solved.stop_reason is not None:
                budget_stop_reason = solved.stop_reason
                break
            model_inputs = solved.inputs
            if solved.inconclusive_reason is not None:
                path_tree.exhaust(prefix, branch)
                continue
            if model_inputs is None:
                unsatisfiable_paths += 1
                path_tree.exhaust(prefix, branch)
            elif _input_key(model_inputs) not in queued_inputs:
                queued_inputs.add(_input_key(model_inputs))
                queued_executions.add((_input_key(model_inputs), ()))
                schedule_state_counts.setdefault(_input_key(model_inputs), 1)
                target_branch = BranchCoverage(branch.location, branch.kind, not branch.taken)
                target_depth, target_visits = target_metadata
                enqueued = enqueue(
                    _ExplorationState(
                        model_inputs,
                        (),
                        target_branch,
                        target_depth,
                        target_visits,
                    )
                )
                if not enqueued:
                    path_tree.exhaust(prefix, branch)
            else:
                path_tree.exhaust(prefix, branch)

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
    aggregate_coverage = CoverageSnapshot(frozenset(covered_nodes), frozenset(covered_branches))
    return ExplorationResult(
        entry=entry,
        parameter_names=parameter_names,
        runs=tuple(runs),
        unsatisfiable_paths=unsatisfiable_paths,
        counterexamples=tuple(counterexamples),
        coverage=aggregate_coverage,
        statistics=counters.snapshot(stop_reason, monotonic() - started_at),
    )


def _resolve_entry(
    module: _ModuleValue, entry: str
) -> tuple[FunctionNode, _ClassValue | None, str]:
    if "." not in entry:
        function = module.functions.get(entry)
        if function is None:
            raise ValueError(f"entry function {entry!r} was not found")
        return function, None, "function"
    class_name, method_name = entry.split(".", 1)
    owner = module.classes.get(class_name)
    if owner is None:
        raise ValueError(f"entry class {class_name!r} was not found")
    method = next(
        (
            statement
            for statement in owner.definition.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name == method_name
        ),
        None,
    )
    if method is None:
        raise ValueError(f"entry method {entry!r} was not found")
    decorator_names = {
        decorator.id for decorator in method.decorator_list if isinstance(decorator, ast.Name)
    }
    if "property" in decorator_names:
        raise ValueError(f"entry {entry!r} is a property, not a callable method")
    kind = (
        "staticmethod"
        if "staticmethod" in decorator_names
        else "classmethod" if "classmethod" in decorator_names else "method"
    )
    return method, owner, kind


def _class_invariants(
    module: _ModuleValue, owner: _ClassValue, seen: set[int] | None = None
) -> tuple[Precondition, ...]:
    seen = set() if seen is None else seen
    if id(owner) in seen:
        return ()
    seen.add(id(owner))
    inherited: list[Precondition] = []
    for base in owner.definition.bases:
        if isinstance(base, ast.Name) and base.id in module.classes:
            inherited.extend(_class_invariants(module, module.classes[base.id], seen))
    inherited.extend(parse_class_invariants(owner.definition))
    return tuple(inherited)


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
    solver_rlimit: int | None,
    max_solver_calls: int | None,
    max_pending_states: int,
    max_symbolic_container_size: int,
) -> None:
    positive_options = {
        "max_iterations": max_iterations,
        "max_loop_iterations": max_loop_iterations,
        "max_resume_steps": max_resume_steps,
        "max_task_switches": max_task_switches,
        "max_schedule_states": max_schedule_states,
        "max_pending_states": max_pending_states,
        "max_symbolic_container_size": max_symbolic_container_size,
    }
    for name, value in positive_options.items():
        if value < 1:
            raise ValueError(f"{name} must be at least one")
    if scheduler not in {"fifo", "nondeterministic"}:
        raise ValueError("scheduler must be 'fifo' or 'nondeterministic'")
    if search_strategy not in {"fifo", "breadth_first", "coverage"}:
        raise ValueError("search_strategy must be 'fifo', 'breadth_first', or 'coverage'")
    if max_uninteresting_iterations is not None and max_uninteresting_iterations < 1:
        raise ValueError("max_uninteresting_iterations must be at least one")
    optional_positive = {
        "total_timeout": total_timeout,
        "per_run_timeout": per_run_timeout,
        "solver_timeout": solver_timeout,
        "max_solver_calls": max_solver_calls,
        "solver_rlimit": solver_rlimit,
    }
    for name, optional_value in optional_positive.items():
        if optional_value is not None and optional_value <= 0:
            raise ValueError(f"{name} must be greater than zero")


def _error_outcome(error: ConcolicError | _TargetException) -> ExecutionOutcome:
    if isinstance(error, _TargetException):
        return ExecutionOutcome(OutcomeKind.TARGET_EXCEPTION, error.name, error.message or None)
    if isinstance(error, UnsupportedSyntaxError):
        return ExecutionOutcome(OutcomeKind.UNSUPPORTED, type(error).__name__, str(error) or None)
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


def _execution_deadline(started_at: float, budgets: _Budgets) -> tuple[float | None, str]:
    candidates: list[tuple[float, str]] = []
    if budgets.total_deadline is not None:
        candidates.append((budgets.total_deadline, "total_timeout"))
    if budgets.per_run_timeout is not None:
        candidates.append((started_at + budgets.per_run_timeout, "per_run_timeout"))
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
    snapshots = {
        f"__old_{name}": executor.pre_env[name]
        for clause in clauses
        for name in clause.snapshots
        if name in executor.pre_env
    }
    executor.env = {
        **previous_env,
        **snapshots,
        "__return__": executor._last_result,
    }
    try:
        return tuple(
            (clause, executor._truthy(executor._evaluate(clause.expression))) for clause in clauses
        )
    finally:
        executor.env = previous_env


def _evaluate_preconditions(executor: _Executor, clauses: tuple[Precondition, ...]) -> bool:
    for clause in clauses:
        condition = executor._truthy(executor._evaluate(clause.expression))
        executor._record_branch(
            condition.symbolic,
            condition.concrete,
            clause.expression,
            "precondition",
        )
        if not condition.concrete:
            return False
    return True


def _solve_path(
    z3: Any,
    parameter_names: tuple[str, ...],
    input_kinds: tuple[Any, ...],
    input_constraints: tuple[Any, ...],
    prefix: tuple[_Branch, ...],
    flipped: _Branch,
    counters: _Counters,
    budgets: _Budgets,
    cache: SolverResultCache,
) -> _SolveResult:
    now = monotonic()
    if budgets.total_deadline is not None and now >= budgets.total_deadline:
        return _SolveResult(stop_reason="total_timeout")
    if budgets.max_solver_calls is not None and counters.solver_calls >= budgets.max_solver_calls:
        return _SolveResult(stop_reason="max_solver_calls")
    counters.solver_calls += 1
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
    space = SolverStateSpace(
        z3,
        timeout_seconds=effective_timeout,
        rlimit=budgets.solver_rlimit,
        cache=cache,
    )
    space.add(*input_constraints)
    for branch in prefix:
        space.add(branch.expression if branch.taken else z3.Not(branch.expression))
    space.add(flipped.expression if not flipped.taken else z3.Not(flipped.expression))
    checked = space.check()
    result = checked.result
    counters.solver_seconds += checked.seconds
    counters.solver_cache_hits += int(checked.cache_hit)
    if budgets.total_deadline is not None and monotonic() >= budgets.total_deadline:
        return _SolveResult(stop_reason="total_timeout")
    if result == z3.unknown:
        reason = checked.reason or "unknown"
        diagnostic = _solver_diagnostic(reason, prefix, flipped)
        counters.solver_diagnostics.append(diagnostic)
        if len(counters.solver_diagnostics) > 20:
            del counters.solver_diagnostics[:-20]
        counters.solver_unknowns += 1
        if "timeout" in reason.lower() or timeout_reason is not None:
            counters.solver_timeouts += 1
            if timeout_reason == "total_timeout":
                return _SolveResult(stop_reason="total_timeout")
            return _SolveResult(inconclusive_reason="solver_timeout")
        return _SolveResult(inconclusive_reason=f"solver_unknown:{reason}")
    if result != z3.sat:
        counters.unsatisfiable_queries += 1
        return _SolveResult()
    counters.satisfiable_queries += 1
    model = checked.model
    assert model is not None
    model_memo: dict[int, Any] = {}
    return _SolveResult(
        tuple(
            _model_value(model, z3, name, kind, model_memo)
            for name, kind in zip(parameter_names, input_kinds)
        )
    )


def _model_value(
    model: Any, z3: Any, name: str, kind: Any, memo: dict[int, Any] | None = None
) -> Any:
    if memo is None:
        memo = {}
    if isinstance(kind, (_ListValue, _DictValue, _SetValue)) and id(kind) in memo:
        return memo[id(kind)]
    if isinstance(kind, _ListValue) and kind.input_name is not None:
        length = model.eval(kind.symbolic_length, model_completion=True).as_long()
        capacity = kind.capacity or length
        length = max(0, min(length, capacity))
        templates = kind.element_templates or (0,)
        result: list[Any] = []
        memo[id(kind)] = result
        result.extend(
            _model_value(
                model,
                z3,
                f"{kind.input_name}_{index}",
                templates[min(index, len(templates) - 1)],
                memo,
            )
            for index in range(length)
        )
        return result
    if isinstance(kind, _DictValue) and kind.input_name is not None:
        result: dict[Any, Any] = {}
        memo[id(kind)] = result
        for key, present in kind.symbolic_presence.items():
            if z3.is_true(model.eval(present, model_completion=True)):
                result[key] = _model_value(
                    model,
                    z3,
                    kind.value_names[key],
                    kind.candidate_templates.get(key, 0),
                    memo,
                )
        return result
    if isinstance(kind, _SetValue) and kind.input_name is not None:
        result: set[Any] = set()
        memo[id(kind)] = result
        for key, present in kind.symbolic_presence.items():
            if z3.is_true(model.eval(present, model_completion=True)):
                value_name = kind.value_names[key]
                result.add(
                    key
                    if not value_name
                    else _model_value(
                        model,
                        z3,
                        value_name,
                        kind.candidate_templates[key],
                        memo,
                    )
                )
        return result
    if isinstance(kind, _BoolValue):
        return z3.is_true(model.eval(kind.symbolic, model_completion=True))
    if isinstance(kind, _StringValue):
        return model.eval(kind.symbolic, model_completion=True).as_string()
    if isinstance(kind, _FloatValue):
        value = model.eval(kind.symbolic, model_completion=True)
        if hasattr(value, "approx") and not hasattr(value, "numerator_as_long"):
            value = value.approx(20)
        return value.numerator_as_long() / value.denominator_as_long()
    if isinstance(kind, _IntValue):
        return model.eval(kind.symbolic, model_completion=True).as_long()
    if isinstance(kind, _TupleValue):
        return tuple(
            _model_value(model, z3, f"{name}_{index}", item, memo)
            for index, item in enumerate(kind.values)
        )
    if kind is None:
        return None
    if isinstance(kind, list):
        return [
            _model_value(model, z3, f"{name}_{index}", item, memo)
            for index, item in enumerate(kind)
        ]
    if isinstance(kind, dict):
        return {
            key: _model_value(model, z3, f"{name}_{key}", item, memo) for key, item in kind.items()
        }
    if isinstance(kind, bool):
        return z3.is_true(model.eval(z3.Bool(name), model_completion=True))
    if isinstance(kind, str):
        return model.eval(z3.String(name), model_completion=True).as_string()
    if isinstance(kind, float):
        value = model.eval(z3.Real(name), model_completion=True)
        if hasattr(value, "approx") and not hasattr(value, "numerator_as_long"):
            value = value.approx(20)
        return value.numerator_as_long() / value.denominator_as_long()
    return model.eval(z3.Int(name), model_completion=True).as_long()


def _solver_diagnostic(reason: str, prefix: tuple[_Branch, ...], flipped: _Branch) -> str:
    target = flipped.expression.sexpr()
    if len(target) > 240:
        target = target[:237] + "..."
    return f"{reason}; prefix_length={len(prefix)}; target={target}"
