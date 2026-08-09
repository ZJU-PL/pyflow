"""Coverage-preserving selection of concrete concolic executions."""

from __future__ import annotations

from typing import Any, Iterable

from .runtime import ContractCounterexample, OutcomeKind, RunRecord
from .support import _input_key


def minimize_runs(
    runs: Iterable[RunRecord],
    counterexamples: Iterable[ContractCounterexample] = (),
) -> tuple[RunRecord, ...]:
    """Return a deterministic small corpus preserving observed coverage.

    Distinct non-returning outcomes and contract-counterexample inputs are
    mandatory. Remaining executions are selected greedily by new branch edges,
    then new AST nodes, with smaller inputs and schedules used as tie-breakers.
    """
    candidates = tuple(runs)
    if not candidates:
        return ()

    selected: set[int] = set()
    outcome_signatures: set[tuple[Any, ...]] = set()
    counterexample_inputs = {
        _input_key(counterexample.inputs) for counterexample in counterexamples
    }
    for index, run in enumerate(candidates):
        if _input_key(run.inputs) in counterexample_inputs:
            selected.add(index)
        if run.outcome.kind is OutcomeKind.RETURNED:
            continue
        signature = (
            run.outcome.kind,
            run.outcome.exception_type,
            run.outcome.message,
        )
        if signature not in outcome_signatures:
            outcome_signatures.add(signature)
            selected.add(index)

    all_branches = set().union(*(run.coverage.branches for run in candidates))
    all_nodes = set().union(*(run.coverage.nodes for run in candidates))
    covered_branches = set().union(
        *(candidates[index].coverage.branches for index in selected)
    )
    covered_nodes = set().union(
        *(candidates[index].coverage.nodes for index in selected)
    )

    while covered_branches != all_branches or covered_nodes != all_nodes:
        remaining = [index for index in range(len(candidates)) if index not in selected]
        if not remaining:
            break
        best = max(
            remaining,
            key=lambda index: _selection_score(
                candidates[index], covered_branches, covered_nodes, index
            ),
        )
        run = candidates[best]
        if not (
            run.coverage.branches - covered_branches
            or run.coverage.nodes - covered_nodes
        ):
            break
        selected.add(best)
        covered_branches.update(run.coverage.branches)
        covered_nodes.update(run.coverage.nodes)

    if not selected:
        selected.add(0)
    return tuple(candidates[index] for index in sorted(selected))


def _selection_score(
    run: RunRecord,
    covered_branches: set[Any],
    covered_nodes: set[Any],
    index: int,
) -> tuple[int, int, int, int, int, int]:
    return (
        len(run.coverage.branches - covered_branches),
        len(run.coverage.nodes - covered_nodes),
        -_value_size(run.inputs),
        -len(run.schedule),
        -run.path_length,
        -index,
    )


def _value_size(value: Any) -> int:
    if isinstance(value, (list, tuple, set, frozenset)):
        return 1 + sum(_value_size(item) for item in value)
    if isinstance(value, dict):
        return 1 + sum(
            _value_size(key) + _value_size(item) for key, item in value.items()
        )
    if isinstance(value, (str, bytes)):
        return 1 + len(value)
    return 1
