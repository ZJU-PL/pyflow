"""Replay concolic executions against CPython for semantic validation."""

from __future__ import annotations

import asyncio
import copy
import importlib.util
import inspect
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Iterable

from ..core.runtime import ExecutionOutcome, OutcomeKind, RunRecord


class ReplayStatus(str, Enum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    NOT_COMPARABLE = "not_comparable"
    REPLAY_ERROR = "replay_error"


@dataclass(frozen=True)
class ReplayResult:
    run: RunRecord
    status: ReplayStatus
    actual_outcome: ExecutionOutcome | None
    actual_result: Any = None
    actual_post_inputs: tuple[Any, ...] | None = None
    differences: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "inputs": list(self.run.inputs),
            "status": self.status.value,
            "actual_outcome": (self.actual_outcome.to_dict() if self.actual_outcome else None),
            "actual_result": self.actual_result,
            "actual_post_inputs": (
                list(self.actual_post_inputs) if self.actual_post_inputs is not None else None
            ),
            "differences": list(self.differences),
        }


def replay_runs(
    path: str | Path,
    entry: str,
    runs: Iterable[RunRecord],
) -> tuple[ReplayResult, ...]:
    """Replay runs in fresh CPython modules and compare observable behavior."""
    source_path = Path(path).resolve()
    return tuple(_replay_run(source_path, entry, run, index) for index, run in enumerate(runs))


def _replay_run(path: Path, entry: str, run: RunRecord, index: int) -> ReplayResult:
    if run.outcome.kind not in {
        OutcomeKind.RETURNED,
        OutcomeKind.TARGET_EXCEPTION,
    }:
        return ReplayResult(
            run,
            ReplayStatus.NOT_COMPARABLE,
            None,
            differences=(f"unsupported expected outcome: {run.outcome.kind.value}",),
        )

    arguments = copy.deepcopy(run.inputs)
    try:
        function = _load_entry(path, entry, index)
    except Exception as error:
        return ReplayResult(
            run,
            ReplayStatus.REPLAY_ERROR,
            None,
            differences=(f"module replay failed: {type(error).__name__}: {error}",),
        )

    actual_result: Any = None
    try:
        actual_result = function(*arguments)
        if inspect.isawaitable(actual_result):
            actual_result = asyncio.run(_await_value(actual_result))
        actual_outcome = ExecutionOutcome(OutcomeKind.RETURNED)
    except Exception as error:
        actual_outcome = ExecutionOutcome(
            OutcomeKind.TARGET_EXCEPTION,
            type(error).__name__,
            str(error) or None,
        )
    actual_post_inputs = copy.deepcopy(arguments)
    differences = _compare_replay(run, actual_outcome, actual_result, actual_post_inputs)
    return ReplayResult(
        run=run,
        status=(ReplayStatus.MATCHED if not differences else ReplayStatus.MISMATCHED),
        actual_outcome=actual_outcome,
        actual_result=actual_result,
        actual_post_inputs=actual_post_inputs,
        differences=tuple(differences),
    )


async def _await_value(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _load_entry(path: Path, entry: str, index: int):
    module_name, import_root = _module_identity(path, index)
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    root = str(import_root)
    sys.path.insert(0, root)
    sys.modules[module_name] = module
    try:
        specification.loader.exec_module(module)
        function = getattr(module, entry)
    finally:
        sys.modules.pop(module_name, None)
        if sys.path and sys.path[0] == root:
            sys.path.pop(0)
    return function


def _module_identity(path: Path, index: int) -> tuple[str, Path]:
    """Return an import identity that preserves package-relative imports."""
    package_parts: list[str] = []
    parent = path.parent
    while (parent / "__init__.py").is_file():
        package_parts.append(parent.name)
        parent = parent.parent
    package_parts.reverse()
    if package_parts:
        if path.name != "__init__.py":
            package_parts.append(path.stem)
        return ".".join(package_parts), parent
    return f"_pyflow_concolic_replay_{index}", path.parent


def _compare_replay(
    run: RunRecord,
    actual_outcome: ExecutionOutcome,
    actual_result: Any,
    actual_post_inputs: tuple[Any, ...],
) -> list[str]:
    differences: list[str] = []
    expected = run.outcome
    if actual_outcome.kind is not expected.kind:
        differences.append(
            f"outcome: expected {expected.kind.value}, " f"got {actual_outcome.kind.value}"
        )
    elif expected.kind is OutcomeKind.RETURNED and actual_result != run.result:
        differences.append(f"result: expected {run.result!r}, got {actual_result!r}")
    elif expected.kind is OutcomeKind.TARGET_EXCEPTION:
        if actual_outcome.exception_type != expected.exception_type:
            differences.append(
                f"exception type: expected {expected.exception_type!r}, "
                f"got {actual_outcome.exception_type!r}"
            )
        if actual_outcome.message != expected.message:
            differences.append(
                f"exception message: expected {expected.message!r}, "
                f"got {actual_outcome.message!r}"
            )
    if run.post_inputs is not None and actual_post_inputs != run.post_inputs:
        differences.append(
            f"post inputs: expected {run.post_inputs!r}, " f"got {actual_post_inputs!r}"
        )
    return differences
