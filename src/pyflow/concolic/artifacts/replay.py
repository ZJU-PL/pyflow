"""Replay concolic executions against CPython for semantic validation."""

from __future__ import annotations

import asyncio
import copy
import importlib
import importlib.util
import inspect
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Iterable

from ..core.runtime import (
    IdentityToken,
    ExecutionOutcome,
    OperationObservation,
    OutcomeKind,
    RunRecord,
)
from .behavior import BehaviorObservation, compare_observations


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
    identity_is_opaque = _contains_identity_token(run.result)
    expected = BehaviorObservation.from_run(run)
    if identity_is_opaque:
        expected = BehaviorObservation(run.outcome, actual_result, run.post_inputs)
    differences = (
        *compare_observations(
            expected, BehaviorObservation(actual_outcome, actual_result, actual_post_inputs)
        ),
        *_compare_operation_observations(run.operations),
    )
    if differences:
        status = ReplayStatus.MISMATCHED
    elif identity_is_opaque:
        status = ReplayStatus.NOT_COMPARABLE
        differences = ("result contains process-local object identity",)
    else:
        status = ReplayStatus.MATCHED
    return ReplayResult(
        run=run,
        status=status,
        actual_outcome=actual_outcome,
        actual_result=actual_result,
        actual_post_inputs=actual_post_inputs,
        differences=differences,
    )


def _compare_operation_observations(
    operations: tuple[OperationObservation, ...],
) -> tuple[str, ...]:
    differences: list[str] = []
    for index, operation in enumerate(operations, 1):
        label = f"operation {index} {operation.module}.{operation.name}"
        try:
            function = getattr(importlib.import_module(operation.module), operation.name)
        except (AttributeError, ImportError) as error:
            differences.append(f"{label}: resolution failed: {type(error).__name__}: {error}")
            continue
        arguments = copy.deepcopy(operation.arguments)
        keywords = copy.deepcopy(dict(operation.keywords))
        actual_result: Any = None
        try:
            actual_result = function(*arguments, **keywords)
            actual_outcome = ExecutionOutcome(OutcomeKind.RETURNED)
        except Exception as error:
            actual_outcome = ExecutionOutcome(
                OutcomeKind.TARGET_EXCEPTION,
                type(error).__name__,
                str(error) or None,
            )
        expected_post = (
            operation.post_arguments,
            dict(operation.post_keywords or ()),
        )
        actual_post = (tuple(arguments), keywords)
        operation_differences = compare_observations(
            BehaviorObservation(operation.outcome, operation.result, expected_post),
            BehaviorObservation(actual_outcome, actual_result, actual_post),
        )
        differences.extend(f"{label}: {difference}" for difference in operation_differences)
    return tuple(differences)


def _contains_identity_token(value: Any) -> bool:
    if isinstance(value, IdentityToken):
        return True
    if isinstance(value, dict):
        return any(
            _contains_identity_token(key) or _contains_identity_token(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_identity_token(item) for item in value)
    return False


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
        function = _resolve_runtime_entry(module, entry)
    finally:
        sys.modules.pop(module_name, None)
        if sys.path and sys.path[0] == root:
            sys.path.pop(0)
    return function


def _resolve_runtime_entry(module: Any, entry: str):
    if "." not in entry:
        return getattr(module, entry)
    class_name, method_name = entry.split(".", 1)
    owner = getattr(module, class_name)
    descriptor = inspect.getattr_static(owner, method_name)
    if isinstance(descriptor, staticmethod):
        return getattr(owner, method_name)
    if isinstance(descriptor, classmethod):
        return getattr(owner, method_name)
    if isinstance(descriptor, property):
        raise TypeError(f"entry {entry!r} is a property")
    return getattr(owner(), method_name)


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
