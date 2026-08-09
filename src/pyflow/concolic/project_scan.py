"""Project-level concolic support measurement and replay validation."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from time import monotonic
from typing import Any, Mapping

from .catalog import FunctionTarget, discover_targets
from .inputgen import InputSynthesizer


class ScanStatus(str, Enum):
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    INELIGIBLE = "ineligible"
    INPUT_GENERATION_FAILED = "input_generation_failed"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    REPLAY_MISMATCH = "replay_mismatch"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIMEOUT = "timeout"
    SIDE_EFFECT_HAZARD = "side_effect_hazard"
    WORKER_ERROR = "worker_error"


@dataclass(frozen=True)
class ScanAttempt:
    complexity: int
    inputs: tuple[Any, ...] | None
    status: ScanStatus
    seconds: float
    reason: str | None = None
    result: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "complexity": self.complexity,
            "inputs": list(self.inputs) if self.inputs is not None else None,
            "status": self.status.value,
            "seconds": self.seconds,
            "reason": self.reason,
            "result": dict(self.result) if self.result is not None else None,
        }


@dataclass(frozen=True)
class FunctionScanResult:
    target: FunctionTarget
    status: ScanStatus
    attempts: tuple[ScanAttempt, ...]
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "status": self.status.value,
            "reasons": list(self.reasons),
            "attempts": [attempt.to_dict() for attempt in self.attempts],
        }


@dataclass(frozen=True)
class ProjectScanResult:
    root: Path
    functions: tuple[FunctionScanResult, ...]
    seconds: float

    def to_dict(self) -> dict[str, Any]:
        statuses = Counter(result.status.value for result in self.functions)
        reasons = Counter(reason for result in self.functions for reason in result.reasons)
        attempts = sum(len(result.attempts) for result in self.functions)
        return {
            "root": str(self.root),
            "summary": {
                "discovered": len(self.functions),
                "eligible": sum(result.target.eligible for result in self.functions),
                "attempts": attempts,
                "statuses": dict(sorted(statuses.items())),
                "reasons": dict(sorted(reasons.items())),
                "seconds": self.seconds,
            },
            "functions": [result.to_dict() for result in self.functions],
        }


def scan_project(
    root: str | Path,
    *,
    max_functions: int | None = None,
    input_complexity: int = 2,
    function_timeout: float = 10.0,
    allow_side_effects: bool = False,
    include_private: bool = False,
    exploration_options: Mapping[str, Any] | None = None,
    synthesizer: InputSynthesizer | None = None,
) -> ProjectScanResult:
    """Measure project functions in isolated workers using shared targets."""
    if max_functions is not None and max_functions <= 0:
        raise ValueError("max_functions must be positive")
    if input_complexity < 0:
        raise ValueError("input_complexity must be non-negative")
    if function_timeout <= 0:
        raise ValueError("function_timeout must be positive")
    started = monotonic()
    project_root = Path(root).resolve()
    targets = discover_targets(project_root, include_private=include_private)
    if max_functions is not None:
        targets = targets[:max_functions]
    generator = synthesizer or InputSynthesizer()
    functions = tuple(
        _scan_target(
            target,
            generator,
            input_complexity,
            function_timeout,
            allow_side_effects,
            dict(exploration_options or {}),
        )
        for target in targets
    )
    return ProjectScanResult(project_root, functions, monotonic() - started)


def _scan_target(
    target: FunctionTarget,
    synthesizer: InputSynthesizer,
    input_complexity: int,
    function_timeout: float,
    allow_side_effects: bool,
    options: dict[str, Any],
) -> FunctionScanResult:
    if not target.eligible:
        return FunctionScanResult(target, ScanStatus.INELIGIBLE, (), target.eligibility_reasons)
    if target.hazards and not allow_side_effects:
        return FunctionScanResult(target, ScanStatus.SIDE_EFFECT_HAZARD, (), target.hazards)
    attempts: list[ScanAttempt] = []
    for complexity in range(input_complexity + 1):
        generated = synthesizer.synthesize(target, complexity)
        if generated.inputs is None:
            attempts.append(
                ScanAttempt(
                    complexity,
                    None,
                    ScanStatus.INPUT_GENERATION_FAILED,
                    0.0,
                    "; ".join(generated.reasons),
                )
            )
            continue
        attempts.append(
            _run_worker(target, complexity, generated.inputs, function_timeout, options)
        )
    status = _overall_status(attempts)
    reasons = tuple(sorted({attempt.reason for attempt in attempts if attempt.reason}))
    return FunctionScanResult(target, status, tuple(attempts), reasons)


def _run_worker(
    target: FunctionTarget,
    complexity: int,
    inputs: tuple[Any, ...],
    timeout: float,
    options: dict[str, Any],
) -> ScanAttempt:
    request = {
        "path": str(target.path),
        "entry": target.entry,
        "inputs": list(inputs),
        "options": options,
    }
    started = monotonic()
    try:
        process = subprocess.run(
            [sys.executable, "-m", "pyflow.concolic.worker"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ScanAttempt(
            complexity,
            inputs,
            ScanStatus.TIMEOUT,
            monotonic() - started,
            f"worker exceeded {timeout:g}s",
        )
    seconds = monotonic() - started
    try:
        response = json.loads(process.stdout)
    except json.JSONDecodeError:
        message = process.stderr.strip() or "worker produced invalid JSON"
        return ScanAttempt(complexity, inputs, ScanStatus.WORKER_ERROR, seconds, message)
    if not response.get("ok"):
        error = response.get("error", {})
        reason = f"{error.get('type', 'Error')}: {error.get('message', '')}".rstrip()
        return ScanAttempt(complexity, inputs, ScanStatus.WORKER_ERROR, seconds, reason)
    result = response["result"]
    return ScanAttempt(
        complexity,
        inputs,
        _classify_result(result),
        seconds,
        _result_reason(result),
        result,
    )


def _classify_result(result: Mapping[str, Any]) -> ScanStatus:
    replays = result.get("replays", [])
    if any(replay.get("status") in {"mismatched", "replay_error"} for replay in replays):
        return ScanStatus.REPLAY_MISMATCH
    exploration = result["exploration"]
    outcomes = exploration.get("statistics", {}).get("outcomes", {})
    if outcomes.get("unsupported", 0) or outcomes.get("engine_error", 0):
        return ScanStatus.UNSUPPORTED_OPERATION
    stop = exploration.get("statistics", {}).get("search", {}).get("stop_reason")
    if stop in {
        "total_timeout",
        "per_run_timeout",
        "solver_timeout",
        "max_solver_calls",
        "max_pending_states",
        "max_iterations",
    }:
        return ScanStatus.BUDGET_EXHAUSTED
    return ScanStatus.SUPPORTED


def _result_reason(result: Mapping[str, Any]) -> str | None:
    exploration = result["exploration"]
    for run in exploration.get("runs", []):
        outcome = run.get("outcome", {})
        if outcome.get("kind") in {"unsupported", "engine_error", "resource_limit"}:
            reason = outcome.get("message") or outcome.get("exception_type")
            return str(reason) if reason is not None else None
    for replay in result.get("replays", []):
        if replay.get("differences"):
            return "; ".join(replay["differences"])
    return None


def _overall_status(attempts: list[ScanAttempt]) -> ScanStatus:
    statuses = {attempt.status for attempt in attempts}
    if statuses == {ScanStatus.SUPPORTED}:
        return ScanStatus.SUPPORTED
    if ScanStatus.SUPPORTED in statuses:
        return ScanStatus.PARTIALLY_SUPPORTED
    return attempts[0].status if len(statuses) == 1 else ScanStatus.PARTIALLY_SUPPORTED
