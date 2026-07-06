"""
Lockstep concolic execution + symbolic replay (for testing and debugging).

This module provides a controlled way to:
- execute a program concretely on CPython (selective concolic trace),
- build an ExecutionOracle from that trace, and
- replay the same execution inside the full Z3-based SymbolicVM.

This is intended for:
- semantics regression testing ("debug the debugger"),
- producing faithful witness traces when unknown libraries are involved,
- diagnosing divergence between concrete and symbolic execution.

It MUST NOT be used to justify SAFE proofs (it is path-specific).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import types

from .concolic import ConcreteInput
from .selective_concolic import SelectiveConcolicExecutor, SelectiveConcolicTrace
from .hybrid import ConcolicReplayOracle
from ..semantics.symbolic_vm import SymbolicVM
from ..unsafe.registry import check_unsafe_regions


@dataclass
class LockstepResult:
    status: str  # "ok" | "mismatch" | "error"
    message: str

    concrete_exception_type: Optional[str] = None
    concrete_exception_repr: Optional[str] = None
    symbolic_exception: Optional[str] = None

    replay_paths: int = 0
    replay_trace_len: int = 0
    replay_bug_type: Optional[str] = None

    observed_call_events: int = 0


def run_lockstep(
    *,
    code_obj: types.CodeType,
    concrete_input: ConcreteInput,
    owned_filenames: set[str],
    max_steps: int = 500,
    max_instruction_events: int = 300_000,
) -> LockstepResult:
    """
    Execute concretely + replay symbolically with an oracle, and compare outcomes.
    """
    try:
        trace: SelectiveConcolicTrace = SelectiveConcolicExecutor(
            max_opcode_events=max_instruction_events
        ).execute(
            code_obj=code_obj,
            concrete_input=concrete_input,
            owned_filenames=owned_filenames,
        )

        oracle = ConcolicReplayOracle.from_trace(trace)
        vm = SymbolicVM(oracle=oracle)
        paths = vm.explore_bounded(code_obj, max_steps=max_steps)

        # Prefer a non-InfeasiblePath replay. If multiple exist, pick one that matches
        # the concrete exception type (when available).
        preferred = None
        if trace.exception_type is not None:
            for p in paths:
                if p.state.exception == trace.exception_type:
                    preferred = p
                    break

        if preferred is None:
            for p in paths:
                if p.state.exception != "InfeasiblePath":
                    preferred = p
                    break

        if preferred is None and paths:
            preferred = paths[0]

        symbolic_exc = preferred.state.exception if preferred else None
        bug = None
        if preferred is not None:
            unsafe = check_unsafe_regions(preferred.state, preferred.trace)
            if unsafe is not None:
                bug = unsafe.get("bug_type")

        if preferred is None:
            return LockstepResult(
                status="mismatch",
                message="Symbolic replay produced no paths",
                concrete_exception_type=trace.exception_type,
                concrete_exception_repr=trace.exception_repr,
                symbolic_exception=None,
                replay_paths=len(paths),
                replay_trace_len=0,
                replay_bug_type=None,
                observed_call_events=len(trace.call_events),
            )

        if trace.exception_type != symbolic_exc:
            return LockstepResult(
                status="mismatch",
                message="Concrete exception does not match symbolic replay exception",
                concrete_exception_type=trace.exception_type,
                concrete_exception_repr=trace.exception_repr,
                symbolic_exception=symbolic_exc,
                replay_paths=len(paths),
                replay_trace_len=len(preferred.trace),
                replay_bug_type=bug,
                observed_call_events=len(trace.call_events),
            )

        # A replay may legitimately stop early if max_steps is too small; treat that as mismatch.
        if not (preferred.state.halted or not preferred.state.frame_stack or preferred.state.exception is not None):
            return LockstepResult(
                status="mismatch",
                message="Symbolic replay did not terminate within max_steps",
                concrete_exception_type=trace.exception_type,
                concrete_exception_repr=trace.exception_repr,
                symbolic_exception=symbolic_exc,
                replay_paths=len(paths),
                replay_trace_len=len(preferred.trace),
                replay_bug_type=bug,
                observed_call_events=len(trace.call_events),
            )

        return LockstepResult(
            status="ok",
            message="Concrete execution and symbolic replay agree",
            concrete_exception_type=trace.exception_type,
            concrete_exception_repr=trace.exception_repr,
            symbolic_exception=symbolic_exc,
            replay_paths=len(paths),
            replay_trace_len=len(preferred.trace),
            replay_bug_type=bug,
            observed_call_events=len(trace.call_events),
        )
    except Exception as e:
        return LockstepResult(status="error", message=f"{type(e).__name__}: {e}")

