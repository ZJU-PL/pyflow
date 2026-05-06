"""
SOTA paper #2 integration: worst-case + stochastic safety workflows (Prajna et al., TAC 2007).

We implement the *stochastic/observational* side as a portfolio step for BUG finding
and false-positive reduction, orthogonal to barrier synthesis:

- Run the program concretely (selective concolic tracing) to observe *actual*
  library/unknown-call behaviors along a real execution.
- Replay that execution in the symbolic VM using a ConcolicReplayOracle that
  supplies call observations and branch decisions.

This reduces nondeterminism from havoc contracts (worst-case) without compromising
soundness of SAFE proofs (we never claim SAFE from this pass). It often:
  - increases BUG coverage (deep bugs under realistic library behavior),
  - decreases false positives (spurious bugs requiring impossible havoc returns).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import types

from .concolic import ConcreteInput
from .hybrid import ConcolicReplayOracle
from .selective_concolic import SelectiveConcolicExecutor
from ..semantics.symbolic_vm import SymbolicVM, SymbolicPath
from ..unsafe.registry import check_unsafe_regions


@dataclass(frozen=True)
class StochasticReplayBug:
    bug: dict
    path: SymbolicPath
    trace: "object"  # SelectiveConcolicTrace (avoid heavy import typing)


def stochastic_replay_find_bug(
    code_obj: types.CodeType,
    *,
    concrete_input: Optional[ConcreteInput] = None,
    owned_filenames: Optional[set[str]] = None,
    max_opcode_events: int = 200_000,
    max_steps: int = 500,
    verbose: bool = False,
) -> Optional[StochasticReplayBug]:
    """
    Concrete trace + replay-guided symbolic exploration to find a real BUG.

    Returns a StochasticReplayBug only when the symbolic replay reaches an unsafe
    region (i.e., produces a BUG artifact). This is intended as a kitchen-sink
    portfolio step and MUST NOT be used for SAFE proofs.
    """
    concrete_input = concrete_input or ConcreteInput.empty()
    owned_filenames = owned_filenames or {code_obj.co_filename}

    executor = SelectiveConcolicExecutor(max_opcode_events=max_opcode_events)
    trace = executor.execute(code_obj=code_obj, concrete_input=concrete_input, owned_filenames=owned_filenames)

    oracle = ConcolicReplayOracle.from_trace(trace)
    vm = SymbolicVM(verbose=verbose, oracle=oracle)

    paths = vm.explore_bounded(code_obj, max_steps=max_steps)
    for p in paths:
        unsafe = check_unsafe_regions(p.state, p.trace)
        if unsafe is not None:
            unsafe = dict(unsafe)
            unsafe["stochastic_replay"] = {
                "exception_type": trace.exception_type,
                "exception_repr": trace.exception_repr,
                "stdout": trace.stdout[:2000],
                "stderr": trace.stderr[:2000],
                "observed_calls_count": len(trace.call_events),
            }
            return StochasticReplayBug(bug=unsafe, path=p, trace=trace)

    # No bug found along this replayed execution.
    return None
