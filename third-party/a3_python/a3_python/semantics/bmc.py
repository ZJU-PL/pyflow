"""
Bounded Model Checking (BMC) over the SymbolicVM.

This is a *bug-finding* engine: it searches for a reachable unsafe state within
bounded steps and bounded state expansions, using the existing symbolic bytecode
semantics (not an extracted linear model).

Why this exists:
- The baseline analyzer does deep-ish path exploration and can hit path limits.
- A shallow, breadth-first BMC pass often finds real bugs quickly and cheaply.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Optional

from ..unsafe.registry import check_all_unsafe_regions, SECURITY_BUG_TYPES
from .symbolic_vm import SymbolicVM, SymbolicPath


@dataclass(frozen=True)
class BMCSymbolicResult:
    bug: dict
    path: SymbolicPath
    expanded: int


def bmc_find_bug(
    code,
    *,
    max_steps: int,
    max_expansions: int,
    solver_timeout_ms: Optional[int] = 200,
    include_security: bool = False,
    verbose: bool = False,
) -> Optional[BMCSymbolicResult]:
    """
    Search for a BUG within bounded steps/expansions.

    Returns the first found bug (breadth-first), or None if not found.
    """
    vm = SymbolicVM(verbose=verbose, solver_timeout_ms=solver_timeout_ms)
    initial = vm.load_code(code)

    q: deque[SymbolicPath] = deque([initial])
    expanded = 0

    while q and expanded < max_expansions:
        path = q.popleft()
        expanded += 1

        bugs = check_all_unsafe_regions(path.state, path.trace)
        if bugs:
            if not include_security:
                bugs = [b for b in bugs if b.get("bug_type") not in SECURITY_BUG_TYPES]
            if bugs:
                # Return the first bug on this path.
                return BMCSymbolicResult(bug=bugs[0], path=path, expanded=expanded)

        if path.state.halted or not path.state.frame_stack:
            continue
        if len(path.trace) >= max_steps:
            continue

        try:
            succs = vm.step(path)
        except Exception:
            continue

        # vm.step returns [mutated_path, forks...]; enqueue all successors.
        for s in succs:
            if s.state.halted and not s.state.frame_stack:
                # Completed module/function; still worth checking unsafe next iteration.
                q.append(s)
            else:
                q.append(s)

    return None

