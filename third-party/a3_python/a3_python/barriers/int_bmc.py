"""
Bounded Model Checking (BMC) for small integer transition systems.

This is a reusable engine for kitchen-sink portfolios: cheap bug finding by
bounded unrolling before heavier invariant/proof attempts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import z3


@dataclass(frozen=True)
class BMCCounterexample:
    depth: int
    trace: list[dict[str, int]]


def bmc_find_counterexample(
    *,
    var_names: list[str],
    init: Callable[[dict[str, z3.IntNumRef]], z3.BoolRef],
    trans: Callable[[dict[str, z3.IntNumRef], dict[str, z3.IntNumRef]], z3.BoolRef],
    unsafe: Callable[[dict[str, z3.IntNumRef]], z3.BoolRef],
    max_depth: int,
    timeout_ms: Optional[int] = None,
) -> Optional[BMCCounterexample]:
    """
    Return a concrete counterexample trace if Unsafe is reachable within max_depth steps.

    This uses standard unrolling:
      Init(x0) ∧ Trans(x0,x1) ∧ ... ∧ Trans(x_{k-1},x_k) ∧ Unsafe(x_k)
    """
    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")

    solver = z3.Solver()
    if timeout_ms is not None:
        solver.set("timeout", int(timeout_ms))

    def mk_vars(step: int) -> dict[str, z3.IntNumRef]:
        return {name: z3.Int(f"{name}_{step}") for name in var_names}

    # x0
    x0 = mk_vars(0)
    solver.add(init(x0))

    # Try all depths up to max_depth (inclusive)
    for k in range(max_depth + 1):
        xk = mk_vars(k)
        solver.push()
        solver.add(unsafe(xk))

        r = solver.check()
        if r == z3.sat:
            model = solver.model()
            trace: list[dict[str, int]] = []
            for step in range(k + 1):
                xs = mk_vars(step)
                trace.append({name: _model_int(model, xs[name]) for name in var_names})
            solver.pop()
            return BMCCounterexample(depth=k, trace=trace)

        solver.pop()

        if k == max_depth:
            break

        # Extend with next transition x_k -> x_{k+1}
        x_next = mk_vars(k + 1)
        solver.add(trans(xk, x_next))

    return None


def _model_int(model: z3.ModelRef, var: z3.IntNumRef) -> int:
    val = model.eval(var, model_completion=True)
    if isinstance(val, z3.IntNumRef):
        return int(val.as_long())
    if z3.is_int_value(val):
        return int(val.as_long())
    # Best-effort fallback.
    try:
        return int(str(val))
    except Exception:
        return 0

