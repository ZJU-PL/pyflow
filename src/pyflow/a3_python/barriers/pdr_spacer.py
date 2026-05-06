"""
PDR/IC3-style safety checking via Z3 Spacer (CHC engine).

Z3's Spacer engine is a state-of-the-art implementation of PDR for Horn clauses.
We use it as a certifier/bug-finder on *extracted* transition systems where:
- variables are integers (or other first-order sorts),
- Init/Trans/Unsafe are expressed as Z3 formulas.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import z3


@dataclass(frozen=True)
class PDRResult:
    verdict: str  # "SAFE" | "BUG" | "UNKNOWN"
    invariant: Optional[z3.ExprRef] = None
    message: str = ""


def pdr_check_safety(
    *,
    var_names: list[str],
    init: Callable[[dict[str, z3.IntNumRef]], z3.BoolRef],
    trans: Callable[[dict[str, z3.IntNumRef], dict[str, z3.IntNumRef]], z3.BoolRef],
    unsafe: Callable[[dict[str, z3.IntNumRef]], z3.BoolRef],
    timeout_ms: Optional[int] = None,
) -> PDRResult:
    """
    Check reachability of Unsafe using Z3 Fixedpoint with the Spacer engine.

    Returns SAFE when Spacer proves Unsafe unreachable (and attempts to return an invariant).
    Returns BUG when Spacer finds Unsafe reachable (counterexample extraction is best-effort).
    """
    if not var_names:
        raise ValueError("var_names must be non-empty")

    xs = [z3.Int(name) for name in var_names]
    inv = z3.Function("Inv", *([z3.IntSort()] * len(xs) + [z3.BoolSort()]))
    bad = z3.Function("Bad", z3.BoolSort())

    fp = z3.Fixedpoint()
    fp.set(engine="spacer")
    if timeout_ms is not None:
        fp.set("timeout", int(timeout_ms))

    fp.register_relation(inv)
    fp.register_relation(bad)

    x_map = {name: x for name, x in zip(var_names, xs)}
    x_nexts = [z3.Int(f"{name}_next") for name in var_names]
    x_next_map = {name: x for name, x in zip(var_names, x_nexts)}

    fp.declare_var(*xs, *x_nexts)

    init_f = init(x_map)
    trans_f = trans(x_map, x_next_map)
    unsafe_f = unsafe(x_map)

    # Inv(x) :- Init(x).
    fp.rule(inv(*xs), init_f)

    # Inv(x') :- Inv(x) ∧ Trans(x,x').
    fp.rule(
        inv(*[x_next_map[name] for name in var_names]),
        z3.And(inv(*xs), trans_f),
    )

    # Bad :- Inv(x) ∧ Unsafe(x).
    fp.rule(bad(), z3.And(inv(*xs), unsafe_f))

    try:
        res = fp.query(bad())
    except z3.Z3Exception as e:
        return PDRResult(verdict="UNKNOWN", message=f"Spacer error: {e}")

    if res == z3.unsat:
        inv_ans = None
        try:
            inv_ans = fp.get_answer()
        except z3.Z3Exception:
            inv_ans = None
        return PDRResult(verdict="SAFE", invariant=inv_ans, message="Unsafe unreachable (Spacer)")

    if res == z3.sat:
        return PDRResult(verdict="BUG", message="Unsafe reachable (Spacer)")

    return PDRResult(verdict="UNKNOWN", message="Spacer returned unknown")
