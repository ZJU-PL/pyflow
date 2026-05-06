"""
ICE (Implication CounterExample) learning for predicate-conjunction invariants.

This is a SOTA-ish invariant inference building block used in "kitchen sink"
portfolios: given examples and a fixed predicate basis, infer a conjunction that:
- includes all positive examples,
- excludes all negative examples,
- respects implication examples.

The hypothesis class is:
    H(x) = ∧_{p in P, include[p]=True} p(x)

Learning reduces to SAT/SMT over boolean include-variables because all examples
are concrete and each predicate evaluates to True/False on an example.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import z3


@dataclass(frozen=True)
class ICEResult:
    success: bool
    invariant: Optional[z3.BoolRef] = None
    chosen_predicates: tuple[str, ...] = ()
    message: str = ""


def ice_learn_conjunction(
    *,
    variables: dict[str, z3.IntNumRef],
    candidate_predicates: dict[str, z3.BoolRef],
    positive: list[dict[str, int]],
    negative: list[dict[str, int]],
    implications: list[tuple[dict[str, int], dict[str, int]]],
    maximize_predicates: bool = True,
    timeout_ms: Optional[int] = None,
) -> ICEResult:
    """
    Learn a conjunction over candidate_predicates that satisfies ICE constraints.
    """
    if not candidate_predicates:
        return ICEResult(False, message="No candidate predicates")

    include = {name: z3.Bool(f"inc_{name}") for name in candidate_predicates.keys()}

    solver: z3.Solver | z3.Optimize
    solver = z3.Optimize() if maximize_predicates else z3.Solver()
    if timeout_ms is not None:
        solver.set("timeout", int(timeout_ms))

    def eval_pred(pred: z3.BoolRef, ex: dict[str, int]) -> bool:
        subs = [(variables[name], z3.IntVal(int(value))) for name, value in ex.items() if name in variables]
        v = z3.simplify(z3.substitute(pred, subs))
        return z3.is_true(v)

    # Positive examples: chosen preds must hold.
    for ex in positive:
        for name, pred in candidate_predicates.items():
            if not eval_pred(pred, ex):
                solver.add(z3.Not(include[name]))

    # Hypothesis holds on example e iff all chosen preds are True on e.
    def holds_on(ex: dict[str, int]) -> z3.BoolRef:
        conjuncts = []
        for name, pred in candidate_predicates.items():
            if eval_pred(pred, ex):
                # include -> True is redundant
                continue
            conjuncts.append(z3.Not(include[name]))
        return z3.And(*conjuncts) if conjuncts else z3.BoolVal(True)

    # Negative examples: require hypothesis to be false.
    for ex in negative:
        # ¬H(ex)  ⇔  ∃p. include[p] ∧ ¬p(ex)
        falsifying = []
        for name, pred in candidate_predicates.items():
            if not eval_pred(pred, ex):
                falsifying.append(include[name])
        if falsifying:
            solver.add(z3.Or(*falsifying))
        else:
            # All predicates true at this negative example => impossible for conjunction class.
            return ICEResult(False, message="Negative example satisfies all candidates; hypothesis class too weak")

    # Implication examples: H(e) -> H(e')
    for ex_pre, ex_post in implications:
        solver.add(z3.Implies(holds_on(ex_pre), holds_on(ex_post)))

    if maximize_predicates:
        solver.maximize(z3.Sum([z3.If(b, 1, 0) for b in include.values()]))

    r = solver.check()
    if r != z3.sat:
        return ICEResult(False, message=f"ICE solver result: {r}")

    model = solver.model()
    chosen = tuple(sorted([name for name, b in include.items() if z3.is_true(model.eval(b, model_completion=True))]))
    inv = z3.And(*[candidate_predicates[name] for name in chosen]) if chosen else z3.BoolVal(True)
    return ICEResult(True, invariant=inv, chosen_predicates=chosen, message="ICE learned conjunction")

