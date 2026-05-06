"""
HSCC'04 barrier certificates integration (Prajna, Jadbabaie, Pappas).

Paper (SOTA #1 in kitchensinkplus.md):
  S. Prajna, A. Jadbabaie, G. J. Pappas.
  "Safety verification of hybrid systems using barrier certificates." HSCC 2004.

In a3-python, we use the same *barrier proof obligations* (Init/Unsafe/Step)
but apply them to discrete transition systems extracted from Python bytecode.

This module provides a first practical, sound "hybrid-style" integration:
- extract an affine loop model (guard + affine updates),
- identify division sites in the loop body,
- prove DIV_ZERO is unreachable when the loop guard itself enforces the divisor != 0.

The proof is a checkable barrier certificate: a piecewise polynomial barrier
that is positive outside the loop body and enforces non-zero divisor inside it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional
import itertools
import dis
import z3

from ..cfg.loop_analysis import LoopInfo, extract_loops
from ..cfg.affine_loop_model import (
    extract_affine_loop_model,
    AffineUpdate,
    ConstantUpdate,
    AffineOperand,
)
from ..semantics.symbolic_vm import SymbolicMachineState, SymbolicFrame
from ..z3model.heap import SymbolicHeap
from ..z3model.values import SymbolicValue, ValueTag
from ..semantics.security_tracker_lattice import LatticeSecurityTracker

from .invariants import BarrierCertificate, InductivenessChecker, InductivenessResult


@dataclass(frozen=True)
class GuardedDivZeroBarrierProof:
    loop_header_offset: int
    divisor_var: str
    barrier: BarrierCertificate
    inductiveness: InductivenessResult


def prove_guarded_div_zero_in_affine_loops(
    code_obj,
    *,
    timeout_ms: int = 2000,
    epsilon: float = 0.01,
) -> list[GuardedDivZeroBarrierProof]:
    """
    Attempt HSCC'04-style barrier proofs for DIV_ZERO inside affine loops.

    Soundness rule for this pass:
    - We only claim SAFE when we can prove, universally, that
      (loop_guard holds) => (divisor != 0) at the start of each iteration.
    - We model a loop iteration as one affine transition (back-edge model).

    Returns a list of proven loop-local DIV_ZERO safety certificates.
    """
    proofs: list[GuardedDivZeroBarrierProof] = []
    loops = extract_loops(code_obj)
    checker = InductivenessChecker(timeout_ms=timeout_ms)

    for loop in loops:
        model = extract_affine_loop_model(
            code_obj,
            header_offset=loop.header_offset,
            body_offsets=loop.body_offsets,
            modified_variables=loop.modified_variables,
        )
        if model is None or model.guard is None:
            continue

        guard_var = _guard_var_implying_nonzero(model.guard)
        if guard_var is None:
            continue

        divisor_vars = _extract_divisor_vars_from_loop_body(code_obj, loop.body_offsets)
        if guard_var not in divisor_vars:
            continue

        state_builder, var_extractors = _build_loop_state_builder(
            code_obj,
            loop_variables=(loop.loop_variables | {guard_var}),
        )
        guard_formula = _make_guard_formula(model.guard, var_extractors)
        step_relation = _make_affine_step_relation(loop, model, var_extractors, guard_formula)

        divisor_extractor = var_extractors[guard_var]

        barrier = _conditional_nonzero_barrier(
            condition_extractor=guard_formula,
            variable_name=guard_var,
            variable_extractor=divisor_extractor,
            epsilon=epsilon,
        )

        def unsafe_predicate(state: SymbolicMachineState) -> z3.BoolRef:
            d = divisor_extractor(state)
            d_int = d if z3.is_int(d) else z3.ToInt(d)
            return z3.And(guard_formula(state), d_int == 0)

        induct = checker.check_inductiveness(
            barrier=barrier,
            initial_state_builder=state_builder,
            unsafe_predicate=unsafe_predicate,
            step_relation=step_relation,
        )
        if induct.is_inductive:
            proofs.append(
                GuardedDivZeroBarrierProof(
                    loop_header_offset=loop.header_offset,
                    divisor_var=guard_var,
                    barrier=barrier,
                    inductiveness=induct,
                )
            )

    return proofs


def _guard_var_implying_nonzero(guard) -> Optional[str]:
    """
    If the affine guard implies `var != 0`, return that var name.

    Recognizes simple patterns:
      - var != 0
      - var > 0 / var < 0
      - 0 < var / 0 > var
    """
    lhs, rhs = guard.lhs, guard.rhs
    op = guard.op

    def is_var0(v: AffineOperand, c: AffineOperand) -> Optional[str]:
        if v.kind == "var" and c.kind == "const" and int(c.value) == 0:
            return str(v.value)
        return None

    var = is_var0(lhs, rhs) or is_var0(rhs, lhs)
    if var is None:
        return None

    if op in {"!=", ">", "<"}:
        return var

    # <= / >= / == do not imply non-zero.
    return None


def _extract_divisor_vars_from_loop_body(code_obj, body_offsets: set[int]) -> set[str]:
    """
    Best-effort extraction of variables used as divisors in the loop body.

    We only target common patterns:
      LOAD_FAST <x>; LOAD_FAST <y>; BINARY_OP '/'  (divisor is y)
      LOAD_CONST <c>; LOAD_FAST <y>; BINARY_OP '/'  (divisor is y)
    """
    instructions = [ins for ins in dis.get_instructions(code_obj) if ins.offset in body_offsets]
    if not instructions:
        return set()

    # Simple stack provenance: track only "var"/"const"/"other".
    stack: list[tuple[str, Optional[str]]] = []
    divisors: set[str] = set()

    def push_var(name: str) -> None:
        stack.append(("var", name))

    def push_const() -> None:
        stack.append(("const", None))

    def push_other() -> None:
        stack.append(("other", None))

    for ins in instructions:
        op = ins.opname
        if op in {"LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"} and isinstance(
            ins.argval, str
        ):
            push_var(ins.argval)
            continue

        if op in {
            "LOAD_FAST_LOAD_FAST",
            "LOAD_FAST_BORROW_LOAD_FAST_BORROW",
            "LOAD_FAST_BORROW_LOAD_FAST",
            "LOAD_FAST_LOAD_FAST_BORROW",
        } and isinstance(ins.argval, tuple):
            for item in ins.argval:
                if isinstance(item, str):
                    push_var(item)
                else:
                    push_other()
            continue

        if op in {"LOAD_CONST", "LOAD_SMALL_INT"}:
            push_const()
            continue

        if op == "BINARY_OP":
            operator = (ins.argrepr or "").strip()
            if len(stack) >= 2:
                rhs_kind, rhs_name = stack.pop()
                stack.pop()  # lhs
                if operator in {"/", "//", "%"} and rhs_kind == "var" and rhs_name:
                    divisors.add(rhs_name)
                push_other()
            else:
                stack.clear()
            continue

        # Unknown instruction: clear provenance to avoid incorrect pairing.
        if op.startswith("STORE_") or op.startswith("CALL") or op.startswith("PRECALL"):
            stack.clear()
            continue

        # Default: treat as stack-opaque and reset (conservative for extraction).
        stack.clear()

    return divisors


def _build_loop_state_builder(code_obj, *, loop_variables: set[str]):
    counter = itertools.count()

    def builder() -> SymbolicMachineState:
        state_id = next(counter)
        frame_locals: dict[str, SymbolicValue] = {}
        for var_name in sorted(loop_variables):
            frame_locals[var_name] = SymbolicValue(ValueTag.INT, z3.Int(f"{var_name}_{state_id}"))

        frame = SymbolicFrame(
            code=code_obj,
            instruction_offset=0,
            locals=frame_locals,
            globals={},
            builtins={},
            operand_stack=[],
        )
        return SymbolicMachineState(
            frame_stack=[frame],
            heap=SymbolicHeap(),
            path_condition=z3.BoolVal(True),
            func_names={},
            security_tracker=LatticeSecurityTracker(),
        )

    def extractor(name: str) -> Callable[[SymbolicMachineState], z3.ExprRef]:
        def _ex(st: SymbolicMachineState) -> z3.ExprRef:
            if st.frame_stack and name in st.frame_stack[-1].locals:
                val = st.frame_stack[-1].locals[name]
                if hasattr(val, "payload") and isinstance(val.payload, z3.ExprRef):
                    return val.payload
            return z3.IntVal(0)

        return _ex

    var_extractors = {name: extractor(name) for name in loop_variables}
    return builder, var_extractors


def _make_guard_formula(
    guard,
    var_extractors: dict[str, Callable[[SymbolicMachineState], z3.ExprRef]],
) -> Callable[[SymbolicMachineState], z3.BoolRef]:
    def operand_to_int(opnd: AffineOperand, st: SymbolicMachineState) -> Optional[z3.ArithRef]:
        if opnd.kind == "const":
            return z3.IntVal(int(opnd.value))
        if opnd.kind == "var":
            name = str(opnd.value)
            ex = var_extractors.get(name)
            if ex is None:
                return None
            v = ex(st)
            return v if z3.is_int(v) else z3.ToInt(v)
        return None

    def guard_formula(st: SymbolicMachineState) -> z3.BoolRef:
        lhs = operand_to_int(guard.lhs, st)
        rhs = operand_to_int(guard.rhs, st)
        if lhs is None or rhs is None:
            return z3.BoolVal(True)
        op = guard.op
        if op == "<":
            return lhs < rhs
        if op == "<=":
            return lhs <= rhs
        if op == ">":
            return lhs > rhs
        if op == ">=":
            return lhs >= rhs
        if op == "==":
            return lhs == rhs
        if op == "!=":
            return lhs != rhs
        return z3.BoolVal(True)

    return guard_formula


def _make_affine_step_relation(
    loop: LoopInfo,
    model,
    var_extractors: dict[str, Callable[[SymbolicMachineState], z3.ExprRef]],
    guard_formula: Callable[[SymbolicMachineState], z3.BoolRef],
) -> Callable[[SymbolicMachineState, SymbolicMachineState], z3.BoolRef]:
    def step(s: SymbolicMachineState, s_prime: SymbolicMachineState) -> z3.BoolRef:
        constraints: list[z3.BoolRef] = [guard_formula(s)]

        all_vars = loop.loop_variables | set(model.updates.keys())
        for var_name in sorted(all_vars):
            pre = var_extractors[var_name](s)
            post = var_extractors[var_name](s_prime)
            pre_i = pre if z3.is_int(pre) else z3.ToInt(pre)
            post_i = post if z3.is_int(post) else z3.ToInt(post)

            upd = model.updates.get(var_name)
            if isinstance(upd, AffineUpdate):
                constraints.append(post_i == pre_i + int(upd.delta))
            elif isinstance(upd, ConstantUpdate):
                constraints.append(post_i == int(upd.value))
            else:
                # Variables not modified by the model remain unchanged.
                constraints.append(post_i == pre_i)

        return z3.And(*constraints)

    return step


def _conditional_nonzero_barrier(
    *,
    condition_extractor: Callable[[SymbolicMachineState], z3.BoolRef],
    variable_name: str,
    variable_extractor: Callable[[SymbolicMachineState], z3.ExprRef],
    epsilon: float,
    slack: float = 0.25,
    else_value: float = 1000.0,
) -> BarrierCertificate:
    """
    Piecewise polynomial barrier:
      B(s) = if cond(s) then (x^2 - slack) else else_value

    For integer x, x^2 - 0.25 >= 0 implies x != 0.
    """

    def barrier_fn(st: SymbolicMachineState) -> z3.ExprRef:
        cond = condition_extractor(st)
        x = variable_extractor(st)
        x_real = z3.ToReal(x) if z3.is_int(x) else x
        return z3.If(cond, x_real * x_real - z3.RealVal(slack), z3.RealVal(else_value))

    return BarrierCertificate(
        name=f"hscc2004_nonzero_guard_{variable_name}",
        barrier_fn=barrier_fn,
        epsilon=epsilon,
        description=(
            f"HSCC'04-style barrier: if guard holds then {variable_name} != 0 "
            f"(via {variable_name}^2 - {slack} >= 0), else vacuously safe"
        ),
        variables=[variable_name],
    )


# ============================================================================
# Non-loop HSCC'04 barrier (Paper #1)
# ============================================================================

@dataclass(frozen=True)
class NonLoopBarrierProof:
    """HSCC'04 barrier proof for non-loop guarded division."""
    site_offset: int
    divisor_var: str
    guard_condition: str


def prove_nonloop_guarded_div_zero(code_obj) -> list[NonLoopBarrierProof]:
    """
    Prove that division-by-zero sites in non-loop code are unreachable because
    a dominating ``if var != 0:`` guard ensures the divisor is non-zero.

    This extends Paper #1 (HSCC'04 barrier certificates) to straight-line code.
    The "barrier" degenerates to a simple guard implication, but the proof
    structure (guard ∧ hazard = ∅) is identical.
    """
    from .sos_safety import prove_nonloop_guarded_hazards

    nl_proofs = prove_nonloop_guarded_hazards(code_obj)
    return [
        NonLoopBarrierProof(
            site_offset=p.site_offset,
            divisor_var=p.variable,
            guard_condition=f"{p.guard_lhs} {p.guard_op} {p.guard_rhs}",
        )
        for p in nl_proofs
        if p.bug_type == "DIV_ZERO"
    ]

