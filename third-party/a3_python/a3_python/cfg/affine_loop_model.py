"""
Affine loop model extraction for Python bytecode.

This module extracts a small, *solver-friendly* transition relation for common
"counter-style" loops, e.g.:

    while i < n:
        i += 1

or:

    while n > 0:
        n -= 1

The extracted model is used by:
- termination checking (ranking synthesis) to avoid overly-conservative havoc,
- loop invariant synthesis to build meaningful inductiveness obligations,
- SOTA engines (BMC/PDR/ICE) that operate on linear integer transition systems.

Design goals:
- Be robust to CPython superinstructions (e.g., LOAD_FAST_*_LOAD_FAST_*).
- Be conservative: if we cannot extract a sound affine model, return None and
  let callers fall back to existing conservative encoders.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Union

import dis


@dataclass(frozen=True)
class AffineOperand:
    kind: str  # "var" | "const"
    value: Union[str, int]


@dataclass(frozen=True)
class AffineGuard:
    lhs: AffineOperand
    op: str  # "<", "<=", ">", ">=", "==", "!=", ...
    rhs: AffineOperand


@dataclass(frozen=True)
class AffineUpdate:
    var: str
    base: str
    delta: int


@dataclass(frozen=True)
class ConstantUpdate:
    var: str
    value: int


Update = Union[AffineUpdate, ConstantUpdate]


@dataclass(frozen=True)
class AffineLoopModel:
    """
    An affine approximation of a loop back-edge relation.

    This is intended to model the *iteration* transition (back-edge), not the full
    program semantics.
    """

    guard: Optional[AffineGuard]
    updates: dict[str, Update]  # var -> update relation

    def updated_vars(self) -> set[str]:
        return set(self.updates.keys())


_COND_JUMPS = {
    # common
    "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_TRUE",
    "POP_JUMP_FORWARD_IF_FALSE",
    "POP_JUMP_FORWARD_IF_TRUE",
    "POP_JUMP_BACKWARD_IF_FALSE",
    "POP_JUMP_BACKWARD_IF_TRUE",
    # older spellings / variants
    "JUMP_IF_FALSE_OR_POP",
    "JUMP_IF_TRUE_OR_POP",
}

_LOADS_THAT_PUSH_ONE = {
    "LOAD_FAST",
    "LOAD_FAST_BORROW",
    "LOAD_FAST_BORROW_LOAD_FAST_BORROW",  # note: pushes two (handled separately)
    "LOAD_NAME",
    "LOAD_GLOBAL",
    "LOAD_DEREF",
    "LOAD_CLOSURE",
    "LOAD_CONST",
    "LOAD_SMALL_INT",
}

_LOADS_THAT_PUSH_TWO = {
    # CPython superinstructions that push 2 locals
    "LOAD_FAST_LOAD_FAST",
    "LOAD_FAST_BORROW_LOAD_FAST_BORROW",
    "LOAD_FAST_BORROW_LOAD_FAST",
    "LOAD_FAST_LOAD_FAST_BORROW",
}

_STORE_OPS = {
    "STORE_FAST",
    "STORE_NAME",
    "STORE_GLOBAL",
}


def extract_affine_loop_model(
    code_obj, *, header_offset: int, body_offsets: set[int], modified_variables: set[str]
) -> Optional[AffineLoopModel]:
    """
    Best-effort extraction of an affine loop model.

    Returns None if we can't find a trustworthy (guard, update) pair.
    """
    instructions = list(dis.get_instructions(code_obj))
    offset_to_index = {ins.offset: idx for idx, ins in enumerate(instructions)}
    header_index = offset_to_index.get(header_offset)
    if header_index is None:
        return None

    guard = _extract_affine_guard(instructions, header_index)
    updates: dict[str, Update] = {}
    for var in sorted(modified_variables):
        update = _extract_update_for_var(instructions, body_offsets=body_offsets, var_name=var)
        if update is not None:
            updates[var] = update

    if not updates:
        return None

    return AffineLoopModel(guard=guard, updates=updates)


def _extract_affine_guard(
    instructions: Sequence[dis.Instruction], header_index: int
) -> Optional[AffineGuard]:
    # Search forward from header for the first conditional jump that exits the loop body.
    # For "while" loops, the pattern is: LOADs, COMPARE_OP, POP_JUMP_IF_FALSE/TRUE.
    jump_index = None
    compare_index = None
    for idx in range(header_index, min(header_index + 30, len(instructions))):
        op = instructions[idx].opname
        if op == "COMPARE_OP":
            compare_index = idx
        if op in _COND_JUMPS:
            jump_index = idx
            break

    if jump_index is None or compare_index is None:
        return None

    compare = instructions[compare_index]
    if compare.argval is None or not isinstance(compare.argval, str):
        return None

    operands = _collect_stack_operands(instructions, compare_index, needed=2)
    if operands is None:
        return None

    lhs, rhs = operands
    return AffineGuard(lhs=lhs, op=compare.argval, rhs=rhs)


def _extract_update_for_var(
    instructions: Sequence[dis.Instruction], *, body_offsets: set[int], var_name: str
) -> Optional[Update]:
    # Prefer the last STORE_* to var_name within the loop body.
    store_indices = [
        idx
        for idx, ins in enumerate(instructions)
        if ins.offset in body_offsets and ins.opname in _STORE_OPS and ins.argval == var_name
    ]
    if not store_indices:
        return None

    store_idx = store_indices[-1]
    # Pattern A: x = x (+|-) c (or x += c / x -= c)
    if store_idx - 1 >= 0 and instructions[store_idx - 1].opname == "BINARY_OP":
        binop = instructions[store_idx - 1]
        op = _normalize_binary_op(binop.argrepr)
        if op in {"+", "-"}:
            operands = _collect_stack_operands(instructions, store_idx - 1, needed=2)
            if operands:
                lhs, rhs = operands
                # We only accept affine updates where lhs is the same var and rhs is an int const.
                if lhs.kind == "var" and lhs.value == var_name and rhs.kind == "const" and isinstance(rhs.value, int):
                    delta = rhs.value if op == "+" else -rhs.value
                    return AffineUpdate(var=var_name, base=var_name, delta=delta)
    # Pattern B: x = const
    operands = _collect_stack_operands(instructions, store_idx, needed=1)
    if operands and operands[0].kind == "const" and isinstance(operands[0].value, int):
        return ConstantUpdate(var=var_name, value=operands[0].value)

    return None


def _collect_stack_operands(
    instructions: Sequence[dis.Instruction], consumer_index: int, *, needed: int
) -> Optional[list[AffineOperand]]:
    operands: list[AffineOperand] = []
    remaining = needed

    # Walk backwards collecting values that were pushed for the consumer.
    for idx in range(consumer_index - 1, max(-1, consumer_index - 20), -1):
        pushes = _stack_pushes(instructions[idx])
        if not pushes:
            continue
        # pushes is bottom->top; reverse for backwards collection.
        for operand in reversed(pushes):
            operands.append(operand)
            remaining -= 1
            if remaining == 0:
                operands.reverse()
                return operands

    return None


def _stack_pushes(ins: dis.Instruction) -> list[AffineOperand]:
    op = ins.opname

    # Two-value local loads (superinstructions)
    if op in _LOADS_THAT_PUSH_TWO:
        if isinstance(ins.argval, tuple) and all(isinstance(x, str) for x in ins.argval):
            return [AffineOperand("var", ins.argval[0]), AffineOperand("var", ins.argval[1])]
        return []

    # Single push loads
    if op in _LOADS_THAT_PUSH_ONE:
        if op in {"LOAD_CONST", "LOAD_SMALL_INT"}:
            if isinstance(ins.argval, bool):
                # Avoid confusing booleans with ints for numeric loops.
                return []
            if isinstance(ins.argval, int):
                return [AffineOperand("const", ins.argval)]
            return []

        # Local/global name loads
        if op.startswith("LOAD_") and isinstance(ins.argval, str):
            return [AffineOperand("var", ins.argval)]

    return []


def _normalize_binary_op(argrepr: str) -> Optional[str]:
    """
    Map CPython BINARY_OP argrepr (e.g. '+', '-=', '//', '%=') to a normalized operator.
    """
    if not argrepr:
        return None
    # Common forms:
    #   '+' '-' '*', '/', '//', '%'
    #   '+=' '-=' '*=' '/=' '//=' '%='
    if argrepr.endswith("=") and len(argrepr) >= 2:
        argrepr = argrepr[:-1]
    if argrepr in {"+", "-"}:
        return argrepr
    return None

