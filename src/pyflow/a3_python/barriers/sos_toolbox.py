"""
SOTA papers #4-5 integration: SOSTOOLS (SOS tooling) + Putinar Positivstellensatz.

We implement a light-weight SOS-style toolkit that leverages:
- compactness (Putinar) from explicit bounds in loop guards, and
- polynomial template certificates (SOSTOOLS-style) verified via SMT.

This is orthogonal to barrier synthesis:
  * It reduces false positives by proving certain hazard sites unreachable
    on *compact* domains (bounded loop guards).
  * It increases bug coverage by enabling localized SAFE proofs that prune
    expensive paths in the kitchen-sink portfolio.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import dis
import z3

from ..cfg.loop_analysis import extract_loops
from ..cfg.control_flow import build_cfg, ControlFlowGraph
from ..cfg.affine_loop_model import extract_affine_loop_model, AffineGuard, AffineOperand
from .templates import polynomial_barrier, extract_local_variable
from .sos_safety import _find_division_sites, _find_math_domain_calls


@dataclass(frozen=True)
class SosCompactProof:
    bug_type: str
    loop_header_offset: int
    site_offset: int
    variable: str
    lower: int
    upper: int
    guard: str
    certificate: str
    reason: str


def prove_guarded_hazards_compact(code_obj) -> list[SosCompactProof]:
    """
    Prove guarded hazards unreachable when the guard yields a compact domain.

    Requires finite bounds [l, u] for the hazard variable.
    """
    proofs: list[SosCompactProof] = []

    cfg = build_cfg(code_obj)
    loops = extract_loops(code_obj, cfg=cfg)
    for loop in loops:
        bounds = _infer_compact_bounds(code_obj, loop.header_offset)
        if not bounds:
            continue

        # DIV_ZERO: divisor != 0 on compact interval.
        for div_site in _find_division_sites(_ordered_body_instructions(code_obj, loop.body_offsets)):
            var = div_site.divisor_var
            if var not in bounds:
                continue
            lower, upper = bounds[var]
            if _var_modified_before_site_in_iteration(cfg, code_obj, loop, var, div_site.offset):
                continue
            if _bounds_imply_nonzero(var, lower, upper):
                proofs.append(
                    SosCompactProof(
                        bug_type="DIV_ZERO",
                        loop_header_offset=loop.header_offset,
                        site_offset=div_site.offset,
                        variable=var,
                        lower=lower,
                        upper=upper,
                        guard=f"{lower} <= {var} <= {upper}",
                        certificate=_certificate_string(var, lower, upper),
                        reason="Compact bounds exclude zero",
                    )
                )

        # FP_DOMAIN: domain checks for sqrt/log on compact interval.
        for call_site in _find_math_domain_calls(_ordered_body_instructions(code_obj, loop.body_offsets)):
            var = call_site.arg_var
            if var not in bounds:
                continue
            lower, upper = bounds[var]
            if _var_modified_before_site_in_iteration(cfg, code_obj, loop, var, call_site.offset):
                continue
            if call_site.kind == "sqrt" and _bounds_imply_nonnegative(var, lower, upper):
                proofs.append(
                    SosCompactProof(
                        bug_type="FP_DOMAIN",
                        loop_header_offset=loop.header_offset,
                        site_offset=call_site.offset,
                        variable=var,
                        lower=lower,
                        upper=upper,
                        guard=f"{lower} <= {var} <= {upper}",
                        certificate=_certificate_string(var, lower, upper),
                        reason="Compact bounds ensure sqrt domain",
                    )
                )
            if call_site.kind == "log" and _bounds_imply_positive(var, lower, upper):
                proofs.append(
                    SosCompactProof(
                        bug_type="FP_DOMAIN",
                        loop_header_offset=loop.header_offset,
                        site_offset=call_site.offset,
                        variable=var,
                        lower=lower,
                        upper=upper,
                        guard=f"{lower} <= {var} <= {upper}",
                        certificate=_certificate_string(var, lower, upper),
                        reason="Compact bounds ensure log domain",
                    )
                )

    return proofs


def _var_modified_before_site_in_iteration(
    cfg: ControlFlowGraph,
    code_obj,
    loop,
    var: str,
    site_offset: int,
) -> bool:
    """
    Conservative soundness check:
    If `var` might be stored on any path from loop entry (after header guard)
    to `site_offset` within a single iteration, do not produce a compact proof.
    """
    header_block = cfg.get_block_for_offset(loop.header_offset)
    site_block = cfg.get_block_for_offset(site_offset)
    if header_block is None or site_block is None:
        return True

    loop_block_ids: set[int] = set()
    for off in loop.body_offsets | {loop.header_offset}:
        bid = cfg.offset_to_block.get(off)
        if bid is not None:
            loop_block_ids.add(bid)

    if header_block.id not in loop_block_ids or site_block.id not in loop_block_ids:
        return True

    header_offsets = {ins.offset for ins in header_block.instructions}
    candidate_store_offsets: list[int] = []
    for ins in dis.get_instructions(code_obj):
        if ins.offset not in loop.body_offsets:
            continue
        if ins.offset in header_offsets:
            continue
        if _is_store_to_var(ins, var):
            candidate_store_offsets.append(ins.offset)

    if not candidate_store_offsets:
        return False

    # Within-iteration reachability: cut edges that jump back to the loop header.
    adjacency: dict[int, list[int]] = {}
    reverse: dict[int, list[int]] = {}
    for bid in loop_block_ids:
        block = cfg.blocks.get(bid)
        if not block:
            continue
        succs: list[int] = []
        for tgt_id, _, _ in block.successors:
            if tgt_id not in loop_block_ids:
                continue
            if tgt_id == header_block.id:
                continue
            succs.append(tgt_id)
        adjacency[bid] = succs
        for tgt_id in succs:
            reverse.setdefault(tgt_id, []).append(bid)

    entry_blocks = {
        tgt_id
        for tgt_id, _, _ in header_block.successors
        if tgt_id in loop_block_ids and tgt_id != header_block.id
    }
    if not entry_blocks:
        return True

    reachable_from_entry: set[int] = set()
    work = list(entry_blocks)
    while work:
        bid = work.pop()
        if bid in reachable_from_entry:
            continue
        reachable_from_entry.add(bid)
        work.extend(adjacency.get(bid, []))

    if site_block.id not in reachable_from_entry:
        return True

    can_reach_site: set[int] = set()
    work = [site_block.id]
    while work:
        bid = work.pop()
        if bid in can_reach_site:
            continue
        can_reach_site.add(bid)
        work.extend(reverse.get(bid, []))

    for store_offset in candidate_store_offsets:
        store_block_id = cfg.offset_to_block.get(store_offset)
        if store_block_id is None:
            continue
        if store_block_id not in reachable_from_entry:
            continue
        if store_block_id not in can_reach_site:
            continue
        if store_block_id == site_block.id and store_offset >= site_offset:
            continue
        return True

    return False


def _is_store_to_var(ins: dis.Instruction, var: str) -> bool:
    if not ins.opname.startswith("STORE_"):
        return False
    if ins.argval == var:
        return True
    if isinstance(ins.argval, tuple) and var in ins.argval:
        return True
    return False


def _ordered_body_instructions(code_obj, body_offsets: set[int]) -> list[dis.Instruction]:
    instrs = [i for i in dis.get_instructions(code_obj) if i.offset in body_offsets]
    instrs.sort(key=lambda i: i.offset)
    return instrs


def _certificate_string(var: str, lower: int, upper: int) -> str:
    # SOSTOOLS-style compact-domain certificate: (x-l)*(u-x) >= 0.
    return f"({var}-{lower})*({upper}-{var}) >= 0"


def _bounds_imply_nonzero(var: str, lower: int, upper: int) -> bool:
    x = z3.Int(var)
    solver = z3.Solver()
    solver.add(x >= lower, x <= upper, x == 0)
    return solver.check() == z3.unsat


def _bounds_imply_nonnegative(var: str, lower: int, upper: int) -> bool:
    x = z3.Int(var)
    solver = z3.Solver()
    solver.add(x >= lower, x <= upper, x < 0)
    return solver.check() == z3.unsat


def _bounds_imply_positive(var: str, lower: int, upper: int) -> bool:
    x = z3.Int(var)
    solver = z3.Solver()
    solver.add(x >= lower, x <= upper, x <= 0)
    return solver.check() == z3.unsat


def _infer_compact_bounds(code_obj, header_offset: int) -> dict[str, tuple[int, int]]:
    """
    Extract compact bounds [l, u] for loop variables from the loop header.

    Handles chained comparisons like: 0 <= x <= 10
    by simulating stack effects for COPY/SWAP in header.
    """
    instructions = list(dis.get_instructions(code_obj))
    offset_to_index = {ins.offset: idx for idx, ins in enumerate(instructions)}
    header_index = offset_to_index.get(header_offset)
    if header_index is None:
        return {}

    bounds: dict[str, tuple[Optional[int], Optional[int]]] = {}
    stack: list[tuple[str, Optional[int] | Optional[str]]] = []

    def push_const(val: int) -> None:
        stack.append(("const", int(val)))

    def push_var(name: str) -> None:
        stack.append(("var", str(name)))

    def pop() -> Optional[tuple[str, Optional[int] | Optional[str]]]:
        return stack.pop() if stack else None

    def swap(n: int) -> None:
        if n <= 1 or len(stack) < n:
            return
        idx = -n
        stack[-1], stack[idx] = stack[idx], stack[-1]

    def copy(n: int) -> None:
        if n <= 0 or len(stack) < n:
            return
        stack.append(stack[-n])

    for ins in instructions[header_index : header_index + 40]:
        op = ins.opname
        if op in {"LOAD_SMALL_INT", "LOAD_CONST"} and isinstance(ins.argval, int):
            push_const(ins.argval)
        elif op in {"LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"} and isinstance(
            ins.argval, str
        ):
            push_var(ins.argval)
        elif op == "SWAP" and isinstance(ins.arg, int):
            swap(ins.arg)
        elif op == "COPY" and isinstance(ins.arg, int):
            copy(ins.arg)
        elif op == "COMPARE_OP":
            rhs = pop()
            lhs = pop()
            if not lhs or not rhs:
                continue
            if lhs[0] == "var" and rhs[0] == "const":
                var = lhs[1]
                c = rhs[1]
                bounds[var] = _update_bounds(bounds.get(var), ins.argval, int(c))
            elif lhs[0] == "const" and rhs[0] == "var":
                var = rhs[1]
                c = lhs[1]
                bounds[var] = _update_bounds(bounds.get(var), _flip_op(ins.argval), int(c))
        elif op in {"POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE", "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE"}:
            # ignore control flow; we just want comparisons
            continue

    compact: dict[str, tuple[int, int]] = {}
    for var, (lo, hi) in bounds.items():
        if lo is not None and hi is not None and lo <= hi:
            compact[var] = (lo, hi)
    return compact


def _update_bounds(
    existing: Optional[tuple[Optional[int], Optional[int]]],
    op: str,
    c: int,
) -> tuple[Optional[int], Optional[int]]:
    lo, hi = existing if existing else (None, None)
    if op == ">":
        lo = max(lo, c + 1) if lo is not None else c + 1
    elif op == ">=":
        lo = max(lo, c) if lo is not None else c
    elif op == "<":
        hi = min(hi, c - 1) if hi is not None else c - 1
    elif op == "<=":
        hi = min(hi, c) if hi is not None else c
    elif op == "==":
        lo = c if lo is None else max(lo, c)
        hi = c if hi is None else min(hi, c)
    return (lo, hi)


def _flip_op(op: str) -> str:
    if op == "<":
        return ">"
    if op == "<=":
        return ">="
    if op == ">":
        return "<"
    if op == ">=":
        return "<="
    return op
