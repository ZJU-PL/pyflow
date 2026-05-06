"""
Hybrid concolic+symbolic support for unknown library semantics.

This module bridges:
- Selective concrete tracing (SelectiveConcolicTrace)
- Trace-guided symbolic replay (ExecutionOracle for SymbolicVM)

The oracle produced here is intended for:
- replaying a concrete witness path in the symbolic VM,
- attaching concrete call observations to symbolic counterexamples,
- debugging mismatches at branch and call sites.

It must NOT be used to justify SAFE proofs.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional
import dis
import types

from ..semantics.oracles import CallObservation, CallSiteKey, ExecutionOracle
from .selective_concolic import CodeKey, SelectiveConcolicTrace


def _is_conditional_branch(opname: str) -> bool:
    # Keep in sync with what SymbolicVM can replay deterministically.
    return opname in {
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "FOR_ITER",
    }


@dataclass
class ConcolicReplayOracle(ExecutionOracle):
    """
    ExecutionOracle built from a SelectiveConcolicTrace.

    The oracle is *occurrence sensitive*:
    - each callsite/branch site maps to a queue (deque) of observations/next-offsets
    - pop_* methods consume observations in the same order as the concrete run
    """

    _call_deques: Dict[CallSiteKey, Deque[CallObservation]]
    _owned_offsets: Dict[CodeKey, list[int]]
    _branch_deques_by_code: Dict[CodeKey, Dict[int, Deque[int]]]

    concretize_unknown_returns: bool = True

    @staticmethod
    def from_trace(trace: SelectiveConcolicTrace) -> "ConcolicReplayOracle":
        call_deques: Dict[CallSiteKey, Deque[CallObservation]] = {}
        for site, obs_list in trace.call_observations.items():
            call_deques[site] = deque(obs_list)
        return ConcolicReplayOracle(
            _call_deques=call_deques,
            _owned_offsets=dict(trace.owned_offsets),
            _branch_deques_by_code={},
            concretize_unknown_returns=True,
        )

    def pop_call_observation(self, code: types.CodeType, offset: int) -> Optional[CallObservation]:
        site = CallSiteKey.from_code(code, offset)
        q = self._call_deques.get(site)
        if not q:
            return None
        return q.popleft() if q else None

    def pop_branch_next_offset(self, code: types.CodeType, offset: int) -> Optional[int]:
        code_key = CodeKey.from_code(code)
        self._ensure_branch_deques(code, code_key)
        by_offset = self._branch_deques_by_code.get(code_key, {})
        q = by_offset.get(offset)
        if not q:
            return None
        return q.popleft() if q else None

    def _ensure_branch_deques(self, code: types.CodeType, code_key: CodeKey) -> None:
        if code_key in self._branch_deques_by_code:
            return

        offsets = self._owned_offsets.get(code_key)
        if not offsets:
            self._branch_deques_by_code[code_key] = {}
            return

        instr_by_offset = {i.offset: i for i in dis.get_instructions(code)}
        by_offset: Dict[int, Deque[int]] = {}

        for i in range(len(offsets) - 1):
            cur = offsets[i]
            nxt = offsets[i + 1]
            instr = instr_by_offset.get(cur)
            if not instr:
                continue
            if _is_conditional_branch(instr.opname):
                by_offset.setdefault(cur, deque()).append(nxt)

        self._branch_deques_by_code[code_key] = by_offset

