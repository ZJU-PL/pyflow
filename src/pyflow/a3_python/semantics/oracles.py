"""
Execution oracles for trace-guided symbolic replay.

These oracles allow the symbolic VM to follow a particular concrete execution
without resorting to source-pattern matching. They are intended for:

- Selective concolic execution (symbolically model "our code", concretely run libraries)
- Trace replay / witness production
- Debugging mismatches between concrete and symbolic executions

Important soundness note:
- Oracles may *concretize* behaviors for witness production (existential claims),
  but must never be used as a basis for universal SAFE proofs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol
import types


@dataclass(frozen=True)
class CallSiteKey:
    """
    Stable identifier for a callsite inside a code object.

    The key is intentionally derived only from code metadata + bytecode offset,
    so it can be matched between concrete tracing (CPython frames) and our
    symbolic bytecode VM.
    """

    filename: str
    qualname: str
    firstlineno: int
    offset: int

    @staticmethod
    def from_code(code: types.CodeType, offset: int) -> "CallSiteKey":
        qualname = getattr(code, "co_qualname", code.co_name)
        return CallSiteKey(
            filename=code.co_filename,
            qualname=qualname,
            firstlineno=code.co_firstlineno,
            offset=offset,
        )


@dataclass(frozen=True)
class CallObservation:
    """
    Concrete observation of a call (from concolic tracing).

    This observation is an under-approximate sample of Sem_f. It is useful to:
    - produce concrete witnesses/repros,
    - detect when a trusted contract is too narrow (unsound),
    - guide where to invest contract/summarization work.
    """

    function_id: str
    kind: str  # "python" | "c"

    # Concrete values (best-effort; may be None if not observable)
    args: Optional[dict[str, Any]] = None
    # Disambiguates "returned None" from "return not observed".
    has_return_value: bool = False
    return_value: Optional[Any] = None

    # Exception information (if raised at the call boundary)
    exception_type: Optional[str] = None
    exception_repr: Optional[str] = None


class ExecutionOracle(Protocol):
    """
    Oracle interface used by SymbolicVM for trace-guided replay.

    Implementations are typically built from a selective concolic execution trace.
    """

    def pop_branch_next_offset(self, code: types.CodeType, offset: int) -> Optional[int]:
        """
        If available, return the *next* bytecode offset observed after executing
        the conditional branch instruction at (code, offset), for this occurrence.

        Returns None if no guidance is available.
        """

    def pop_call_observation(self, code: types.CodeType, offset: int) -> Optional[CallObservation]:
        """
        If available, return the next concrete call observation for the callsite
        (code, offset), for this occurrence.

        Returns None if no observation is available.
        """

    @property
    def concretize_unknown_returns(self) -> bool:
        """
        If True, the symbolic VM may concretize return values for unknown calls
        when an observation is available. This is for witness/replay only.
        """
