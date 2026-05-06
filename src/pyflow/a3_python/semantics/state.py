"""
Machine state datastructures for concrete and symbolic semantics.
Target: Python 3.11+ bytecode as abstract machine.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Frame:
    """
    A single execution frame in the Python abstract machine.
    
    Corresponds to a function/module scope during execution.
    """
    code: Any  # types.CodeType
    instruction_offset: int = 0
    locals: dict[str, Any] = field(default_factory=dict)
    globals: dict[str, Any] = field(default_factory=dict)
    builtins: dict[str, Any] = field(default_factory=dict)
    operand_stack: list[Any] = field(default_factory=list)
    block_stack: list[tuple[str, int]] = field(default_factory=list)
    
    def __repr__(self):
        return (
            f"Frame(offset={self.instruction_offset}, "
            f"stack_depth={len(self.operand_stack)}, "
            f"locals={list(self.locals.keys())})"
        )


@dataclass
class MachineState:
    """
    The complete state of the Python abstract machine.
    
    State space S in the transition system model.
    """
    frame_stack: list[Frame] = field(default_factory=list)
    exception: Optional[tuple[type, Any, Any]] = None
    halted: bool = False
    return_value: Any = None
    
    @property
    def current_frame(self) -> Optional[Frame]:
        return self.frame_stack[-1] if self.frame_stack else None
    
    def __repr__(self):
        if self.halted:
            return f"MachineState(halted=True, return_value={self.return_value})"
        if self.exception:
            exc_type, exc_val, _ = self.exception
            return f"MachineState(exception={exc_type.__name__}: {exc_val})"
        return f"MachineState(frames={len(self.frame_stack)}, current={self.current_frame})"
