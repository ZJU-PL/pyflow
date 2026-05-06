"""
Concrete bytecode stepper for Python 3.11+.

Implements a faithful-to-CPython interpreter for a subset of bytecode.
Used as oracle/reference for validation and differential testing.
"""

import dis
import types
from typing import Any

from .state import Frame, MachineState


class ConcreteVM:
    """
    Concrete bytecode interpreter.
    
    Executes Python bytecode with observable machine states.
    """
    
    def __init__(self):
        self.state = MachineState()
    
    def load_code(self, code: types.CodeType, globals_dict: dict[str, Any] = None):
        """Initialize machine with a code object."""
        if globals_dict is None:
            globals_dict = {}
        
        import builtins
        builtins_dict = {name: getattr(builtins, name) for name in dir(builtins) if not name.startswith('_')}
        
        frame = Frame(
            code=code,
            instruction_offset=0,
            locals={},
            globals=globals_dict,
            builtins=builtins_dict,
            operand_stack=[],
            block_stack=[]
        )
        self.state.frame_stack = [frame]
        self.state.halted = False
        self.state.exception = None
        self.state.return_value = None
    
    def step(self) -> bool:
        """
        Execute one bytecode instruction.
        
        Returns True if execution should continue, False if halted.
        """
        if self.state.halted or self.state.exception:
            return False
        
        frame = self.state.current_frame
        if not frame:
            self.state.halted = True
            return False
        
        code = frame.code
        if frame.instruction_offset >= len(code.co_code):
            self.state.halted = True
            self.state.return_value = None
            return False
        
        instruction = self._get_instruction(frame)
        if not instruction:
            self.state.halted = True
            return False
        
        self._execute_instruction(frame, instruction)
        return not self.state.halted and not self.state.exception
    
    def run(self, max_steps: int = 10000) -> MachineState:
        """Run until halt or max_steps reached."""
        steps = 0
        while self.step() and steps < max_steps:
            steps += 1
        return self.state
    
    def _get_instruction(self, frame: Frame):
        """Get current instruction from code object."""
        code = frame.code
        offset = frame.instruction_offset
        
        if offset >= len(code.co_code):
            return None
        
        for instr in dis.get_instructions(code):
            if instr.offset == offset:
                return instr
        return None
    
    def _next_offset(self, instr) -> int:
        """Compute the next instruction offset."""
        code = self.state.current_frame.code
        instructions = list(dis.get_instructions(code))
        
        for i, inst in enumerate(instructions):
            if inst.offset == instr.offset:
                if i + 1 < len(instructions):
                    return instructions[i + 1].offset
                else:
                    return len(code.co_code)
        
        return instr.offset + 2
    
    def _execute_instruction(self, frame: Frame, instr):
        """Execute a single instruction. Updates frame in-place."""
        opname = instr.opname
        
        if opname == "RESUME":
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "LOAD_CONST":
            frame.operand_stack.append(instr.argval)
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "LOAD_SMALL_INT":
            frame.operand_stack.append(instr.argval)
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "LOAD_FAST":
            var_name = instr.argval
            if var_name in frame.locals:
                frame.operand_stack.append(frame.locals[var_name])
            else:
                self.state.exception = (UnboundLocalError, f"local variable '{var_name}' referenced before assignment", None)
                return
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "STORE_FAST":
            if not frame.operand_stack:
                self.state.exception = (RuntimeError, "stack underflow", None)
                return
            value = frame.operand_stack.pop()
            frame.locals[instr.argval] = value
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "BINARY_OP":
            if len(frame.operand_stack) < 2:
                self.state.exception = (RuntimeError, "stack underflow", None)
                return
            right = frame.operand_stack.pop()
            left = frame.operand_stack.pop()
            
            op = instr.argval
            try:
                if op == 0:  # ADD
                    result = left + right
                elif op == 10:  # SUBTRACT
                    result = left - right
                elif op == 5:  # MULTIPLY
                    result = left * right
                elif op == 11:  # TRUE_DIVIDE
                    result = left / right
                elif op == 6:  # FLOOR_DIVIDE
                    result = left // right
                elif op == 1:  # AND
                    result = left & right
                elif op == 2:  # OR
                    result = left | right
                elif op == 7:  # MODULO
                    result = left % right
                elif op == 4:  # LSHIFT
                    result = left << right
                elif op == 9:  # RSHIFT
                    result = left >> right
                elif op == 13:  # XOR
                    result = left ^ right
                else:
                    self.state.exception = (NotImplementedError, f"BINARY_OP {op} not implemented", None)
                    return
                frame.operand_stack.append(result)
            except Exception as e:
                self.state.exception = (type(e), str(e), None)
                return
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "RETURN_VALUE":
            if not frame.operand_stack:
                self.state.return_value = None
            else:
                self.state.return_value = frame.operand_stack.pop()
            self.state.frame_stack.pop()
            if not self.state.frame_stack:
                self.state.halted = True
            else:
                self.state.frame_stack[-1].operand_stack.append(self.state.return_value)
        
        elif opname == "POP_TOP":
            if frame.operand_stack:
                frame.operand_stack.pop()
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "COMPARE_OP":
            if len(frame.operand_stack) < 2:
                self.state.exception = (RuntimeError, "stack underflow", None)
                return
            right = frame.operand_stack.pop()
            left = frame.operand_stack.pop()
            
            op = instr.argval
            try:
                if op == "<":
                    result = left < right
                elif op == "<=":
                    result = left <= right
                elif op == "==":
                    result = left == right
                elif op == "!=":
                    result = left != right
                elif op == ">":
                    result = left > right
                elif op == ">=":
                    result = left >= right
                else:
                    self.state.exception = (NotImplementedError, f"COMPARE_OP {op} not implemented", None)
                    return
                frame.operand_stack.append(result)
            except Exception as e:
                self.state.exception = (type(e), str(e), None)
                return
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "CONTAINS_OP":
            # CONTAINS_OP: item in container (arg=0) or item not in container (arg=1)
            # Stack: [..., item, container] → [..., result]
            if len(frame.operand_stack) < 2:
                self.state.exception = (RuntimeError, "stack underflow", None)
                return
            container = frame.operand_stack.pop()
            item = frame.operand_stack.pop()
            
            invert = instr.arg == 1  # 0 = 'in', 1 = 'not in'
            
            try:
                result = item in container
                if invert:
                    result = not result
                frame.operand_stack.append(result)
            except Exception as e:
                self.state.exception = (type(e), str(e), None)
                return
            frame.instruction_offset = self._next_offset(instr)
        
        elif opname == "EXTENDED_ARG":
            # EXTENDED_ARG is a prefix instruction that extends the argument of the next instruction.
            # dis.get_instructions() already resolves EXTENDED_ARG and includes the combined argument
            # in the arg/argval fields of the following instruction. We simply skip EXTENDED_ARG.
            # Semantically: EXTENDED_ARG does not modify machine state, it only affects bytecode decoding.
            frame.instruction_offset = self._next_offset(instr)
        
        else:
            self.state.exception = (NotImplementedError, f"Opcode {opname} not implemented", None)


def load_and_run(source: str, globals_dict: dict[str, Any] = None) -> MachineState:
    """Convenience function: compile source and run to completion."""
    code = compile(source, "<string>", "eval")
    vm = ConcreteVM()
    vm.load_code(code, globals_dict)
    return vm.run()
