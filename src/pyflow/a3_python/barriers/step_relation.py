"""
Step relation encoding as Z3 constraints.

The transition system model requires:
- State space S (machine states)
- Initial states S0
- Step relation → (nondeterministic)
- Unsafe region U_x ⊆ S per bug type

This module provides explicit Z3 encoding of the step relation s → s'
for use in barrier certificate verification.

Theory:
For a barrier B to be inductive, we need:
  Step: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0

The step relation s → s' represents one bytecode instruction execution,
including all nondeterministic choices (unknown calls, inputs, scheduling).
"""

from dataclasses import dataclass
from typing import Optional, List, Callable
import z3

from ..semantics.symbolic_vm import SymbolicMachineState, SymbolicFrame
from ..z3model.values import SymbolicValue, ValueTag


@dataclass
class StateEncoding:
    """
    Z3 encoding of a symbolic machine state.
    
    Maps state components to Z3 variables/expressions that can be
    used in constraints.
    """
    # Frame locals (map variable name -> Z3 expression)
    locals: dict[str, z3.ExprRef]
    
    # Operand stack (list of Z3 expressions, indexed from bottom)
    stack: List[z3.ExprRef]
    
    # Instruction offset
    offset: z3.ArithRef
    
    # Exception state (optional)
    has_exception: z3.BoolRef
    exception_type: Optional[z3.ExprRef] = None
    
    # Heap size (for resource leak detection)
    heap_size: z3.ArithRef = None
    
    # Path condition (accumulated constraints)
    path_condition: z3.BoolRef = z3.BoolVal(True)
    
    def __post_init__(self):
        if self.heap_size is None:
            self.heap_size = z3.Int('heap_size')


class StepRelationEncoder:
    """
    Encodes the bytecode step relation s → s' as Z3 constraints.
    
    For each bytecode opcode, provides a Z3 formula relating
    pre-state s to post-state s'.
    """
    
    def __init__(self):
        self.opcode_encoders = self._build_opcode_table()
    
    def encode_step(
        self,
        pre_state: StateEncoding,
        post_state: StateEncoding,
        opcode: str,
        arg: Optional[int] = None
    ) -> z3.BoolRef:
        """
        Encode s → s' for a single instruction step.
        
        Args:
            pre_state: Z3 encoding of state before instruction
            post_state: Z3 encoding of state after instruction
            opcode: Bytecode operation name (e.g., 'BINARY_OP')
            arg: Instruction argument (if any)
        
        Returns:
            Z3 boolean constraint: (s → s') for this opcode
        """
        if opcode not in self.opcode_encoders:
            # Unknown opcode: havoc semantics (any post-state possible)
            # This is sound (over-approximation) but imprecise
            return z3.BoolVal(True)
        
        encoder_fn = self.opcode_encoders[opcode]
        return encoder_fn(pre_state, post_state, arg)
    
    def _build_opcode_table(self) -> dict[str, Callable]:
        """Build mapping from opcode names to encoder functions."""
        return {
            'LOAD_CONST': self._encode_load_const,
            'LOAD_FAST': self._encode_load_fast,
            'STORE_FAST': self._encode_store_fast,
            'BINARY_OP': self._encode_binary_op,
            'COMPARE_OP': self._encode_compare_op,
            'POP_JUMP_IF_FALSE': self._encode_pop_jump_if_false,
            'POP_JUMP_IF_TRUE': self._encode_pop_jump_if_true,
            'RETURN_VALUE': self._encode_return_value,
            # More opcodes can be added incrementally
        }
    
    def _encode_load_const(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        LOAD_CONST: push constant onto stack.
        
        Transition:
          stack' = stack + [const]
          locals' = locals
          offset' = offset + instruction_size
          exception' = exception (unchanged)
        """
        # Stack grows by 1
        stack_grows = z3.And(
            len(post.stack) == len(pre.stack) + 1,
            # All previous stack elements unchanged
            z3.And([post.stack[i] == pre.stack[i] for i in range(len(pre.stack))])
            if pre.stack else z3.BoolVal(True)
        )
        
        # Locals unchanged
        locals_unchanged = z3.And([
            post.locals[name] == pre.locals[name]
            for name in pre.locals.keys()
        ]) if pre.locals else z3.BoolVal(True)
        
        # Offset advances (typically by 2 bytes for 3.11+)
        offset_advances = post.offset == pre.offset + 2
        
        # Exception unchanged
        exception_unchanged = post.has_exception == pre.has_exception
        
        return z3.And(
            stack_grows,
            locals_unchanged,
            offset_advances,
            exception_unchanged
        )
    
    def _encode_load_fast(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        LOAD_FAST: push local variable onto stack.
        
        If variable is uninitialized, raises UnboundLocalError.
        """
        # Need variable name from arg (index into co_varnames)
        # For simplicity, assume we're encoding a specific known variable
        # A complete implementation would need the code object context
        
        # Stack grows by 1
        stack_grows = len(post.stack) == len(pre.stack) + 1
        
        # Locals unchanged
        locals_unchanged = z3.And([
            post.locals[name] == pre.locals[name]
            for name in pre.locals.keys()
        ]) if pre.locals else z3.BoolVal(True)
        
        # Offset advances
        offset_advances = post.offset == pre.offset + 2
        
        # Two cases: variable exists vs raises exception
        # For now, assume it exists (complete encoding would branch)
        exception_unchanged = post.has_exception == pre.has_exception
        
        return z3.And(
            stack_grows,
            locals_unchanged,
            offset_advances,
            exception_unchanged
        )
    
    def _encode_store_fast(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        STORE_FAST: pop stack top and store to local variable.
        """
        # Stack shrinks by 1
        stack_shrinks = z3.And(
            len(post.stack) == len(pre.stack) - 1,
            z3.And([post.stack[i] == pre.stack[i] for i in range(len(post.stack))])
            if post.stack else z3.BoolVal(True)
        )
        
        # One local is updated (value from top of pre.stack)
        # Other locals unchanged
        # (Complete encoding would specify which local based on arg)
        
        offset_advances = post.offset == pre.offset + 2
        exception_unchanged = post.has_exception == pre.has_exception
        
        return z3.And(
            stack_shrinks,
            offset_advances,
            exception_unchanged
        )
    
    def _encode_binary_op(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        BINARY_OP: pop two operands, push result.
        
        May raise exception (ZeroDivisionError, TypeError, etc.)
        This is a nondeterministic transition: either succeed or raise.
        """
        # Stack: pop 2, push 1 => net -1
        stack_changes = z3.And(
            len(post.stack) == len(pre.stack) - 1,
            z3.And([post.stack[i] == pre.stack[i] for i in range(len(post.stack))])
            if post.stack else z3.BoolVal(True)
        )
        
        # Locals unchanged
        locals_unchanged = z3.And([
            post.locals[name] == pre.locals[name]
            for name in pre.locals.keys()
        ]) if pre.locals else z3.BoolVal(True)
        
        offset_advances = post.offset == pre.offset + 2
        
        # Two possible outcomes:
        # 1. Success: exception' = False, result on stack
        # 2. Failure: exception' = True, jump to handler
        # Encoding the disjunction makes this nondeterministic
        success_case = z3.And(
            stack_changes,
            locals_unchanged,
            offset_advances,
            z3.Not(post.has_exception)
        )
        
        exception_case = z3.And(
            # Stack may be unchanged or modified depending on exception handling
            locals_unchanged,
            post.has_exception
            # Offset jumps to handler (not encoded here - requires exception table)
        )
        
        return z3.Or(success_case, exception_case)
    
    def _encode_compare_op(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        COMPARE_OP: pop two operands, push boolean result.
        """
        # Similar to BINARY_OP but always pushes bool
        stack_changes = z3.And(
            len(post.stack) == len(pre.stack) - 1,
            z3.And([post.stack[i] == pre.stack[i] for i in range(len(post.stack))])
            if post.stack else z3.BoolVal(True)
        )
        
        locals_unchanged = z3.And([
            post.locals[name] == pre.locals[name]
            for name in pre.locals.keys()
        ]) if pre.locals else z3.BoolVal(True)
        
        offset_advances = post.offset == pre.offset + 2
        exception_unchanged = post.has_exception == pre.has_exception
        
        return z3.And(
            stack_changes,
            locals_unchanged,
            offset_advances,
            exception_unchanged
        )
    
    def _encode_pop_jump_if_false(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        POP_JUMP_IF_FALSE: pop stack, conditionally jump.
        
        This is a nondeterministic transition with two branches:
        - If TOS is false: jump to target
        - If TOS is true: fall through
        """
        # Stack shrinks by 1
        stack_shrinks = z3.And(
            len(post.stack) == len(pre.stack) - 1,
            z3.And([post.stack[i] == pre.stack[i] for i in range(len(post.stack))])
            if post.stack else z3.BoolVal(True)
        )
        
        locals_unchanged = z3.And([
            post.locals[name] == pre.locals[name]
            for name in pre.locals.keys()
        ]) if pre.locals else z3.BoolVal(True)
        
        exception_unchanged = post.has_exception == pre.has_exception
        
        # Two possible offsets (branch or fall-through)
        if arg is not None:
            branch_taken = post.offset == arg
            fall_through = post.offset == pre.offset + 2
            offset_choice = z3.Or(branch_taken, fall_through)
        else:
            offset_choice = z3.BoolVal(True)  # Unknown target
        
        return z3.And(
            stack_shrinks,
            locals_unchanged,
            exception_unchanged,
            offset_choice
        )
    
    def _encode_pop_jump_if_true(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        POP_JUMP_IF_TRUE: pop stack, conditionally jump.
        
        Dual of POP_JUMP_IF_FALSE.
        """
        # Identical structure to POP_JUMP_IF_FALSE
        return self._encode_pop_jump_if_false(pre, post, arg)
    
    def _encode_return_value(
        self,
        pre: StateEncoding,
        post: StateEncoding,
        arg: Optional[int]
    ) -> z3.BoolRef:
        """
        RETURN_VALUE: pop stack, return from function.
        
        Post-state represents function exit (halted or frame popped).
        """
        # Stack top becomes return value
        # Frame is popped (not encoded in StateEncoding currently)
        # For intra-procedural analysis, this is a terminal state
        
        stack_has_value = len(pre.stack) >= 1
        
        # Post-state is "halted" or has return value set
        # (encoding depends on whether we track this explicitly)
        
        return stack_has_value


def encode_initial_state(
    code,
    inputs: dict[str, z3.ExprRef]
) -> StateEncoding:
    """
    Encode initial state S0 for a code object.
    
    Args:
        code: Python code object (types.CodeType)
        inputs: Symbolic input values (map param name -> Z3 variable)
    
    Returns:
        StateEncoding representing the entry point state
    """
    # Initial locals = function parameters (symbolic)
    locals_dict = inputs.copy()
    
    # Empty stack
    stack = []
    
    # Offset = 0 (entry point)
    offset = z3.Int('offset_0')
    offset_constraint = offset == 0
    
    # No exception initially
    has_exception = z3.Bool('has_exception_0')
    exception_constraint = z3.Not(has_exception)
    
    # Empty heap initially (or minimal objects)
    heap_size = z3.Int('heap_size_0')
    heap_constraint = heap_size == 0
    
    encoding = StateEncoding(
        locals=locals_dict,
        stack=stack,
        offset=offset,
        has_exception=has_exception,
        heap_size=heap_size,
        path_condition=z3.And(offset_constraint, exception_constraint, heap_constraint)
    )
    
    return encoding


def encode_unsafe_region(
    state: StateEncoding,
    bug_type: str
) -> z3.BoolRef:
    """
    Encode unsafe region U(σ) for a given bug type.
    
    Args:
        state: Z3 encoding of machine state
        bug_type: One of the 20 bug types (e.g., 'DIV_ZERO', 'ASSERT_FAIL')
    
    Returns:
        Z3 boolean: true iff state is in unsafe region for this bug
    """
    if bug_type == 'DIV_ZERO':
        # Division by zero: second operand on stack is 0
        if len(state.stack) >= 2:
            divisor = state.stack[-1]  # Top of stack
            return divisor == 0
        return z3.BoolVal(False)
    
    elif bug_type == 'ASSERT_FAIL':
        # AssertionError raised and unhandled
        return z3.And(
            state.has_exception,
            # Would need exception type encoding here
        )
    
    elif bug_type == 'BOUNDS':
        # Index out of bounds (would need sequence length encoding)
        return z3.BoolVal(False)  # Placeholder
    
    elif bug_type == 'MEMORY_LEAK':
        # Unbounded heap growth
        # Define threshold (e.g., heap_size > 1000 objects)
        return state.heap_size > 1000
    
    elif bug_type == 'STACK_OVERFLOW':
        # Recursion depth exceeds limit
        # (Would need frame count in StateEncoding)
        return z3.BoolVal(False)  # Placeholder
    
    else:
        # Other bug types not yet encoded
        return z3.BoolVal(False)


def compute_step_relation_formula(
    pre: StateEncoding,
    post: StateEncoding,
    opcode: str,
    arg: Optional[int] = None
) -> z3.BoolRef:
    """
    Helper: compute the step relation formula s → s' for one opcode.
    
    This is the core Z3 constraint used in barrier verification:
      Step: ∀s,s'. (B(s) ≥ 0 ∧ s → s') ⇒ B(s') ≥ 0
    """
    encoder = StepRelationEncoder()
    return encoder.encode_step(pre, post, opcode, arg)
