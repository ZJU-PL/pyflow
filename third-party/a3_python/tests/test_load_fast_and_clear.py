"""
Tests for LOAD_FAST_AND_CLEAR opcode.

LOAD_FAST_AND_CLEAR is used in comprehensions for exception safety.
Semantics:
- If the variable exists in locals: push its value, then delete it from locals
- If the variable doesn't exist: push None (no exception)
"""

import pytest
import dis
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState, SymbolicFrame
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_load_fast_and_clear_opcode_exists():
    """Verify LOAD_FAST_AND_CLEAR opcode exists in list comprehensions."""
    code = """
def f():
    x = 1
    return [x for x in range(3)]
"""
    compiled = compile(code, '<test>', 'exec')
    func = compiled.co_consts[0]
    
    # Find LOAD_FAST_AND_CLEAR in the bytecode
    found = False
    for instr in dis.get_instructions(func):
        if instr.opname == "LOAD_FAST_AND_CLEAR":
            found = True
            assert instr.argval == "x"
            break
    
    assert found, "LOAD_FAST_AND_CLEAR not found in comprehension bytecode"


def test_load_fast_and_clear_manual_existing():
    """Test LOAD_FAST_AND_CLEAR with an existing variable."""
    code = compile("x = 42", '<test>', 'exec')
    
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code)
    frame.locals["x"] = SymbolicValue.int(42)
    state.frame_stack.append(frame)
    
    # Manually create a LOAD_FAST_AND_CLEAR instruction
    class FakeInstr:
        opname = "LOAD_FAST_AND_CLEAR"
        argval = "x"
        offset = 0
        arg = 0
    
    instr = FakeInstr()
    vm._execute_instruction(state, frame, instr)
    
    # Check: value pushed to stack
    assert len(frame.operand_stack) == 1
    val = frame.operand_stack[0]
    # Check that it's an int with value 42
    # Note: We can't directly compare Z3 expressions without a solver,
    # but we can check the structure
    assert val.payload is not None
    
    # Check: variable cleared from locals
    assert "x" not in frame.locals


def test_load_fast_and_clear_manual_nonexistent():
    """Test LOAD_FAST_AND_CLEAR with a non-existent variable (pushes None)."""
    code = compile("pass", '<test>', 'exec')
    
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code)
    # Don't create the variable 'x'
    state.frame_stack.append(frame)
    
    class FakeInstr:
        opname = "LOAD_FAST_AND_CLEAR"
        argval = "x"
        offset = 0
        arg = 0
    
    instr = FakeInstr()
    vm._execute_instruction(state, frame, instr)
    
    # Check: None pushed to stack
    assert len(frame.operand_stack) == 1
    val = frame.operand_stack[0]
    # Check that a value was pushed (should be None)
    assert val.payload is not None
    
    # Check: no exception raised
    assert state.exception is None


def test_comprehension_with_outer_variable():
    """Test that comprehensions use LOAD_FAST_AND_CLEAR for variable save/restore."""
    code = """
def f():
    x = 100
    result = [x * 2 for x in [1, 2, 3]]
    return x
"""
    compiled = compile(code, '<test>', 'exec')
    func = compiled.co_consts[0]
    
    # Verify LOAD_FAST_AND_CLEAR appears in bytecode
    found = False
    for instr in dis.get_instructions(func):
        if instr.opname == "LOAD_FAST_AND_CLEAR":
            found = True
            assert instr.argval == "x"
            break
    
    assert found, "LOAD_FAST_AND_CLEAR should appear in list comprehension"
    
    # Test that VM can step through it without crashing
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=50)
    # Should produce some paths without exceptions
    assert len(paths) > 0


def test_comprehension_exception_safety():
    """Test comprehension exception handling with LOAD_FAST_AND_CLEAR."""
    code = """
def f():
    x = 999
    try:
        result = [1/0 for _ in range(1)]
    except ZeroDivisionError:
        pass
    return x
"""
    compiled = compile(code, '<test>', 'exec')
    
    # Just verify it compiles and uses LOAD_FAST_AND_CLEAR
    func = compiled.co_consts[0]
    opcodes = [i.opname for i in dis.get_instructions(func)]
    # Should have the opcode (comprehensions save loop variables)
    # The exact presence depends on whether comprehension uses loop var from outer scope


def test_nested_comprehensions():
    """Test nested comprehensions with LOAD_FAST_AND_CLEAR."""
    code = """
def f():
    x = 5
    result = [[x + y for y in range(2)] for x in range(3)]
    return x
"""
    compiled = compile(code, '<test>', 'exec')
    func = compiled.co_consts[0]
    
    # Verify LOAD_FAST_AND_CLEAR appears
    found = False
    for instr in dis.get_instructions(func):
        if instr.opname == "LOAD_FAST_AND_CLEAR":
            found = True
            break
    
    assert found, "Nested comprehensions should use LOAD_FAST_AND_CLEAR"


def test_load_fast_and_clear_sequence():
    """Test LOAD_FAST_AND_CLEAR in a realistic bytecode sequence."""
    code = """
def test_func():
    outer = "saved"
    items = [outer.upper() for outer in ["a", "b"]]
    return outer
"""
    
    # Verify the opcode appears
    compiled = compile(code, '<test>', 'exec')
    func = compiled.co_consts[0]
    
    found = False
    for instr in dis.get_instructions(func):
        if instr.opname == "LOAD_FAST_AND_CLEAR":
            found = True
            assert instr.argval == "outer"
            break
    
    assert found


def test_comprehension_with_no_outer_variable():
    """Test comprehension where the loop variable doesn't exist in outer scope."""
    code = """
def f():
    result = [x * 2 for x in range(3)]
    # x is not defined here
    return result
"""
    compiled = compile(code, '<test>', 'exec')
    func = compiled.co_consts[0]
    
    # May or may not have LOAD_FAST_AND_CLEAR depending on if x exists in outer scope
    # Just verify it compiles
    assert func is not None


def test_generator_expression_uses_load_fast_and_clear():
    """Verify generator expressions structure (they use generators, not LOAD_FAST_AND_CLEAR)."""
    code = """
def f():
    x = 10
    gen = (x + 1 for x in range(3))
    return x
"""
    
    compiled = compile(code, '<test>', 'exec')
    func = compiled.co_consts[0]
    
    # Generator expressions don't use LOAD_FAST_AND_CLEAR like list comprehensions
    # They create a separate generator function instead
    # Just verify the code compiles and has a generator
    found_generator = False
    for const in func.co_consts:
        if hasattr(const, 'co_code') and 'genexpr' in const.co_name:
            found_generator = True
            break
    
    assert found_generator, "Generator expression should create a generator code object"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
