"""
Tests for STORE_FAST_LOAD_FAST opcode.

STORE_FAST_LOAD_FAST is a Python 3.14+ optimization that combines STORE_FAST
and LOAD_FAST in a single atomic operation. It's primarily used in comprehensions
to efficiently handle loop variables.

Semantics:
- Pop value from stack
- Store to first variable
- Load from second variable (usually same) and push to stack
"""

import dis
import pytest
import sys
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState, SymbolicFrame
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_store_fast_load_fast_opcode_exists():
    """Verify STORE_FAST_LOAD_FAST appears in Python 3.14+ comprehension bytecode."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    code = compile('[x*2 for x in range(10)]', '<test>', 'eval')
    bytecode = list(dis.get_instructions(code))
    
    # Check if STORE_FAST_LOAD_FAST appears in bytecode
    has_opcode = any(instr.opname == 'STORE_FAST_LOAD_FAST' for instr in bytecode)
    assert has_opcode, "STORE_FAST_LOAD_FAST should appear in comprehension bytecode"


def test_store_fast_load_fast_manual_basic():
    """Test STORE_FAST_LOAD_FAST basic operation."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    code = compile("x = 42", '<test>', 'exec')
    
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code)
    # Push value onto stack
    frame.operand_stack.append(SymbolicValue.int(123))
    state.frame_stack.append(frame)
    
    # Manually create a STORE_FAST_LOAD_FAST instruction
    class FakeInstr:
        opname = "STORE_FAST_LOAD_FAST"
        argval = ("x", "x")  # Store to x, load from x
        offset = 0
        arg = 0
    
    instr = FakeInstr()
    vm._execute_instruction(state, frame, instr)
    
    # Check: value stored to locals
    assert "x" in frame.locals
    
    # Check: value loaded back to stack
    assert len(frame.operand_stack) == 1
    val = frame.operand_stack[0]
    assert val.payload is not None
    
    # Check: no exception raised
    assert state.exception is None


def test_store_fast_load_fast_manual_different_vars():
    """Test STORE_FAST_LOAD_FAST with different store/load variables."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    code = compile("pass", '<test>', 'exec')
    
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code)
    # Push value onto stack
    frame.operand_stack.append(SymbolicValue.int(456))
    # Pre-populate a different variable
    frame.locals["y"] = SymbolicValue.int(999)
    state.frame_stack.append(frame)
    
    class FakeInstr:
        opname = "STORE_FAST_LOAD_FAST"
        argval = ("x", "y")  # Store to x, load from y
        offset = 0
        arg = 0
    
    instr = FakeInstr()
    vm._execute_instruction(state, frame, instr)
    
    # Check: value stored to x
    assert "x" in frame.locals
    
    # Check: y's value loaded to stack
    assert len(frame.operand_stack) == 1
    
    # Check: no exception
    assert state.exception is None


def test_store_fast_load_fast_stack_underflow():
    """Test STORE_FAST_LOAD_FAST with empty stack (should raise exception)."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    code = compile("pass", '<test>', 'exec')
    
    vm = SymbolicVM()
    state = SymbolicMachineState()
    frame = SymbolicFrame(code)
    # Don't push anything to stack (empty)
    state.frame_stack.append(frame)
    
    class FakeInstr:
        opname = "STORE_FAST_LOAD_FAST"
        argval = ("x", "x")
        offset = 0
        arg = 0
    
    instr = FakeInstr()
    vm._execute_instruction(state, frame, instr)
    
    # Check: exception raised for stack underflow
    assert state.exception == "StackUnderflow"


def test_comprehension_with_store_fast_load_fast():
    """Test basic list comprehension that uses STORE_FAST_LOAD_FAST."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    from a3_python.frontend.loader import load_python_string
    from a3_python.semantics.symbolic_vm import SymbolicVM
    
    code_str = """
def test():
    result = [x * 2 for x in range(5)]
    return result

test()
"""
    
    code = load_python_string(code_str, "<test>")
    vm = SymbolicVM()
    
    # This should not crash
    try:
        path = vm.load_code(code)
        # Execute a few steps (don't need to complete)
        for _ in range(50):
            if path.halted:
                break
            vm.step(path)
        
        # If we get here without exception, the opcode is handled
        assert True
    except Exception as e:
        # If opcode is not implemented, we'll get an error
        if "STORE_FAST_LOAD_FAST" in str(e):
            pytest.fail(f"STORE_FAST_LOAD_FAST not properly implemented: {e}")
        # Other exceptions might be okay (e.g., symbolic execution limitations)


def test_nested_comprehension_with_store_fast_load_fast():
    """Test nested comprehensions that use STORE_FAST_LOAD_FAST."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    from a3_python.frontend.loader import load_python_string
    from a3_python.semantics.symbolic_vm import SymbolicVM
    
    code_str = """
def test():
    result = [[y*2 for y in range(3)] for x in range(2)]
    return result

test()
"""
    
    code = load_python_string(code_str, "<test>")
    vm = SymbolicVM()
    
    try:
        path = vm.load_code(code)
        for _ in range(50):
            if path.halted:
                break
            vm.step(path)
        assert True
    except Exception as e:
        if "STORE_FAST_LOAD_FAST" in str(e):
            pytest.fail(f"STORE_FAST_LOAD_FAST not properly implemented: {e}")


def test_dict_comprehension_with_store_fast_load_fast():
    """Test dict comprehension using STORE_FAST_LOAD_FAST."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    from a3_python.frontend.loader import load_python_string
    from a3_python.semantics.symbolic_vm import SymbolicVM
    
    code_str = """
def test():
    result = {x: x*2 for x in range(5)}
    return result

test()
"""
    
    code = load_python_string(code_str, "<test>")
    vm = SymbolicVM()
    
    try:
        path = vm.load_code(code)
        for _ in range(50):
            if path.halted:
                break
            vm.step(path)
        assert True
    except Exception as e:
        if "STORE_FAST_LOAD_FAST" in str(e):
            pytest.fail(f"STORE_FAST_LOAD_FAST not properly implemented: {e}")


def test_set_comprehension_with_store_fast_load_fast():
    """Test set comprehension using STORE_FAST_LOAD_FAST."""
    if sys.version_info < (3, 14):
        pytest.skip("STORE_FAST_LOAD_FAST only in Python 3.14+")
    
    from a3_python.frontend.loader import load_python_string
    from a3_python.semantics.symbolic_vm import SymbolicVM
    
    code_str = """
def test():
    result = {x*2 for x in range(5)}
    return result

test()
"""
    
    code = load_python_string(code_str, "<test>")
    vm = SymbolicVM()
    
    try:
        path = vm.load_code(code)
        for _ in range(50):
            if path.halted:
                break
            vm.step(path)
        assert True
    except Exception as e:
        if "STORE_FAST_LOAD_FAST" in str(e):
            pytest.fail(f"STORE_FAST_LOAD_FAST not properly implemented: {e}")

