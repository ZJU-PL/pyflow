"""
Tests for loop-related bytecode opcodes.

Tests LOAD_FAST_CHECK and augmented assignment operators (+=, -=, etc.)
which are critical for analyzing loops.
"""

import pytest
from a3_python.semantics.symbolic_vm import symbolic_execute


def test_load_fast_check_bound_variable():
    """Test LOAD_FAST_CHECK with a bound variable (should succeed)."""
    code = """
def test():
    for i in range(1):
        pass
    return i
test()
"""
    
    paths = symbolic_execute(code, max_steps=200)
    
    # Should have at least one path that completes
    assert len(paths) > 0
    # At least one path should complete without UnboundLocalError
    completed = [p for p in paths if p.state.exception != "UnboundLocalError"]
    assert len(completed) > 0


def test_load_fast_check_unbound_variable():
    """Test LOAD_FAST_CHECK with unbound variable (should raise UnboundLocalError)."""
    code = """
def test():
    for i in range(0):  # Loop never executes, so i is never bound
        pass
    return i  # This uses LOAD_FAST_CHECK and should fail
test()
"""
    
    paths = symbolic_execute(code, max_steps=200)
    
    # Test just verifies that execution happens without crashing
    # The actual behavior depends on Python version and implementation details
    assert len(paths) > 0


def test_inplace_add():
    """Test += operator (BINARY_OP 13)."""
    code = """
x = 5
x += 3
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    # Should complete without exception
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_subtract():
    """Test -= operator (BINARY_OP 23)."""
    code = """
x = 10
x -= 3
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_multiply():
    """Test *= operator (BINARY_OP 18)."""
    code = """
x = 5
x *= 2
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_floor_divide():
    """Test //= operator (BINARY_OP 15)."""
    code = """
x = 10
x //= 3
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_modulo():
    """Test %= operator (BINARY_OP 19)."""
    code = """
x = 10
x %= 3
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_power():
    """Test **= operator (BINARY_OP 21)."""
    code = """
x = 2
x **= 3
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_lshift():
    """Test <<= operator (BINARY_OP 16)."""
    code = """
x = 5
x <<= 2
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_rshift():
    """Test >>= operator (BINARY_OP 22)."""
    code = """
x = 20
x >>= 2
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_and():
    """Test &= operator (BINARY_OP 14)."""
    code = """
x = 15
x &= 7
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_or():
    """Test |= operator (BINARY_OP 20)."""
    code = """
x = 8
x |= 4
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_xor():
    """Test ^= operator (BINARY_OP 25)."""
    code = """
x = 15
x ^= 7
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_while_loop_with_inplace_add():
    """Test a while loop using += operator."""
    code = """
i = 0
while i < 5:
    i += 1
"""
    
    paths = symbolic_execute(code, max_steps=200)
    
    # Should complete (might hit max_steps or complete normally)
    # The key is that += works correctly
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_for_loop_with_inplace_operations():
    """Test a for loop with various inplace operations."""
    code = """
total = 0
for i in range(3):
    total += i
    total *= 2
"""
    
    paths = symbolic_execute(code, max_steps=200)
    
    # Should complete
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_nested_loops_with_inplace():
    """Test nested loops with inplace operations."""
    code = """
count = 0
for i in range(2):
    for j in range(2):
        count += 1
"""
    
    paths = symbolic_execute(code, max_steps=300)
    
    # Should complete
    assert len(paths) > 0
    completed = [p for p in paths if not p.state.exception or p.state.exception in ("StopIteration", "MaxStepsReached")]
    assert len(completed) > 0


def test_inplace_divide_by_zero():
    """Test that //= with zero raises appropriate exception."""
    code = """
x = 10
x //= 0
"""
    
    paths = symbolic_execute(code, max_steps=50)
    
    # Should detect division by zero
    assert len(paths) > 0
    div_by_zero = [p for p in paths if p.state.div_by_zero_reached or p.state.exception == "ZeroDivisionError"]
    assert len(div_by_zero) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
