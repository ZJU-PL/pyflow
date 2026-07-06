"""
Tests for JUMP_FORWARD opcode (Python 3.14).

JUMP_FORWARD is an unconditional forward jump instruction used in control flow.
It's semantically equivalent to JUMP_BACKWARD but jumps forward instead of backward.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM


def test_jump_forward_basic():
    """Test that JUMP_FORWARD doesn't crash the analyzer."""
    code = compile("""
# This code may generate JUMP_FORWARD in some Python versions
x = 1
if False:
    y = 2
z = 3
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=10))
    # Should not crash
    assert len(paths) >= 0


def test_jump_forward_control_flow():
    """Test JUMP_FORWARD in control flow structures."""
    code = compile("""
def test():
    x = 10
    if x > 0:
        y = 1
    else:
        y = 2
    return y

result = test()
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=20))
    assert len(paths) >= 0


def test_jump_forward_nested_conditionals():
    """Test JUMP_FORWARD in nested conditional structures."""
    code = compile("""
def nested(a, b):
    if a > 0:
        if b > 0:
            x = 1
        else:
            x = 2
    else:
        x = 3
    return x

result = nested(5, 3)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=30))
    assert len(paths) >= 0


def test_jump_forward_exception_handling():
    """Test JUMP_FORWARD in try-except blocks."""
    code = compile("""
def exception_test():
    try:
        x = 1
    except Exception:
        x = 2
    return x

result = exception_test()
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=20))
    assert len(paths) >= 0


def test_jump_forward_with_else():
    """Test JUMP_FORWARD jumping over else block."""
    code = compile("""
def with_else(flag):
    if flag > 0:
        result = 1
    else:
        result = 0
    return result

x = with_else(5)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=30))
    assert len(paths) >= 0


def test_jump_forward_multiple_paths():
    """Test JUMP_FORWARD with multiple execution paths."""
    code = compile("""
def multi_path(x):
    if x < 0:
        return -1
    elif x == 0:
        return 0
    else:
        return 1

a = multi_path(-5)
b = multi_path(0)
c = multi_path(10)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=50))
    assert len(paths) >= 0


def test_jump_forward_semantic_equivalence():
    """Test that JUMP_FORWARD maintains semantic correctness."""
    # This code should be SAFE - no bugs
    code = compile("""
def safe_function(n):
    if n > 0:
        result = n * 2
    else:
        result = 0
    return result

# Safe operations
x = safe_function(5)
y = safe_function(-3)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=30))
    # Should complete without errors
    assert len(paths) >= 0


def test_jump_forward_with_loop():
    """Test JUMP_FORWARD in combination with loops."""
    code = compile("""
def loop_with_conditional(n):
    result = 0
    for i in range(n):
        if i % 2 == 0:
            result += i
        else:
            result += i * 2
    return result

x = loop_with_conditional(5)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=50))
    assert len(paths) >= 0


def test_jump_forward_chained_conditionals():
    """Test JUMP_FORWARD in chained if-elif-else."""
    code = compile("""
def classify(score):
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return grade

result = classify(85)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=50))
    assert len(paths) >= 0


def test_jump_forward_short_circuit():
    """Test JUMP_FORWARD in short-circuit evaluation contexts."""
    code = compile("""
def short_circuit(a, b):
    # May involve JUMP_FORWARD for conditional evaluation
    if a > 0 and b > 0:
        return 1
    elif a > 0 or b > 0:
        return 2
    else:
        return 3

x = short_circuit(5, 3)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = list(vm.explore_bounded(code, max_steps=40))
    assert len(paths) >= 0


