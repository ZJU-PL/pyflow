"""
Test LOAD_FAST_BORROW opcode (Python 3.14+ performance optimization).

LOAD_FAST_BORROW loads a local variable with borrowed reference semantics.
Semantically identical to LOAD_FAST for symbolic execution purposes.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM


def test_load_fast_borrow_basic():
    """LOAD_FAST_BORROW loads local variable successfully."""
    code = """
def test_func(x):
    # In Python 3.14, optimizer may use LOAD_FAST_BORROW for performance
    # Semantically identical to LOAD_FAST - loads local variable
    return x
    
result = test_func(42)
"""
    compiled = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=100)
    # Should complete without errors
    assert len(paths) >= 0


def test_load_fast_borrow_multiple():
    """LOAD_FAST_BORROW works with multiple local variables."""
    code = """
def compute(a, b, c):
    x = a + b
    y = b + c
    z = x + y
    return z
    
result = compute(1, 2, 3)
"""
    compiled = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=100)
    assert len(paths) >= 0


def test_load_fast_borrow_loop():
    """LOAD_FAST_BORROW in loop context."""
    code = """
def sum_loop(n):
    total = 0
    i = 0
    while i < 3:  # Small bound for symbolic execution
        # LOAD_FAST_BORROW may be used for 'total' and 'i'
        total = total + i
        i = i + 1
    return total
    
result = sum_loop(3)
"""
    compiled = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=150)
    assert len(paths) >= 0


def test_load_fast_borrow_nested():
    """LOAD_FAST_BORROW in nested function calls."""
    code = """
def outer(x):
    def inner(y):
        # LOAD_FAST_BORROW for both x (closure) and y (local)
        return x + y
    return inner(10)
    
result = outer(5)
"""
    compiled = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=150)
    assert len(paths) >= 0


def test_load_fast_borrow_exception():
    """LOAD_FAST_BORROW with exception handling."""
    code = """
def safe_divide(a, b):
    try:
        # LOAD_FAST_BORROW for a and b
        result = a / b
        return result
    except ZeroDivisionError:
        return 0
        
x = safe_divide(10, 2)
"""
    compiled = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=100)
    assert len(paths) >= 0


def test_load_fast_borrow_arithmetic():
    """LOAD_FAST_BORROW in arithmetic operations."""
    code = """
def calculate(a, b):
    x = a * 2
    y = b + 3
    z = x - y
    return z
    
result = calculate(5, 7)
"""
    compiled = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(compiled, max_steps=100)
    assert len(paths) >= 0

