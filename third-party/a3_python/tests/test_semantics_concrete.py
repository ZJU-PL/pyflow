"""
Golden tests: differential testing of concrete VM vs CPython.

Each test compares the concrete VM's result against CPython's actual execution.
"""

import pytest
from a3_python.semantics.concrete_vm import ConcreteVM, load_and_run


def test_simple_constant():
    """Test: Load a constant and return it."""
    source = "42"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 42
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_simple_addition():
    """Test: Simple binary addition."""
    source = "3 + 5"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 8
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_subtraction():
    """Test: Simple binary subtraction."""
    source = "10 - 3"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 7
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_multiplication():
    """Test: Simple binary multiplication."""
    source = "6 * 7"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 42
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_division():
    """Test: Simple binary division."""
    source = "15 / 3"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 5.0
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_division_by_zero():
    """Test: Division by zero raises ZeroDivisionError."""
    source = "1 / 0"
    
    state = load_and_run(source)
    
    assert state.exception is not None
    exc_type, exc_msg, _ = state.exception
    assert exc_type == ZeroDivisionError
    
    with pytest.raises(ZeroDivisionError):
        eval(source)


def test_compound_expression():
    """Test: More complex arithmetic expression."""
    source = "(2 + 3) * 4"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 20
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_comparison_less_than():
    """Test: Less-than comparison."""
    source = "3 < 5"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value is True
    assert state.exception is None
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_comparison_greater_than():
    """Test: Greater-than comparison."""
    source = "5 > 3"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value is True
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_comparison_equality():
    """Test: Equality comparison."""
    source = "5 == 5"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value is True
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_modulo():
    """Test: Modulo operation."""
    source = "17 % 5"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 2
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_floor_division():
    """Test: Floor division."""
    source = "17 // 5"
    
    state = load_and_run(source)
    
    assert state.halted
    assert state.return_value == 3
    
    cpython_result = eval(source)
    assert state.return_value == cpython_result


def test_modulo_by_zero():
    """Test: Modulo by zero raises ZeroDivisionError."""
    source = "5 % 0"
    
    state = load_and_run(source)
    
    assert state.exception is not None
    exc_type, _, _ = state.exception
    assert exc_type == ZeroDivisionError
    
    with pytest.raises(ZeroDivisionError):
        eval(source)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
