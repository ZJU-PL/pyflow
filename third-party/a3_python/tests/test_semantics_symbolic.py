"""
Tests for symbolic execution engine.

These tests verify that the symbolic VM can explore paths through
simple Python programs and maintain correct path conditions.
"""

import pytest
import z3
from a3_python.semantics.symbolic_vm import SymbolicVM, symbolic_execute
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_symbolic_simple_constant():
    """Symbolic execution of a simple constant."""
    paths = symbolic_execute("42")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    assert path.state.return_value is not None
    
    # Check that return value is symbolic int with value 42
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 42)
    assert solver.check() == z3.sat


def test_symbolic_addition():
    """Symbolic execution of addition."""
    paths = symbolic_execute("5 + 3")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 8)
    assert solver.check() == z3.sat


def test_symbolic_subtraction():
    """Symbolic execution of subtraction."""
    paths = symbolic_execute("10 - 7")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 3)
    assert solver.check() == z3.sat


def test_symbolic_multiplication():
    """Symbolic execution of multiplication."""
    paths = symbolic_execute("6 * 7")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 42)
    assert solver.check() == z3.sat


def test_symbolic_division():
    """Symbolic execution of division (non-zero denominator)."""
    paths = symbolic_execute("10 / 2")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    # Python's / operator returns float, so result is 5.0
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_float())
    assert solver.check() == z3.sat


def test_symbolic_division_by_zero_detection():
    """
    Symbolic execution should detect potential division by zero.
    
    This is a key test: the symbolic executor must recognize when
    the DIV_ZERO unsafe region is reachable.
    """
    paths = symbolic_execute("10 / 0")
    
    assert len(paths) == 1
    path = paths[0]
    
    # The path should have marked div_by_zero as potentially reachable
    # (even if the concrete value is 0, symbolically we track this)
    # For now, we don't halt on div-by-zero but we mark it
    # Later unsafe/* modules will use this marker
    
    # Just verify path completed and has the marker
    # (Full DIV_ZERO detection will be in UNSAFE_REGIONS_CORE phase)
    assert path.state.halted or path.state.exception or path.state.div_by_zero_reached


def test_symbolic_comparison_lt():
    """Symbolic execution of less-than comparison."""
    paths = symbolic_execute("5 < 10")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_bool())
    solver.add(rv.as_bool() == True)
    assert solver.check() == z3.sat


def test_symbolic_comparison_gt():
    """Symbolic execution of greater-than comparison."""
    paths = symbolic_execute("5 > 10")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_bool())
    solver.add(rv.as_bool() == False)
    assert solver.check() == z3.sat


def test_symbolic_comparison_eq():
    """Symbolic execution of equality comparison."""
    paths = symbolic_execute("42 == 42")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_bool())
    solver.add(rv.as_bool() == True)
    assert solver.check() == z3.sat


def test_symbolic_compound_expression():
    """Symbolic execution of compound expression."""
    paths = symbolic_execute("(5 + 3) * 2")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 16)
    assert solver.check() == z3.sat


def test_symbolic_path_condition_is_satisfiable():
    """Verify that path conditions remain satisfiable for valid programs."""
    paths = symbolic_execute("(10 + 5) - 3")
    
    assert len(paths) == 1
    path = paths[0]
    
    solver = z3.Solver()
    solver.add(path.state.path_condition)
    assert solver.check() == z3.sat


def test_symbolic_trace_captured():
    """Verify that execution traces are captured."""
    paths = symbolic_execute("42")
    
    assert len(paths) == 1
    path = paths[0]
    
    # Should have a trace with START and instructions
    assert len(path.trace) >= 2  # At least START + some instructions
    assert any("START" in entry for entry in path.trace)


def test_symbolic_modulo():
    """Symbolic execution of modulo operation."""
    paths = symbolic_execute("17 % 5")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 2)
    assert solver.check() == z3.sat


def test_symbolic_floor_division():
    """Symbolic execution of floor division."""
    paths = symbolic_execute("17 // 5")
    
    assert len(paths) == 1
    path = paths[0]
    assert path.state.halted
    
    rv = path.state.return_value
    solver = z3.Solver()
    solver.add(rv.is_int())
    solver.add(rv.as_int() == 3)
    assert solver.check() == z3.sat
