"""Test BUILD_TUPLE and FORMAT_SIMPLE opcodes."""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath
from a3_python.z3model.values import ValueTag


def test_build_tuple_basic():
    """Test BUILD_TUPLE with simple values."""
    code = """
x = 1
y = 2
t = (x, y)
"""
    vm = SymbolicVM()
    paths = vm.explore_bounded(compile(code, "<test>", "exec"), max_steps=50)
    
    # Should complete without errors
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_tuple_empty():
    """Test BUILD_TUPLE with empty tuple."""
    code = "()"
    vm = SymbolicVM()
    paths = vm.explore_bounded(compile(code, "<test>", "eval"), max_steps=50)
    
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_tuple_three_elements():
    """Test BUILD_TUPLE with three elements."""
    code = """
a = 1
b = 2
c = 3
t = (a, b, c)
"""
    vm = SymbolicVM()
    paths = vm.explore_bounded(compile(code, "<test>", "exec"), max_steps=100)
    
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_format_simple_basic():
    """Test FORMAT_SIMPLE with f-string."""
    code = """
x = 42
s = f"{x}"
"""
    vm = SymbolicVM()
    paths = vm.explore_bounded(compile(code, "<test>", "exec"), max_steps=50)
    
    # Should complete without errors
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_format_simple_variable():
    """Test FORMAT_SIMPLE with variable."""
    code = """
name = "Alice"
greeting = f"{name}"
"""
    vm = SymbolicVM()
    paths = vm.explore_bounded(compile(code, "<test>", "exec"), max_steps=50)
    
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_tuple_and_format():
    """Test combined BUILD_TUPLE and FORMAT_SIMPLE."""
    code = """
x = 1
y = 2
t = (x, y)
s = f"{x}"
"""
    vm = SymbolicVM()
    paths = vm.explore_bounded(compile(code, "<test>", "exec"), max_steps=100)
    
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


