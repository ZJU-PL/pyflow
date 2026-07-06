"""
Tests for BUILD_LIST opcode semantic correctness.

Validates that BUILD_LIST opcode is implemented according to Python semantics.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_build_list_empty():
    """BUILD_LIST with count=0 creates empty list."""
    source = "[]"
    code = compile(source, "<test>", "eval")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None
    assert final_path.state.return_value is not None
    assert final_path.state.return_value.tag == ValueTag.LIST


def test_build_list_with_constants():
    """BUILD_LIST with multiple constant items."""
    source = """
x = [1, 2, 3]
x
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_list_with_variables():
    """BUILD_LIST with variable items."""
    source = """
a = 10
b = 20
result = [a, b]
result
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_list_with_mixed_types():
    """BUILD_LIST with different value types."""
    source = """
x = [1, "hello", 3.14]
x
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_list_single_item():
    """BUILD_LIST with single item."""
    source = "[42]"
    code = compile(source, "<test>", "eval")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None
    assert final_path.state.return_value is not None


def test_build_list_nested():
    """BUILD_LIST with nested list."""
    source = """
inner = [1, 2]
outer = [inner, 3]
outer
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=40)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_list_multiple_lists():
    """Multiple BUILD_LIST operations."""
    source = """
list1 = [1, 2]
list2 = [3, 4]
list3 = [5, 6]
list3
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None
