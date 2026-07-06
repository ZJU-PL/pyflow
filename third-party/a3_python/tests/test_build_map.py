"""
Tests for BUILD_MAP opcode semantic correctness.

Validates that BUILD_MAP opcode is implemented according to Python semantics.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_build_map_empty():
    """BUILD_MAP with count=0 creates empty dict."""
    source = "{}"
    code = compile(source, "<test>", "eval")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None
    assert final_path.state.return_value is not None
    assert final_path.state.return_value.tag == ValueTag.DICT


def test_build_map_with_string_keys():
    """BUILD_MAP with string keys and integer values."""
    source = """
x = {"a": 1, "b": 2}
x
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_map_with_variables():
    """BUILD_MAP with variable keys and values."""
    source = """
key1 = "x"
val1 = 10
key2 = "y"
val2 = 20
result = {key1: val1, key2: val2}
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_map_with_integer_keys():
    """BUILD_MAP with integer keys."""
    source = """
d = {1: "one", 2: "two", 3: "three"}
d
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=25)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_map_mixed_types():
    """BUILD_MAP with mixed key types."""
    source = """
d = {1: "int_key", "str": "str_key", 3.14: "float_key"}
d
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_map_single_pair():
    """BUILD_MAP with single key-value pair."""
    source = """
d = {"key": "value"}
d
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=15)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None


def test_build_map_with_computed_values():
    """BUILD_MAP with computed values."""
    source = """
a = 5
b = 10
d = {"sum": a + b, "product": a * b}
d
"""
    code = compile(source, "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=40)
    
    # Should complete without exception
    assert len(paths) > 0
    final_path = paths[0]
    assert final_path.state.exception is None
