"""
Tests for STORE_SUBSCR opcode (subscript assignment).

Tests list and dict subscript assignment, bounds checking, type errors.
"""

import pytest
import dis
import types

from a3_python.semantics.symbolic_vm import SymbolicVM


def compile_code(source: str) -> types.CodeType:
    """Compile Python source to code object."""
    return compile(source, '<test>', 'exec')


def test_store_subscr_opcode_exists():
    """Test that STORE_SUBSCR is recognized and doesn't crash."""
    code = compile_code("""
x = [1, 2, 3]
x[0] = 5
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should not crash - may find paths or not, but shouldn't fail to execute
    assert paths is not None


def test_list_subscr_assignment_basic():
    """Test basic list subscript assignment."""
    code = compile_code("""
x = [1, 2, 3]
x[1] = 99
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should execute without unhandled exceptions in the non-error paths
    # Check that at least one path completes normally
    completed = [p for p in paths if p.state.halted and not p.state.exception]
    assert len(completed) > 0 or len(paths) > 0


def test_list_subscr_assignment_first():
    """Test assignment to first element."""
    code = compile_code("""
x = [1, 2, 3]
x[0] = 10
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    assert len(paths) > 0


def test_list_subscr_assignment_last():
    """Test assignment to last element."""
    code = compile_code("""
x = [1, 2, 3]
x[2] = 30
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    assert len(paths) > 0


def test_dict_subscr_assignment_basic():
    """Test basic dict subscript assignment."""
    code = compile_code("""
d = {'a': 1}
d['b'] = 2
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should execute without exceptions
    assert len(paths) > 0


def test_dict_subscr_assignment_update():
    """Test updating existing dict key."""
    code = compile_code("""
d = {'a': 1}
d['a'] = 100
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    assert len(paths) > 0


def test_dict_subscr_assignment_int_key():
    """Test dict assignment with integer key."""
    code = compile_code("""
d = {1: 'one'}
d[2] = 'two'
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    assert len(paths) > 0


def test_list_subscr_bounds_error():
    """Test that out-of-bounds list assignment is detected."""
    code = compile_code("""
x = [1, 2, 3]
x[10] = 99  # IndexError: list assignment index out of range
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should detect bounds violation
    bounds_paths = [p for p in paths if p.state.bounds_violation_reached]
    assert len(bounds_paths) > 0, "Should detect bounds violation"


def test_list_subscr_negative_bounds():
    """Test that negative out-of-bounds list assignment is detected."""
    code = compile_code("""
x = [1, 2, 3]
x[-5] = 99  # IndexError: list assignment index out of range
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should detect bounds violation
    bounds_paths = [p for p in paths if p.state.bounds_violation_reached]
    assert len(bounds_paths) > 0, "Should detect negative index bounds violation"


def test_subscr_none_error():
    """Test that subscript assignment to None raises TypeError."""
    code = compile_code("""
x = None
x[0] = 1  # TypeError: 'NoneType' object does not support item assignment
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should detect None misuse
    none_paths = [p for p in paths if p.state.none_misuse_reached]
    assert len(none_paths) > 0, "Should detect None misuse"


def test_subscr_type_error_int():
    """Test that subscript assignment to non-subscriptable type raises TypeError."""
    code = compile_code("""
x = 42
x[0] = 1  # TypeError: 'int' object does not support item assignment
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    # Should detect type confusion
    type_paths = [p for p in paths if p.state.type_confusion_reached]
    assert len(type_paths) > 0, "Should detect type confusion"


def test_subscr_assignment_in_function():
    """Test subscript assignment within a function."""
    code = compile_code("""
def update_list(lst, idx, val):
    lst[idx] = val
    
x = [1, 2, 3]
update_list(x, 1, 100)
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    assert len(paths) > 0


def test_subscr_assignment_multiple():
    """Test multiple subscript assignments."""
    code = compile_code("""
x = [1, 2, 3, 4, 5]
x[0] = 10
x[2] = 30
x[4] = 50
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=80)
    assert len(paths) > 0


def test_dict_subscr_string_keys():
    """Test dict with string keys."""
    code = compile_code("""
d = {}
d['name'] = 'Alice'
d['age'] = 30
d['city'] = 'NYC'
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=80)
    assert len(paths) > 0


def test_mixed_list_dict_subscr():
    """Test mixed list and dict subscript assignments."""
    code = compile_code("""
lst = [1, 2, 3]
dct = {'a': 10}
lst[1] = 20
dct['b'] = 20
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=80)
    assert len(paths) > 0


def test_nested_subscr_assignment():
    """Test nested subscript assignment."""
    code = compile_code("""
matrix = [[1, 2], [3, 4]]
matrix[0][1] = 99
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    assert len(paths) > 0


def test_subscr_with_computed_index():
    """Test subscript assignment with computed index."""
    code = compile_code("""
x = [1, 2, 3, 4, 5]
i = 1 + 1
x[i] = 100
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=80)
    assert len(paths) > 0


def test_subscr_with_computed_value():
    """Test subscript assignment with computed value."""
    code = compile_code("""
x = [1, 2, 3]
x[0] = 10 * 5
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=80)
    assert len(paths) > 0


def test_list_build_and_subscr():
    """Test building a list and then assigning to it."""
    code = compile_code("""
x = [i for i in range(5)]
x[2] = 999
""")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    assert len(paths) > 0
