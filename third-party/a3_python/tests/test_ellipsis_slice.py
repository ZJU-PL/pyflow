"""
Test LOAD_CONST support for ellipsis and slice objects.

These types were identified as missing during DSE validation (iteration 55).
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM


def test_ellipsis_constant():
    """Test that ellipsis can be loaded as a constant."""
    code = compile("""
x = ...
""", "<string>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should not crash with NotImplementedError
    assert len(paths) > 0
    # Should complete without exception
    assert not any(p.state.exception for p in paths)


def test_slice_constant_in_subscript():
    """Test that slice objects in subscripts work."""
    code = compile("""
lst = [1, 2, 3, 4, 5]
result = lst[1:3]
""", "<string>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should not crash with NotImplementedError
    assert len(paths) > 0


def test_slice_with_step():
    """Test that slice objects with step work."""
    code = compile("""
lst = [1, 2, 3, 4, 5, 6]
result = lst[::2]
""", "<string>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should not crash with NotImplementedError
    assert len(paths) > 0


def test_slice_negative_indices():
    """Test that slice objects with negative indices work."""
    code = compile("""
lst = [1, 2, 3, 4, 5]
result = lst[-3:-1]
""", "<string>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should not crash with NotImplementedError
    assert len(paths) > 0

