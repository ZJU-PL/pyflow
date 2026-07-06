"""
Test IS_OP opcode for identity comparisons.
"""
import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.z3model.values import ValueTag


def test_is_op_none_true():
    """Test 'x is None' when x is None."""
    code = compile("""
x = None
result = (x is None)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without exception
    assert any(not p.state.exception for p in paths)


def test_is_op_none_false():
    """Test 'x is None' when x is not None."""
    code = compile("""
x = 5
result = (x is None)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without exception
    assert any(not p.state.exception for p in paths)


def test_is_op_not_none():
    """Test 'x is not None' pattern."""
    code = compile("""
x = 5
result = (x is not None)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without exception
    assert any(not p.state.exception for p in paths)


def test_is_op_identity():
    """Test object identity check."""
    code = compile("""
x = [1, 2, 3]
y = x
result = (x is y)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without exception
    assert any(not p.state.exception for p in paths)


def test_is_op_non_identity():
    """Test non-identity of different objects."""
    code = compile("""
x = [1, 2, 3]
y = [1, 2, 3]
result = (x is y)
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without exception
    assert any(not p.state.exception for p in paths)


def test_is_op_in_branch():
    """Test IS_OP in conditional branch."""
    code = compile("""
def check(x):
    if x is None:
        return 0
    return 1
""", "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete without exception
    assert any(not p.state.exception for p in paths)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
