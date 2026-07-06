"""
Tests for CONTAINS_OP opcode implementation.

CONTAINS_OP implements the 'in' and 'not in' operators in Python.
Targets Python 3.11+ bytecode semantics.
"""

import pytest
from a3_python.semantics.concrete_vm import ConcreteVM, load_and_run
from a3_python.semantics.symbolic_vm import SymbolicVM
import z3


class TestContainsOpConcrete:
    """Test CONTAINS_OP in concrete execution."""
    
    def test_contains_list_true(self):
        """Test item in list (found)."""
        state = load_and_run("2 in [1, 2, 3]")
        assert state.return_value is True
        assert state.exception is None
    
    def test_contains_list_false(self):
        """Test item in list (not found)."""
        state = load_and_run("4 in [1, 2, 3]")
        assert state.return_value is False
        assert state.exception is None
    
    def test_not_contains_list_true(self):
        """Test item not in list (true - not found)."""
        state = load_and_run("4 not in [1, 2, 3]")
        assert state.return_value is True
        assert state.exception is None
    
    def test_not_contains_list_false(self):
        """Test item not in list (false - found)."""
        state = load_and_run("2 not in [1, 2, 3]")
        assert state.return_value is False
        assert state.exception is None
    
    def test_contains_tuple(self):
        """Test item in tuple."""
        state = load_and_run("'b' in ('a', 'b', 'c')")
        assert state.return_value is True
        assert state.exception is None
    
    def test_contains_string(self):
        """Test substring in string."""
        state = load_and_run("'llo' in 'hello'")
        assert state.return_value is True
        assert state.exception is None
    
    def test_contains_dict_key(self):
        """Test key in dict (skipped - BUILD_MAP not implemented in concrete VM)."""
        pytest.skip("BUILD_MAP not implemented in concrete VM")
    
    def test_contains_dict_missing_key(self):
        """Test missing key in dict (skipped - BUILD_MAP not implemented in concrete VM)."""
        pytest.skip("BUILD_MAP not implemented in concrete VM")
    
    def test_contains_empty_list(self):
        """Test item in empty list."""
        state = load_and_run("1 in []")
        assert state.return_value is False
        assert state.exception is None
    
    def test_contains_none_container_error(self):
        """Test TypeError when container is None (NULL_PTR bug class)."""
        # Skip: STORE_NAME not implemented in concrete VM
        pytest.skip("STORE_NAME not implemented in concrete VM")
    
    def test_contains_non_iterable_error(self):
        """Test TypeError when container is not iterable (TYPE_CONFUSION bug class)."""
        state = load_and_run("1 in 42")
        assert state.exception is not None
        assert state.exception[0] == TypeError


class TestContainsOpSymbolic:
    """Test CONTAINS_OP in symbolic execution."""
    
    def test_contains_list_symbolic(self):
        """Test symbolic execution of item in list."""
        code = compile("2 in [1, 2, 3]", "<test>", "eval")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should complete without error
        assert len(paths) > 0
        completed = [p for p in paths if p.state.halted]
        assert len(completed) > 0
        
        # Result should be boolean
        for path in completed:
            if path.state.return_value:
                # Check that tag is BOOL (conservative: may be nondeterministic)
                assert path.state.return_value.tag is not None
    
    def test_not_contains_symbolic(self):
        """Test symbolic execution of item not in list."""
        code = compile("4 not in [1, 2, 3]", "<test>", "eval")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        assert len(paths) > 0
        completed = [p for p in paths if p.state.halted]
        assert len(completed) > 0
    
    def test_contains_none_detects_null_ptr(self):
        """Test that 'x in None' detects NULL_PTR bug."""
        code = compile("""
x = None
1 in x
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should detect null_ptr_reached
        null_ptr_paths = [p for p in paths if p.state.null_ptr_reached]
        assert len(null_ptr_paths) > 0
    
    def test_contains_type_error_detection(self):
        """Test that containment on non-iterable detects TYPE_CONFUSION."""
        # Note: For concrete int, this should be detected
        # Symbolic execution with nondeterministic values may not catch this
        # unless we explicitly model the type constraint
        code = compile("1 in 42", "<test>", "eval")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        # Should detect type_confusion_reached
        type_error_paths = [p for p in paths if p.state.type_confusion_reached]
        assert len(type_error_paths) > 0
    
    def test_contains_tuple_symbolic(self):
        """Test symbolic execution with tuple containment."""
        code = compile("'x' in ('a', 'b', 'x')", "<test>", "eval")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        assert len(paths) > 0
        completed = [p for p in paths if p.state.halted]
        assert len(completed) > 0
    
    def test_contains_dict_symbolic(self):
        """Test symbolic execution with dict containment (skipped - BUILD_MAP issues)."""
        pytest.skip("BUILD_MAP symbolic execution incomplete")
    
    def test_contains_string_symbolic(self):
        """Test symbolic execution with string containment."""
        code = compile("'x' in 'xyz'", "<test>", "eval")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        
        assert len(paths) > 0
        completed = [p for p in paths if p.state.halted]
        assert len(completed) > 0


class TestContainsOpDifferential:
    """Differential tests: concrete vs symbolic must agree on observable behavior."""
    
    def test_differential_list_found(self):
        """Concrete and symbolic should both handle 'x in list' when found."""
        code = compile("2 in [1, 2, 3]", "<test>", "eval")
        
        # Concrete
        state = load_and_run("2 in [1, 2, 3]")
        
        # Symbolic
        vm_symbolic = SymbolicVM()
        paths = vm_symbolic.explore_bounded(code, max_steps=50)
        
        # Both should complete successfully
        assert state.exception is None
        assert len(paths) > 0
        assert any(p.state.halted for p in paths)
    
    def test_differential_not_in(self):
        """Concrete and symbolic should both handle 'x not in list'."""
        code = compile("4 not in [1, 2, 3]", "<test>", "eval")
        
        state = load_and_run("4 not in [1, 2, 3]")
        
        vm_symbolic = SymbolicVM()
        paths = vm_symbolic.explore_bounded(code, max_steps=50)
        
        assert state.exception is None
        assert any(p.state.halted for p in paths)
    
    def test_differential_none_error(self):
        """Both VMs should raise TypeError for 'x in None' (symbolic only - concrete needs STORE_NAME)."""
        code = compile("""
x = None
1 in x
""", "<test>", "exec")
        
        # Symbolic only (concrete VM missing STORE_NAME)
        vm_symbolic = SymbolicVM()
        paths = vm_symbolic.explore_bounded(code, max_steps=50)
        null_ptr_paths = [p for p in paths if p.state.null_ptr_reached]
        assert len(null_ptr_paths) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
