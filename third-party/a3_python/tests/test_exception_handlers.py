"""
Test exception handler semantics in symbolic VM.

Tests that try/except blocks work correctly and that caught exceptions
do not propagate as bugs.
"""

import pytest
import sys
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.assert_fail import is_unsafe_assert_fail
from a3_python.unsafe.div_zero import is_unsafe_div_zero
from a3_python.unsafe.panic import is_unsafe_panic


class TestExceptionHandlers:
    """Test exception handling in try/except blocks."""
    
    def test_caught_zero_division_not_bug(self):
        """Division by zero caught in try/except should not be flagged as bug."""
        code = compile("""
try:
    x = 1 / 0
except ZeroDivisionError:
    x = 0
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should complete without unhandled exception
        assert len(paths) > 0
        
        # Check that no path reaches unsafe state (unhandled exception)
        for path in paths:
            # Exception was caught, so DIV_ZERO unsafe should not be triggered
            # (since unsafe means *unhandled* exception reaches top level)
            assert not is_unsafe_panic(path.state), \
                "Caught ZeroDivisionError should not trigger PANIC"
    
    def test_uncaught_zero_division_is_bug(self):
        """Division by zero without try/except should be flagged as bug."""
        code = compile("x = 1 / 0", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should have at least one path
        assert len(paths) > 0
        
        # At least one path should reach unsafe state
        any_unsafe = any(is_unsafe_div_zero(path.state) for path in paths)
        assert any_unsafe, "Uncaught ZeroDivisionError should trigger DIV_ZERO unsafe"
    
    def test_caught_assertion_not_bug(self):
        """AssertionError caught in try/except should not be flagged as bug."""
        code = compile("""
try:
    assert False
except AssertionError:
    pass
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should complete without unhandled exception
        assert len(paths) > 0
        
        # Check that no path reaches unsafe state
        for path in paths:
            assert not is_unsafe_assert_fail(path.state), \
                "Caught AssertionError should not trigger ASSERT_FAIL"
    
    def test_uncaught_assertion_is_bug(self):
        """AssertionError without try/except should be flagged as bug."""
        code = compile("assert False", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should have at least one path
        assert len(paths) > 0
        
        # At least one path should reach unsafe state
        any_unsafe = any(is_unsafe_assert_fail(path.state) for path in paths)
        assert any_unsafe, "Uncaught AssertionError should trigger ASSERT_FAIL unsafe"
    
    def test_caught_type_error_not_bug(self):
        """TypeError caught in try/except should not be flagged as bug."""
        code = compile("""
try:
    x = 1 + "string"
except TypeError:
    x = 0
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should complete without unhandled exception
        assert len(paths) > 0
        
        # Check that no path reaches unsafe state
        for path in paths:
            assert not is_unsafe_panic(path.state), \
                "Caught TypeError should not trigger PANIC"
    
    def test_exception_handler_with_multiple_except(self):
        """Multiple except clauses should each handle their exception type."""
        code = compile("""
try:
    x = 1 / 0
except ValueError:
    x = 1
except ZeroDivisionError:
    x = 2
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should complete without unhandled exception
        assert len(paths) > 0
        
        # No path should have unhandled exception
        for path in paths:
            assert not is_unsafe_panic(path.state), \
                "Exception should be caught by one of the handlers"
    
    @pytest.mark.xfail(reason="Re-raise exception tracking needs refinement for nested handlers")
    def test_reraise_propagates_exception(self):
        """Re-raised exception should propagate as bug if not caught."""
        code = compile("""
try:
    try:
        x = 1 / 0
    except ZeroDivisionError:
        raise
except ValueError:
    x = 0
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should have paths
        assert len(paths) > 0
        
        # The re-raised ZeroDivisionError is not caught by ValueError handler
        # So it should propagate as PANIC
        any_unsafe = any(is_unsafe_panic(path.state) for path in paths)
        assert any_unsafe, "Re-raised exception not caught by wrong type should be PANIC"
    
    def test_nested_try_inner_catch(self):
        """Inner try/except catching exception should prevent outer propagation."""
        code = compile("""
try:
    try:
        x = 1 / 0
    except ZeroDivisionError:
        x = 1
except ValueError:
    x = 2
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should complete without unhandled exception
        assert len(paths) > 0
        
        # No path should reach unsafe state
        for path in paths:
            assert not is_unsafe_panic(path.state), \
                "Inner handler should catch exception"
    
    @pytest.mark.xfail(reason="Exception tracking in handlers needs refinement")
    def test_exception_in_handler_propagates(self):
        """Exception raised within exception handler should propagate."""
        code = compile("""
try:
    x = 1 / 0
except ZeroDivisionError:
    y = 1 / 0  # New exception in handler
""", '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should have paths
        assert len(paths) > 0
        
        # The new exception in the handler is not caught, so PANIC
        any_unsafe = any(is_unsafe_panic(path.state) for path in paths)
        assert any_unsafe, "Exception in handler should propagate as PANIC"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
