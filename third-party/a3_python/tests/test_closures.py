"""
Tests for closure support (MAKE_CELL, STORE_DEREF, LOAD_DEREF, COPY_FREE_VARS).

These tests verify that the symbolic VM correctly handles closure variables,
which are essential for nested function definitions.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM


class TestSimpleClosures:
    """Tests for basic closure functionality."""
    
    def test_simple_closure_creation(self):
        """Test that a simple closure can be created without errors."""
        source = """
def outer():
    x = 1
    def inner():
        return x
    return inner
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)
    
    def test_closure_variable_access(self):
        """Test that closure variables can be accessed from inner function."""
        source = """
def outer():
    x = 42
    def inner():
        return x
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)
    
    def test_multiple_closure_variables(self):
        """Test multiple variables captured in closure."""
        source = """
def outer():
    x = 1
    y = 2
    def inner():
        return x + y
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)


class TestNestedClosures:
    """Tests for nested closures (multiple levels)."""
    
    def test_two_level_closure(self):
        """Test closure with two levels of nesting."""
        source = """
def outer():
    x = 1
    def middle():
        y = 2
        def inner():
            return x + y
        return inner()
    return middle()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)


class TestClosureModification:
    """Tests for modifying closure variables."""
    
    def test_closure_variable_read_only(self):
        """Test reading a closure variable multiple times."""
        source = """
def outer():
    x = 10
    def inner():
        a = x
        b = x
        return a + b
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)


class TestClosureEdgeCases:
    """Tests for edge cases in closure handling."""
    
    def test_closure_without_usage(self):
        """Test function that could capture variables but doesn't."""
        source = """
def outer():
    x = 1
    def inner():
        return 42
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)
    
    def test_partial_closure(self):
        """Test function that captures only some variables."""
        source = """
def outer():
    x = 1
    y = 2
    def inner():
        return x
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should complete without exceptions
        assert any(not p.state.exception for p in paths)


class TestClosureWithBugs:
    """Tests for bug detection in closures."""
    
    @pytest.mark.xfail(reason="User-defined function calls don't yet execute bytecode; they use contracts")
    def test_closure_division_by_zero(self):
        """Test DIV_ZERO detection in closure."""
        source = """
def outer():
    x = 0
    def inner():
        return 1 / x
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should detect division by zero
        assert any(p.state.div_by_zero_reached for p in paths)
    
    @pytest.mark.xfail(reason="User-defined function calls don't yet execute bytecode; they use contracts")
    def test_closure_with_assert(self):
        """Test ASSERT_FAIL detection in closure."""
        source = """
def outer():
    x = False
    def inner():
        assert x
    return inner()
result = outer()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should detect assertion failure
        # (Either as exception or as termination)
        assert any(p.state.exception == "AssertionError" for p in paths)


class TestMakeCellOpcode:
    """Direct tests for MAKE_CELL opcode behavior."""
    
    def test_make_cell_creates_cell(self):
        """Test that MAKE_CELL initializes a cell."""
        # This bytecode pattern appears at the start of functions with closures
        source = """
def f():
    x = 1
    def g():
        return x
    return g
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should execute without error
        assert any(not p.state.exception for p in paths)


class TestStoreDerefOpcode:
    """Tests for STORE_DEREF opcode."""
    
    def test_store_deref_basic(self):
        """Test that STORE_DEREF stores values into cells."""
        source = """
def f():
    x = 42
    def g():
        return x
    return g
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=100)
        
        # Should execute without error
        assert any(not p.state.exception for p in paths)


class TestLoadDerefOpcode:
    """Tests for LOAD_DEREF opcode."""
    
    def test_load_deref_basic(self):
        """Test that LOAD_DEREF loads values from cells."""
        source = """
def f():
    x = 100
    def g():
        return x
    return g()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should execute without error
        assert any(not p.state.exception for p in paths)


class TestCopyFreeVarsOpcode:
    """Tests for COPY_FREE_VARS opcode."""
    
    def test_copy_free_vars_basic(self):
        """Test that COPY_FREE_VARS initializes free variables."""
        # When a closure is called, COPY_FREE_VARS copies captured variables
        source = """
def f():
    x = 1
    y = 2
    def g():
        return x + y
    return g()
"""
        code = compile(source, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should execute without error
        assert any(not p.state.exception for p in paths)
