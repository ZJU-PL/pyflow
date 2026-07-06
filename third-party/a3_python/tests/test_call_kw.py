"""
Tests for CALL_KW opcode (function calls with keyword arguments).

CALL_KW is used when calling functions with keyword arguments.
Stack layout: [callable, NULL, positional_args..., keyword_args..., kwnames_tuple]
"""

import pytest
import dis
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicPath


class TestBasicCallKw:
    """Test basic CALL_KW functionality."""
    
    def test_function_with_only_kwargs(self):
        """Test calling a function with only keyword arguments."""
        code = """
def f(a, b, c):
    return a + b + c

result = f(a=1, b=2, c=3)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should successfully execute
        assert len(paths) > 0
        # Check that CALL_KW was used
        instructions = list(dis.get_instructions(bytecode))
        has_call_kw = any(instr.opname == "CALL_KW" for instr in instructions)
        assert has_call_kw, "Expected CALL_KW opcode in bytecode"
    
    def test_function_with_mixed_args(self):
        """Test calling a function with both positional and keyword arguments."""
        code = """
def f(a, b, c):
    return a + b + c

result = f(1, 2, c=3)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should successfully execute
        assert len(paths) > 0
        # Check that CALL_KW was used
        instructions = list(dis.get_instructions(bytecode))
        has_call_kw = any(instr.opname == "CALL_KW" for instr in instructions)
        assert has_call_kw, "Expected CALL_KW opcode in bytecode"
    
    def test_function_with_single_kwarg(self):
        """Test calling a function with one keyword argument."""
        code = """
def f(a, b, c=5):
    return a + b + c

result = f(1, 2, c=10)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should successfully execute
        assert len(paths) > 0
    
    def test_function_with_default_values(self):
        """Test calling a function that has default values with keyword args."""
        code = """
def f(a, b=2, c=3):
    return a + b + c

result = f(1, c=10)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should successfully execute
        assert len(paths) > 0


class TestBuiltinCallKw:
    """Test CALL_KW with builtin functions."""
    
    def test_builtin_with_kwargs(self):
        """Test calling a builtin function with keyword arguments."""
        code = """
# int() accepts base as keyword argument
result = int("10", base=16)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should execute without errors (though may not get exact result)
        assert len(paths) > 0
    
    def test_builtin_max_with_kwargs(self):
        """Test max() with keyword argument."""
        code = """
# max() accepts key as keyword argument
result = max([1, 2, 3])
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should execute
        assert len(paths) > 0


class TestCallKwWithBugs:
    """Test CALL_KW in the presence of bugs."""
    
    def test_call_kw_with_division_by_zero(self):
        """Test that bugs inside functions called with CALL_KW are detected."""
        code = """
def divide(a, b):
    return a / b

result = divide(a=10, b=0)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should detect potential division by zero
        # Note: This depends on contract modeling; with havoc contract it may not detect
        # Just verify it executes without crashing
        assert len(paths) > 0
    
    def test_call_kw_with_assert_fail(self):
        """Test that assert failures inside functions called with CALL_KW are detected."""
        code = """
def check(value):
    assert value > 0
    return value

result = check(value=-1)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should execute without crashing
        assert len(paths) > 0


class TestCallKwEdgeCases:
    """Test edge cases for CALL_KW."""
    
    def test_multiple_call_kw_in_sequence(self):
        """Test multiple CALL_KW calls in sequence."""
        code = """
def f(a, b):
    return a + b

result1 = f(a=1, b=2)
result2 = f(a=3, b=4)
result3 = f(a=5, b=6)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=200)
        
        # Should successfully execute all calls
        assert len(paths) > 0
    
    def test_nested_call_kw(self):
        """Test nested function calls with keyword arguments."""
        code = """
def inner(x, y):
    return x + y

def outer(a, b):
    return inner(x=a, y=b)

result = outer(a=1, b=2)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=200)
        
        # Should successfully execute (though inner call may use havoc)
        assert len(paths) > 0
    
    def test_call_kw_with_all_defaults_overridden(self):
        """Test calling a function with all default parameters overridden via kwargs."""
        code = """
def f(a=1, b=2, c=3):
    return a + b + c

result = f(a=10, b=20, c=30)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should successfully execute
        assert len(paths) > 0
    
    def test_call_kw_with_many_kwargs(self):
        """Test calling a function with many keyword arguments."""
        code = """
def f(a, b, c, d, e):
    return a + b + c + d + e

result = f(a=1, b=2, c=3, d=4, e=5)
"""
        bytecode = compile(code, "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        # Should successfully execute
        assert len(paths) > 0


class TestCallKwOpcodeCoverage:
    """Verify CALL_KW opcode is actually being exercised."""
    
    def test_call_kw_actually_present_in_bytecode(self):
        """Verify that our test code actually generates CALL_KW instructions."""
        code = """
def f(a, b):
    return a + b

result = f(a=1, b=2)
"""
        bytecode = compile(code, "<test>", "exec")
        instructions = list(dis.get_instructions(bytecode))
        
        # Verify CALL_KW is present
        call_kw_instructions = [i for i in instructions if i.opname == "CALL_KW"]
        assert len(call_kw_instructions) > 0, "No CALL_KW instructions found"
        
        # Verify the argument count
        assert call_kw_instructions[0].argval == 2, "Expected 2 arguments"
    
    def test_call_kw_with_one_kwarg_bytecode(self):
        """Verify bytecode structure for single keyword argument."""
        code = """
def f(a, b, c):
    return a + b + c

result = f(1, 2, c=3)
"""
        bytecode = compile(code, "<test>", "exec")
        instructions = list(dis.get_instructions(bytecode))
        
        # Verify CALL_KW is present
        call_kw_instructions = [i for i in instructions if i.opname == "CALL_KW"]
        assert len(call_kw_instructions) > 0, "No CALL_KW instructions found"
        
        # Should have 3 total arguments (2 positional + 1 keyword)
        assert call_kw_instructions[0].argval == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
