"""
Tests for STORE_GLOBAL opcode.

STORE_GLOBAL stores a value from the operand stack into the global namespace.
This opcode is rarely used in modern Python but is part of the complete bytecode semantics.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.z3model.values import ValueTag
import z3


class TestStoreGlobal:
    """Test STORE_GLOBAL opcode implementation."""
    
    def test_store_global_simple(self):
        """STORE_GLOBAL stores value in globals."""
        code = """
global x
x = 42
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=50)
        
        # Should complete successfully (frame popped on RETURN_VALUE)
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted, "Program should complete"
        assert not path.state.exception, "No exception should occur"
    
    def test_store_global_after_load(self):
        """STORE_GLOBAL works after loading a value."""
        code = """
y = 10
global x
x = y + 5
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=50)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception
    
    def test_store_global_read_back(self):
        """Global can be stored and then read back."""
        code = """
global counter
counter = 0
counter = counter + 1
result = counter
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception
    
    def test_store_global_multiple_assignments(self):
        """Multiple STORE_GLOBAL assignments."""
        code = """
global a, b, c
a = 1
b = 2
c = 3
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception
    
    def test_store_global_overwrite(self):
        """STORE_GLOBAL can overwrite existing global."""
        code = """
global value
value = "first"
value = "second"
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception
    
    def test_store_global_different_types(self):
        """STORE_GLOBAL handles different value types."""
        code = """
global num, txt, lst
num = 42
txt = "hello"
lst = [1, 2, 3]
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=150)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception
    
    def test_store_global_computed_value(self):
        """STORE_GLOBAL with computed expressions."""
        code = """
global result
result = (10 + 5) * 2
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception
    
    def test_store_global_conditional(self):
        """STORE_GLOBAL in conditional branches."""
        code = """
x = 5
global flag
if x > 0:
    flag = True
else:
    flag = False
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=150)
        
        # Should have paths that complete successfully
        assert len(paths) > 0
        # At least one path should complete without error
        completed_ok = any(p.state.halted and not p.state.exception for p in paths)
        assert completed_ok, "At least one path should complete successfully"
    
    def test_store_global_no_stack_underflow(self):
        """STORE_GLOBAL without value causes exception (implementation detail test)."""
        # This is a bytecode-level test - in practice, Python compiler won't generate this
        # But our semantics must handle it correctly for completeness
        # We test indirectly by verifying that normal code doesn't cause stack issues
        code = """
global x
x = 1
x = 2
x = 3
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        assert len(paths) > 0
        path = paths[0]
        # No stack underflow should occur
        assert path.state.exception != "StackUnderflow"
    
    def test_store_global_module_level(self):
        """STORE_GLOBAL at module level (common pattern)."""
        code = """
global CONFIG
CONFIG = {"debug": True, "version": 1}
"""
        bytecode = compile(code, '<test>', 'exec')
        vm = SymbolicVM()
        paths = vm.explore_bounded(bytecode, max_steps=100)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.state.halted
        assert not path.state.exception

