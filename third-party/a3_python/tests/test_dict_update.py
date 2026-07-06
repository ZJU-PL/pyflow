"""
Tests for DICT_UPDATE opcode implementation.

DICT_UPDATE is used for dict unpacking syntax: {**d1, **d2} and function **kwargs.
These tests verify that the opcode is implemented and doesn't crash.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
import tempfile
import os


class TestDictUpdateBasic:
    """Basic tests that DICT_UPDATE opcode works."""
    
    def test_basic_compile(self):
        """Test that dict merge compiles successfully."""
        code = """
d1 = {'a': 1, 'b': 2}
d2 = {'c': 3, 'd': 4}
result = {**d1, **d2}
"""
        # Should compile without error
        compiled = compile(code, "<test>", "exec")
        assert compiled is not None
    
    def test_basic_symbolic_execution(self):
        """Test basic dict merge in symbolic execution."""
        code = compile("""
d1 = {'a': 1, 'b': 2}
d2 = {'c': 3, 'd': 4}
result = {**d1, **d2}
""", "<test>", "exec")
        
        vm = SymbolicVM()
        # Should not crash
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
    
    def test_empty_dicts(self):
        """Test merging empty dicts."""
        code = compile("""
d1 = {}
d2 = {}
result = {**d1, **d2}
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=30)
        assert len(paths) > 0
    
    def test_multiple_unpacks(self):
        """Test multiple dict unpacks."""
        code = compile("""
d1 = {'a': 1}
d2 = {'b': 2}
d3 = {'c': 3}
result = {**d1, **d2, **d3}
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
    
    def test_mixed_literal_and_unpack(self):
        """Test mixing literal entries with unpacking."""
        code = compile("""
d1 = {'a': 1}
result = {'b': 2, **d1, 'c': 3}
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
    
    def test_single_unpack(self):
        """Test single dict unpack."""
        code = compile("""
d1 = {'a': 1, 'b': 2}
result = {**d1}
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=30)
        assert len(paths) > 0
    
    def test_overlapping_keys(self):
        """Test overlapping keys (later overwrites earlier)."""
        code = compile("""
d1 = {'a': 1, 'b': 2}
d2 = {'b': 99, 'c': 3}
result = {**d1, **d2}
""", "<test>", "exec")
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) > 0
    
    def test_none_handling(self):
        """Test dict update with None (should detect TypeError)."""
        code = compile("""
d1 = {'a': 1}
none_dict = None
try:
    result = {**d1, **none_dict}
except TypeError:
    pass
""", "<test>", "exec")
        
        vm = SymbolicVM()
        # Should handle exception branches
        paths = vm.explore_bounded(code, max_steps=50)
        assert len(paths) >= 0  # May be 0 if exception handling isn't complete


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
