"""
Tests for CONTAINS_OP with dict return types from stdlib functions.

Tests the fix for iteration 136: globals() and other functions returning
dicts should work correctly with CONTAINS_OP ('in' operator).
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM

class TestContainsWithDictReturnType:
    """Test CONTAINS_OP when container is a dict from stdlib function"""
    
    def test_globals_in_operator_safe(self):
        """Test that checking membership in globals() is SAFE"""
        code = """
if '_is_loaded' in globals():
    x = 1
else:
    x = 2
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should have successful paths (no TYPE_CONFUSION)
        safe_paths = [p for p in paths if not p.state.type_confusion_reached]
        assert len(safe_paths) > 0, "Should have safe paths for globals() in operator"
        
        # Check no TYPE_CONFUSION was reached
        tc_paths = [p for p in paths if p.state.type_confusion_reached]
        assert len(tc_paths) == 0, f"Should not have TYPE_CONFUSION for globals() in operator, got {len(tc_paths)}"
    
    def test_globals_not_in_operator_safe(self):
        """Test that 'not in' with globals() is SAFE"""
        code = """
if 'nonexistent' not in globals():
    x = 1
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should complete without TYPE_CONFUSION
        # Note: may have exception paths but no TYPE_CONFUSION
        assert not any(p.state.type_confusion_reached for p in paths)
    
    def test_dict_constructor_in_operator(self):
        """Test that dict() return value works with 'in' operator"""
        code = """
d = dict()
if 'key' in d:
    x = 1
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should have safe paths
        assert any(not p.state.exception for p in paths)
        assert not any(p.state.type_confusion_reached for p in paths)
    
    def test_list_constructor_in_operator(self):
        """Test that list() return value works with 'in' operator"""
        code = """
lst = list()
if 1 in lst:
    x = 1
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should have safe paths
        assert any(not p.state.exception for p in paths)
        assert not any(p.state.type_confusion_reached for p in paths)
    
    def test_tuple_constructor_in_operator(self):
        """Test that tuple() return value works with 'in' operator"""
        code = """
t = tuple()
if 1 in t:
    x = 1
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should have safe paths
        assert any(not p.state.exception for p in paths)
        assert not any(p.state.type_confusion_reached for p in paths)


class TestContainsStillDetectsBugs:
    """Ensure CONTAINS_OP still detects real type confusion bugs"""
    
    def test_int_not_iterable_type_confusion(self):
        """Test that using int as container still triggers TYPE_CONFUSION"""
        code = """
x = 5
if 1 in x:
    pass
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should detect TYPE_CONFUSION
        assert any(p.state.type_confusion_reached for p in paths)
    
    def test_none_container_null_ptr(self):
        """Test that None as container triggers NULL_PTR"""
        code = """
x = None
if 1 in x:
    pass
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should detect NULL_PTR (None misuse)
        assert any(p.state.null_ptr_reached for p in paths)


class TestNumpyGlobalsCase:
    """Test the exact numpy _globals.py pattern that was flagged"""
    
    def test_numpy_reload_check(self):
        """Test the numpy pattern: if '_is_loaded' in globals(): raise RuntimeError"""
        code = """
if '_is_loaded' in globals():
    raise RuntimeError('Reloading module')
_is_loaded = True
"""
        compiled = compile(code, '<test>', 'exec')
        
        vm = SymbolicVM()
        paths = vm.explore_bounded(compiled, max_steps=50)
        
        # Should have paths without TYPE_CONFUSION
        safe_paths = [p for p in paths if not p.state.type_confusion_reached]
        assert len(safe_paths) > 0
        
        # Some paths may raise RuntimeError (if '_is_loaded' already exists), that's OK
        # But TYPE_CONFUSION should not be triggered
        tc_paths = [p for p in paths if p.state.type_confusion_reached]
        assert len(tc_paths) == 0, "globals() should not trigger TYPE_CONFUSION"
