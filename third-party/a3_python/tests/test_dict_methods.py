"""
Test dict methods (keys, values, items) - semantically faithful implementation.

These tests verify that dict.keys(), dict.values(), and dict.items() return appropriate
view objects that can be iterated over. This is crucial for analyzing real code that
uses these common patterns.

Bug detection: Calling these methods on None → NULL_PTR, calling on non-dict → TYPE_CONFUSION
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def test_dict_keys_basic():
    """dict.keys() returns an iterable of keys - should be SAFE."""
    code = compile('''
d = {"a": 1, "b": 2}
keys = d.keys()
for k in keys:
    pass
''', "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should complete without finding NULL_PTR or TYPE_CONFUSION bugs
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    
    null_ptr_bugs = [b for b in bugs if b.get('bug_type') == 'NULL_PTR']
    type_confusion_bugs = [b for b in bugs if b.get('bug_type') == 'TYPE_CONFUSION']
    
    assert len(null_ptr_bugs) == 0, "Should not detect NULL_PTR in dict.keys()"
    assert len(type_confusion_bugs) == 0, "Should not detect TYPE_CONFUSION in dict.keys()"


def test_dict_values_basic():
    """dict.values() returns an iterable of values - should be SAFE."""
    code = compile('''
d = {"a": 1, "b": 2}
values = d.values()
for v in values:
    pass
''', "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    
    null_ptr_bugs = [b for b in bugs if b.get('bug_type') == 'NULL_PTR']
    type_confusion_bugs = [b for b in bugs if b.get('bug_type') == 'TYPE_CONFUSION']
    
    assert len(null_ptr_bugs) == 0
    assert len(type_confusion_bugs) == 0


def test_dict_items_basic():
    """dict.items() returns an iterable of (key, value) tuples - should be SAFE."""
    code = compile('''
d = {"a": 1, "b": 2}
items = d.items()
for k, v in items:
    pass
''', "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    
    null_ptr_bugs = [b for b in bugs if b.get('bug_type') == 'NULL_PTR']
    type_confusion_bugs = [b for b in bugs if b.get('bug_type') == 'TYPE_CONFUSION']
    
    assert len(null_ptr_bugs) == 0
    assert len(type_confusion_bugs) == 0


def test_dict_keys_on_none_null_ptr():
    """Calling .keys() on None should detect NULL_PTR or PANIC."""
    code = compile('''
d = None
keys = d.keys()  # AttributeError / NULL_PTR
''', "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    
    # Should detect NULL_PTR or PANIC (AttributeError)
    null_ptr_bugs = [b for b in bugs if b.get('bug_type') == 'NULL_PTR']
    panic_bugs = [b for b in bugs if b.get('bug_type') == 'PANIC']
    
    assert len(null_ptr_bugs) > 0 or len(panic_bugs) > 0, \
        "Should detect NULL_PTR or PANIC when calling .keys() on None"


def test_empty_dict_keys():
    """Calling .keys() on an empty dict should be SAFE."""
    code = compile('''
d = {}
keys = d.keys()
for k in keys:
    pass  # Should not execute (empty)
''', "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=40)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    
    null_ptr_bugs = [b for b in bugs if b.get('bug_type') == 'NULL_PTR']
    
    assert len(null_ptr_bugs) == 0, "Empty dict.keys() should be SAFE"


def test_dict_methods_on_non_dict_type_confusion():
    """Calling dict methods on non-dict should detect PANIC or NULL_PTR (AttributeError)."""
    code = compile('''
not_a_dict = [1, 2, 3]  # This is a list
keys = not_a_dict.keys()  # AttributeError expected
''', "<test>", "exec")
    
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None]
    
    # Should detect PANIC or NULL_PTR (AttributeError is caught by NULL_PTR detector)
    panic_bugs = [b for b in bugs if b.get('bug_type') == 'PANIC']
    null_ptr_bugs = [b for b in bugs if b.get('bug_type') == 'NULL_PTR']
    
    assert len(panic_bugs) > 0 or len(null_ptr_bugs) > 0, \
        "Should detect PANIC or NULL_PTR when calling dict method on non-dict"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

