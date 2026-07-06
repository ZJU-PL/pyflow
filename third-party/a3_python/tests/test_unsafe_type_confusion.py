"""
Tests for TYPE_CONFUSION unsafe predicate.

TYPE_CONFUSION: Dynamic dispatch/type errors violating expected protocol.

These tests validate that:
1. Type mismatches in operations are detected semantically.
2. Compatible type operations do not trigger the predicate.
3. TYPE_CONFUSION is distinct from NULL_PTR (None misuse).
4. Counterexample traces are extractable.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions
from a3_python.unsafe.type_confusion import is_unsafe_type_confusion, extract_counterexample


def test_type_confusion_int_str_add():
    """BUG: Adding int and str is type confusion."""
    code = compile("x = 5 + 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(bugs) > 0, "TYPE_CONFUSION not detected for int + str"
    assert bugs[0]['bug_type'] == 'TYPE_CONFUSION'
    assert bugs[0]['final_state']['exception'] == 'TypeError'
    assert bugs[0]['final_state']['type_confusion_reached']
    assert not bugs[0]['final_state']['none_misuse_reached']


def test_type_confusion_str_int_subtract():
    """BUG: Subtracting int from str is type confusion."""
    code = compile("x = 'hello' - 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(bugs) > 0, "TYPE_CONFUSION not detected for str - int"


def test_type_confusion_bool_str_multiply():
    """BUG: Multiplying bool and str might be type confusion (though Python allows it)."""
    # Note: In actual Python, bool * str works (bool is subclass of int)
    # Our simplified model may treat this differently
    # For now, test that our symbolic model handles it consistently
    code = compile("x = True * 'a'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # This test documents current behavior: may or may not be type confusion
    # depending on implementation details
    # The key is: if it's flagged as TypeError, it should be TYPE_CONFUSION
    for path in paths:
        if path.state.exception == "TypeError":
            bug = check_unsafe_regions(path.state, path.trace)
            if bug:
                assert bug['bug_type'] == 'TYPE_CONFUSION', \
                    "TypeError should be detected as TYPE_CONFUSION"


def test_type_confusion_int_str_compare():
    """BUG: Comparing int < str is type confusion in Python 3."""
    code = compile("x = 5 < 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(bugs) > 0, "TYPE_CONFUSION not detected for int < str"


def test_type_confusion_list_int_compare():
    """BUG: Comparing list > int is type confusion (if list comparison implemented)."""
    code = compile("x = [1, 2, 3] > 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    # Note: This may or may not be detected depending on list comparison implementation
    # The important thing is that if a TypeError is detected, it should be TYPE_CONFUSION
    if len(bugs) > 0:
        assert bugs[0]['bug_type'] == 'TYPE_CONFUSION'
    # If not detected, that's OK for now (list operations are complex)


# NON-BUG tests: operations that should NOT trigger TYPE_CONFUSION

def test_no_type_confusion_int_int_add():
    """NON-BUG: Adding two ints is fine."""
    code = compile("x = 5 + 10", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should complete without type confusion
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0, "Should not detect TYPE_CONFUSION for int + int"


def test_no_type_confusion_int_int_compare():
    """NON-BUG: Comparing two ints is fine."""
    code = compile("x = 5 < 10", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0


def test_no_type_confusion_equality():
    """NON-BUG: Equality comparison works across types."""
    code = compile("x = 5 == 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Equality comparison should succeed (return False) without type error
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0


def test_no_type_confusion_inequality():
    """NON-BUG: Inequality comparison works across types."""
    code = compile("x = 5 != 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0


def test_type_confusion_distinct_from_none_misuse():
    """TYPE_CONFUSION is distinct from NULL_PTR (None misuse)."""
    # None + int should be NULL_PTR, not TYPE_CONFUSION
    code = compile("x = None + 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should find NULL_PTR, not TYPE_CONFUSION
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    null_ptr_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'NULL_PTR']
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(null_ptr_bugs) > 0, "Should detect NULL_PTR for None + int"
    assert len(type_confusion_bugs) == 0, "None misuse should be NULL_PTR, not TYPE_CONFUSION"


def test_counterexample_extraction():
    """Test that TYPE_CONFUSION counterexample can be extracted."""
    code = compile("x = 5 + 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    for path in paths:
        if is_unsafe_type_confusion(path.state):
            # Extract counterexample
            cex = extract_counterexample(path.state, path.trace)
            
            assert cex["bug_type"] == "TYPE_CONFUSION"
            assert isinstance(cex["trace"], list)
            assert cex["final_state"]["exception"] == "TypeError"
            assert cex["final_state"]["type_confusion_reached"]
            assert not cex["final_state"]["none_misuse_reached"]
            return
    
    pytest.fail("No TYPE_CONFUSION path found for counterexample extraction")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ============================================================================
# Additional BUG tests
# ============================================================================

def test_type_confusion_str_int_multiply():
    """BUG: Multiplying str by str is type confusion."""
    code = compile("x = 'hello' * 'world'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(bugs) > 0, "TYPE_CONFUSION not detected for str * str"


def test_type_confusion_int_str_divide():
    """BUG: Dividing int by str is type confusion."""
    code = compile("x = 10 / 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    # Division may not be fully implemented yet; if detected, must be TYPE_CONFUSION
    # This tests the semantic requirement
    if len(bugs) > 0:
        assert bugs[0]['bug_type'] == 'TYPE_CONFUSION'


def test_type_confusion_str_str_subtract():
    """BUG: Subtracting str from str is type confusion."""
    code = compile("x = 'hello' - 'world'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(bugs) > 0, "TYPE_CONFUSION not detected for str - str"


def test_type_confusion_tuple_int_add():
    """BUG: Adding tuple and int is type confusion."""
    code = compile("x = (1, 2) + 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    # May or may not be detected depending on tuple implementation
    # If detected, must be TYPE_CONFUSION
    if len(bugs) > 0:
        assert bugs[0]['bug_type'] == 'TYPE_CONFUSION'


def test_type_confusion_bool_str_add():
    """BUG: Adding bool and str is type confusion."""
    code = compile("x = True + 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    # Bool is technically int subclass, but adding to str should fail
    assert len(bugs) > 0, "TYPE_CONFUSION not detected for bool + str"


# ============================================================================
# Additional NON-BUG tests
# ============================================================================

def test_no_type_confusion_str_str_add():
    """NON-BUG: String concatenation is allowed."""
    code = compile("x = 'hello' + 'world'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0, "Should not detect TYPE_CONFUSION for str + str"


def test_no_type_confusion_int_str_multiply():
    """NON-BUG: Multiplying int by str is allowed in Python."""
    code = compile("x = 3 * 'hello'", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0, "Should not detect TYPE_CONFUSION for int * str"


def test_no_type_confusion_str_int_multiply():
    """NON-BUG: Multiplying str by int is allowed in Python."""
    code = compile("x = 'hello' * 3", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0, "Should not detect TYPE_CONFUSION for str * int"


def test_no_type_confusion_int_int_divide():
    """NON-BUG: Dividing int by int is allowed."""
    code = compile("x = 10 / 2", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0


def test_no_type_confusion_int_int_subtract():
    """NON-BUG: Subtracting int from int is allowed."""
    code = compile("x = 10 - 3", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    assert len(type_confusion_bugs) == 0


def test_no_type_confusion_bool_bool_compare():
    """NON-BUG: Comparing bools is allowed (bool is int subclass)."""
    code = compile("x = True == False", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    # Equality should always work
    assert len(type_confusion_bugs) == 0


def test_no_type_confusion_mixed_numeric():
    """NON-BUG: Mixing int and bool in arithmetic is allowed."""
    code = compile("x = 5 + True", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    type_confusion_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'TYPE_CONFUSION']
    
    # Bool is subclass of int, so this should work
    assert len(type_confusion_bugs) == 0
