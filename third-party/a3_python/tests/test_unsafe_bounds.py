"""
Tests for BOUNDS unsafe region.

Testing the semantic predicate for index out of bounds (IndexError/KeyError).
Both BUG (reachable out-of-bounds) and NON-BUG (provably in-bounds) cases.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


# ============================================================================
# BUG cases: Index out of bounds is reachable
# ============================================================================

def test_bounds_bug_tuple_negative_index():
    """BUG: Negative index on tuple (out of bounds)."""
    code = compile("x = (1, 2, 3); y = x[-1]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should find at least one path with bounds violation
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    # Note: negative indexing is legal in Python (-1 is last element)
    # This test may need adjustment based on semantic model
    # For now, focusing on simpler cases
    pass  # Skip this test for now


def test_bounds_bug_tuple_too_large():
    """BUG: Index beyond tuple length."""
    code = compile("x = (1, 2, 3); y = x[5]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[5] where len(x) == 3"
    assert bugs[0]['bug_type'] == 'BOUNDS'


def test_bounds_bug_tuple_exactly_length():
    """BUG: Index equal to tuple length (off by one)."""
    code = compile("x = (10, 20); y = x[2]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[2] where len(x) == 2"


def test_bounds_bug_empty_tuple():
    """BUG: Indexing empty tuple."""
    code = compile("x = (); y = x[0]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[0] where x is empty"


def test_bounds_bug_tuple_large_index():
    """BUG: Very large index on small tuple."""
    code = compile("x = (1,); y = x[100]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[100] where len(x) == 1"


# ============================================================================
# NON-BUG cases: Index provably in bounds
# ============================================================================

def test_bounds_safe_tuple_first_element():
    """NON-BUG: Accessing first element of non-empty tuple."""
    code = compile("x = (1, 2, 3); y = x[0]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    # Should complete without bounds violation
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[0] where len(x) == 3"


def test_bounds_safe_tuple_last_valid():
    """NON-BUG: Accessing last valid element."""
    code = compile("x = (1, 2, 3); y = x[2]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[2] where len(x) == 3"


def test_bounds_safe_tuple_middle():
    """NON-BUG: Accessing middle element."""
    code = compile("x = (10, 20, 30, 40); y = x[1]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[1] where len(x) == 4"


def test_bounds_safe_single_element():
    """NON-BUG: Accessing single element tuple."""
    code = compile("x = (42,); y = x[0]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[0] where len(x) == 1"


def test_bounds_safe_multiple_accesses():
    """NON-BUG: Multiple in-bounds accesses."""
    code = compile("x = (1, 2, 3); a = x[0]; b = x[1]; c = x[2]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for multiple in-bounds accesses"


# ============================================================================
# Counterexample extraction test
# ============================================================================

def test_bounds_counterexample_extraction():
    """Test that we can extract a witness trace for BOUNDS bug."""
    code = compile("x = (1, 2); y = x[10]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should find BOUNDS bug"
    
    bug = bugs[0]
    assert bug['bug_type'] == 'BOUNDS'
    assert 'trace' in bug
    assert 'final_state' in bug
    assert bug['final_state']['exception'] in ('IndexError', 'KeyError')
    assert bug['final_state']['index_out_of_bounds'] == True


# ============================================================================
# Additional BUG cases
# ============================================================================

def test_bounds_bug_very_small_tuple():
    """BUG: Index 1 on single element tuple."""
    code = compile("x = (5,); y = x[1]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[1] where len(x) == 1"


def test_bounds_bug_two_element_tuple_index_three():
    """BUG: Index 3 on two element tuple."""
    code = compile("x = (1, 2); y = x[3]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[3] where len(x) == 2"


def test_bounds_bug_medium_tuple_high_index():
    """BUG: Index 20 on 5 element tuple."""
    code = compile("x = (1, 2, 3, 4, 5); y = x[20]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[20] where len(x) == 5"


def test_bounds_bug_four_element_at_four():
    """BUG: Index 4 on four element tuple (off by one)."""
    code = compile("x = (10, 20, 30, 40); y = x[4]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[4] where len(x) == 4"


def test_bounds_bug_empty_tuple_high_index():
    """BUG: Index 5 on empty tuple."""
    code = compile("x = (); y = x[5]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) > 0, "Should detect BOUNDS for x[5] where x is empty"


# ============================================================================
# Additional NON-BUG cases
# ============================================================================

def test_bounds_safe_two_element_first():
    """NON-BUG: Accessing first element of two-element tuple."""
    code = compile("x = (10, 20); y = x[0]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[0] where len(x) == 2"


def test_bounds_safe_two_element_last():
    """NON-BUG: Accessing last element of two-element tuple."""
    code = compile("x = (10, 20); y = x[1]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[1] where len(x) == 2"


def test_bounds_safe_five_element_middle():
    """NON-BUG: Accessing middle element of five-element tuple."""
    code = compile("x = (1, 2, 3, 4, 5); y = x[2]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[2] where len(x) == 5"


def test_bounds_safe_five_element_last():
    """NON-BUG: Accessing last element of five-element tuple."""
    code = compile("x = (1, 2, 3, 4, 5); y = x[4]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for x[4] where len(x) == 5"


def test_bounds_safe_sequential_accesses():
    """NON-BUG: Multiple sequential in-bounds accesses."""
    code = compile("x = (10, 20, 30); a = x[0]; b = x[0]; c = x[1]", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'BOUNDS']
    
    assert len(bugs) == 0, "Should NOT detect BOUNDS for repeated in-bounds accesses"
