"""
Tests for DIV_ZERO unsafe region.

Testing the semantic predicate for division by zero (ZeroDivisionError).
Both BUG (reachable div-by-zero) and NON-BUG (provably no div-by-zero) cases.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


# ============================================================================
# BUG cases: Division by zero is reachable
# ============================================================================

def test_divzero_bug_truediv_literal_zero():
    """BUG: Direct true division by literal zero."""
    code = compile("x = 10 / 0", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should find at least one path with div-by-zero
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO for literal 10 / 0"
    assert bugs[0]['bug_type'] == 'DIV_ZERO'


def test_divzero_bug_floordiv_literal_zero():
    """BUG: Direct floor division by literal zero."""
    code = compile("x = 10 // 0", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO for literal 10 // 0"


def test_divzero_bug_mod_literal_zero():
    """BUG: Modulo by literal zero."""
    code = compile("x = 10 % 0", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO for literal 10 % 0"


def test_divzero_bug_truediv_variable_zero():
    """BUG: True division where divisor can be zero."""
    code = compile("y = 0\nx = 10 / y", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO when divisor variable is zero"


def test_divzero_bug_path_conditional():
    """BUG: Division by zero on one branch (reachable)."""
    code = compile("""
x = 5
y = 0
if x > 3:
    z = 100 / y
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should find the path where x > 3 and division by y=0 happens
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO on the conditional branch where y=0"


def test_divzero_bug_floordiv_variable_zero():
    """BUG: Floor division where divisor is zero."""
    code = compile("a = 0\nb = 15 // a", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO for floor division by zero"


def test_divzero_bug_mod_variable_zero():
    """BUG: Modulo where divisor is zero."""
    code = compile("d = 0\ne = 20 % d", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO for modulo by zero"


def test_divzero_bug_computed_zero():
    """BUG: Division by result of computation that equals zero."""
    code = compile("a = 5\nb = 5\nc = a - b\nd = 10 / c", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO when divisor computation yields zero"


def test_divzero_bug_negative_zero_division():
    """BUG: Division where subtraction creates zero divisor."""
    code = compile("x = 10\ny = 10\nz = 100 / (x - y)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO"


def test_divzero_bug_multiplication_to_zero():
    """BUG: Division where multiplication creates zero divisor."""
    code = compile("a = 0\nb = 5\nc = a * b\nd = 50 / c", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0, "Should detect DIV_ZERO when multiplication yields zero"


# ============================================================================
# NON-BUG cases: Division by zero is NOT reachable
# ============================================================================

def test_divzero_nonbug_literal_nonzero():
    """NON-BUG: Division by non-zero literal."""
    code = compile("x = 10 / 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # No path should have div-by-zero
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO for division by non-zero literal"


def test_divzero_nonbug_variable_nonzero():
    """NON-BUG: Division by variable that's definitely non-zero."""
    code = compile("y = 5\nx = 10 / y", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when divisor is definitely non-zero"


def test_divzero_nonbug_guarded():
    """NON-BUG: Division guarded by a check (divisor cannot be zero on that path)."""
    code = compile("""
y = 0
if y != 0:
    x = 10 / y
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # The division only happens when y != 0, so no div-by-zero on any path
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when division is guarded by y != 0"


def test_divzero_nonbug_no_division():
    """NON-BUG: No division operations at all."""
    code = compile("x = 10 + 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when there's no division"


def test_divzero_nonbug_unreachable_branch():
    """NON-BUG: Division by zero in unreachable code."""
    code = compile("""
x = 5
if x < 0:
    # Unreachable: x is always 5
    z = 100 / 0
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # No reachable path should trigger the division
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO in unreachable branch"


def test_divzero_nonbug_floordiv_nonzero():
    """NON-BUG: Floor division by non-zero value."""
    code = compile("x = 20 // 3", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO for floor division by non-zero"


def test_divzero_nonbug_mod_nonzero():
    """NON-BUG: Modulo by non-zero value."""
    code = compile("x = 17 % 5", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO for modulo by non-zero"


def test_divzero_nonbug_computed_nonzero():
    """NON-BUG: Division by result of computation that's non-zero."""
    code = compile("a = 5\nb = 3\nc = a + b\nd = 80 / c", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when divisor is computed non-zero"


def test_divzero_nonbug_multiplication_nonzero():
    """NON-BUG: Division by product that's non-zero."""
    code = compile("a = 3\nb = 4\nc = a * b\nd = 120 / c", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when multiplication yields non-zero"


def test_divzero_nonbug_subtraction_nonzero():
    """NON-BUG: Division by difference that's non-zero."""
    code = compile("x = 10\ny = 3\nz = 21 / (x - y)", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when subtraction yields non-zero"


def test_divzero_nonbug_multiple_divisions_safe():
    """NON-BUG: Multiple divisions all by non-zero values."""
    code = compile("a = 100 / 5\nb = a / 2\nc = b / 10", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO when all divisions are safe"


def test_divzero_nonbug_negative_divisor():
    """NON-BUG: Division by negative non-zero value is safe."""
    code = compile("x = 10 / -2", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) == 0, "Should NOT detect DIV_ZERO for negative non-zero divisor"


# ============================================================================
# Counterexample extraction tests
# ============================================================================

def test_divzero_counterexample_extraction():
    """Test that DIV_ZERO counterexample includes trace and state."""
    code = compile("x = 1 / 0", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
    bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DIV_ZERO']
    
    assert len(bugs) > 0
    counterexample = bugs[0]
    
    # Verify counterexample structure
    assert counterexample['bug_type'] == 'DIV_ZERO'
    assert 'trace' in counterexample
    assert 'final_state' in counterexample
    assert 'path_condition' in counterexample
    assert isinstance(counterexample['trace'], list)
    
    # Verify final state includes div_by_zero flag or exception
    final_state = counterexample['final_state']
    assert final_state['div_by_zero_reached'] or final_state['exception'] == 'ZeroDivisionError'
