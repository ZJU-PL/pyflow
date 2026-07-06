"""
Tests for ASSERT_FAIL unsafe region.

Tests both BUG cases (uncaught AssertionError) and NON-BUG cases
(caught/handled assertions).
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def test_assert_false_unconditional_bug():
    """
    BUG: assert False with no handler.
    
    This should be detected as ASSERT_FAIL.
    """
    code = compile("assert False", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should have at least one path
    assert len(paths) > 0
    
    # At least one path should reach AssertionError
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL for 'assert False'"
    assert bugs_found[0]['bug_type'] == 'ASSERT_FAIL'
    assert bugs_found[0]['final_state']['exception'] == 'AssertionError'


def test_assert_true_not_bug():
    """
    NON-BUG: assert True (optimized away by compiler).
    
    This should not be detected as a bug.
    """
    code = compile("assert True", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Check that no paths reach an unsafe state
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug for 'assert True'"


def test_assert_condition_false_bug():
    """
    BUG: assert with a condition that can be false.
    
    x = 0; assert x > 0 should be detected as ASSERT_FAIL when x <= 0.
    """
    code = compile("x = 0\nassert x > 0", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # Should have at least one path reaching AssertionError
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL for failing assertion"
    assert bugs_found[0]['bug_type'] == 'ASSERT_FAIL'


def test_assert_condition_true_not_bug():
    """
    NON-BUG: assert with a condition that is always true.
    
    x = 5; assert x > 0 should not be detected as a bug.
    """
    code = compile("x = 5\nassert x > 0", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # No path should reach an unsafe state
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug when assertion always passes"


def test_multiple_assertions_first_fails():
    """
    BUG: Multiple assertions where the first one fails.
    """
    code = compile("assert False\nassert True", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL"


def test_multiple_assertions_second_fails():
    """
    BUG: Multiple assertions where the second one fails.
    """
    code = compile("x = 5\nassert x > 0\nassert x < 0", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL on second assertion"


def test_assertion_with_arithmetic():
    """
    NON-BUG: Assertion with arithmetic that always passes.
    """
    code = compile("x = 10\ny = 5\nassert x + y == 15", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug when arithmetic assertion passes"


def test_assertion_with_arithmetic_fails():
    """
    BUG: Assertion with arithmetic that fails.
    """
    code = compile("x = 10\ny = 5\nassert x + y == 20", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL when arithmetic assertion fails"


def test_counterexample_structure():
    """
    Test that counterexample has the required structure.
    """
    code = compile("assert False", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    bug = None
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            break
    
    assert bug is not None
    assert 'bug_type' in bug
    assert 'trace' in bug
    assert 'final_state' in bug
    assert 'path_condition' in bug
    assert bug['bug_type'] == 'ASSERT_FAIL'
    assert isinstance(bug['trace'], list)
    assert len(bug['trace']) > 0


def test_no_false_positive_on_normal_code():
    """
    NON-BUG: Normal code with no assertions should not trigger ASSERT_FAIL.
    """
    code = compile("x = 5\ny = x + 10", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect ASSERT_FAIL in code without assertions"


def test_assert_inequality_fails_bug():
    """
    BUG: assert x != x should fail.
    """
    code = compile("x = 5\nassert x != x", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL"


def test_assert_comparison_chain_bug():
    """
    BUG: assert with comparison chain that fails.
    """
    code = compile("x = 5\nassert x < 5", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL"


def test_assert_negative_value_bug():
    """
    BUG: assert negative > positive should fail.
    """
    code = compile("x = -5\ny = 10\nassert x > y", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL"


def test_assert_subtraction_bug():
    """
    BUG: assert with subtraction that results in false condition.
    """
    code = compile("a = 10\nb = 10\nassert a - b != 0", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL"


def test_assert_multiplication_bug():
    """
    BUG: assert multiplication result wrong.
    """
    code = compile("x = 3\ny = 4\nassert x * y == 10", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect ASSERT_FAIL"


def test_assert_equal_not_bug():
    """
    NON-BUG: assert x == x should always pass.
    """
    code = compile("x = 42\nassert x == x", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_less_than_not_bug():
    """
    NON-BUG: assert with true less-than comparison.
    """
    code = compile("x = 3\ny = 10\nassert x < y", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_greater_than_not_bug():
    """
    NON-BUG: assert with true greater-than comparison.
    """
    code = compile("x = 20\ny = 5\nassert x > y", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_addition_correct_not_bug():
    """
    NON-BUG: assert with correct addition.
    """
    code = compile("a = 7\nb = 8\nassert a + b == 15", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_subtraction_correct_not_bug():
    """
    NON-BUG: assert with correct subtraction.
    """
    code = compile("a = 15\nb = 5\nassert a - b == 10", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_multiplication_correct_not_bug():
    """
    NON-BUG: assert with correct multiplication.
    """
    code = compile("a = 6\nb = 7\nassert a * b == 42", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_inequality_correct_not_bug():
    """
    NON-BUG: assert x != y with different values.
    """
    code = compile("x = 5\ny = 10\nassert x != y", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_multiple_correct_assertions_not_bug():
    """
    NON-BUG: Multiple assertions that all pass.
    """
    code = compile("x = 10\nassert x > 5\nassert x < 20\nassert x == 10", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=40)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"


def test_assert_expression_chain_not_bug():
    """
    NON-BUG: assert with chained expressions that pass.
    """
    code = compile("a = 2\nb = 3\nc = 5\nassert a + b == c", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=40)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    assert len(bugs_found) == 0, "Should not detect bug"
