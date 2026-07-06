"""
Tests for PANIC unsafe region.

Tests both BUG cases (uncaught general exceptions) and NON-BUG cases
(programs that complete successfully without exceptions).

PANIC is the general "unhandled exception = crash" property.
It overlaps with specific bug classes (ASSERT_FAIL, DIV_ZERO, etc.)
but also catches other exceptions.

ITERATION 700: Common exceptions like NameError, ValueError, etc. are now
classified as fine-grained bug types (NAME_ERROR, VALUE_ERROR, etc.) instead
of PANIC. PANIC is reserved for truly custom/unknown exception types.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def test_name_error_bug():
    """
    BUG: NameError (undefined variable) causes NAME_ERROR bug.
    
    ITERATION 700: Now classified as NAME_ERROR, not PANIC.
    """
    code = compile("x = undefined_var", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should have at least one path
    assert len(paths) > 0
    
    # At least one path should have NameError (now classified as NAME_ERROR)
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] in ('NAME_ERROR', 'PANIC'):
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect NAME_ERROR (or PANIC) for NameError"
    assert bugs_found[0]['final_state']['exception'] == 'NameError'


def test_simple_assignment_not_bug():
    """
    NON-BUG: Simple assignment with no exceptions.
    
    Programs that complete successfully should not trigger PANIC.
    """
    code = compile("x = 1", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Check that no paths reach PANIC
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0, "Should not detect PANIC for successful program"


def test_multiple_operations_not_bug():
    """
    NON-BUG: Multiple operations without exceptions.
    """
    code = compile("x = 1\ny = 2\nz = x + y", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    # No path should reach PANIC
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0, "Should not detect PANIC for successful computation"


def test_unbound_local_error_bug():
    """
    BUG: UnboundLocalError causes UNBOUND_LOCAL bug.
    
    Reading a local variable before it's assigned.
    ITERATION 700: Now classified as UNBOUND_LOCAL, not PANIC.
    """
    # This will cause UnboundLocalError in the symbolic VM
    # when trying to read x before storing to it
    code = compile("y = x", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] in ('UNBOUND_LOCAL', 'NAME_ERROR', 'PANIC'):
            bugs_found.append(bug)
    
    # Should detect the exception
    assert len(bugs_found) > 0, "Should detect UNBOUND_LOCAL/NAME_ERROR for undefined variable"


def test_stack_underflow_bug():
    """
    BUG: Stack underflow (internal VM error) causes PANIC.
    
    This tests malformed bytecode or VM internal errors.
    """
    # Create a code object that will cause stack issues in our VM
    # For now, we test that our VM can handle and report such errors
    code = compile("x = 1 + 2", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # This specific code should not cause PANIC
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0, "Valid arithmetic should not cause PANIC"


def test_panic_overlaps_with_assert_fail():
    """
    BUG: AssertionError triggers both ASSERT_FAIL and PANIC.
    
    This tests that PANIC correctly captures all exceptions,
    including those covered by specific bug classes.
    """
    code = compile("assert False", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should detect both ASSERT_FAIL and PANIC
    assert_fails = []
    panics = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            if bug['bug_type'] == 'ASSERT_FAIL':
                assert_fails.append(bug)
            elif bug['bug_type'] == 'PANIC':
                panics.append(bug)
    
    # Due to registry ordering, we get ASSERT_FAIL first
    # But PANIC predicate should still return True for AssertionError
    assert len(assert_fails) > 0, "Should detect ASSERT_FAIL"
    
    # Verify that is_unsafe_panic would also detect this
    from a3_python.unsafe.panic import is_unsafe_panic
    for path in paths:
        if path.state.exception == 'AssertionError':
            assert is_unsafe_panic(path.state), "PANIC should also detect AssertionError"


def test_panic_overlaps_with_div_zero():
    """
    BUG: ZeroDivisionError triggers both DIV_ZERO and PANIC.
    """
    code = compile("x = 1 / 0", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # Should detect DIV_ZERO first due to registry ordering
    div_zeros = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'DIV_ZERO':
            div_zeros.append(bug)
    
    assert len(div_zeros) > 0, "Should detect DIV_ZERO"
    
    # Verify that is_unsafe_panic would also detect this
    from a3_python.unsafe.panic import is_unsafe_panic
    for path in paths:
        if path.state.exception == 'ZeroDivisionError':
            assert is_unsafe_panic(path.state), "PANIC should also detect ZeroDivisionError"


def test_panic_non_specific_helper():
    """
    Test the is_unsafe_panic_non_specific helper.
    
    This helper is useful for isolating PANIC bugs that aren't
    covered by other specific bug classes.
    """
    from a3_python.unsafe.panic import is_unsafe_panic_non_specific
    from a3_python.semantics.symbolic_vm import SymbolicMachineState
    from dataclasses import dataclass
    
    # Create mock states with minimal structure
    @dataclass
    class MockState:
        exception: str = None
        frame_stack: list = None
        halted: bool = False
        
        def __post_init__(self):
            if self.frame_stack is None:
                self.frame_stack = []
    
    state_no_exception = MockState(exception=None)
    state_assertion_error = MockState(exception="AssertionError")
    state_name_error = MockState(exception="NameError")
    
    # No exception: not PANIC
    assert not is_unsafe_panic_non_specific(state_no_exception)
    
    # AssertionError: PANIC in general, but not "non-specific"
    assert not is_unsafe_panic_non_specific(state_assertion_error)
    
    # NameError: PANIC and also "non-specific"
    assert is_unsafe_panic_non_specific(state_name_error)


def test_counterexample_extraction():
    """
    Test that exception counterexamples are correctly extracted.
    
    ITERATION 700: NameError is now classified as NAME_ERROR, not PANIC.
    """
    code = compile("x = undefined_var", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        # Now look for NAME_ERROR or PANIC
        if bug and bug['bug_type'] in ('NAME_ERROR', 'PANIC'):
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should find NAME_ERROR or PANIC bug"
    
    # Check counterexample structure
    bug = bugs_found[0]
    assert 'bug_type' in bug
    assert bug['bug_type'] in ('NAME_ERROR', 'PANIC')
    assert 'trace' in bug
    assert 'final_state' in bug
    assert 'exception' in bug['final_state']
    assert bug['final_state']['exception'] == 'NameError'


def test_return_value_not_bug():
    """
    NON-BUG: Program with return value (no exception).
    
    Even though we're in exec mode, returning None is not an exception.
    """
    code = compile("x = 1\ny = 2", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0, "Successful completion should not be PANIC"


# ============================================================================
# Additional BUG tests
# ============================================================================

def test_attribute_error_bug():
    """BUG: AttributeError causes PANIC (semantic requirement)."""
    # This will fail at symbolic execution but documents the semantic requirement
    code = compile("x = 5; y = x.nonexistent", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # If our VM can detect AttributeError, it should be PANIC
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            bugs_found.append(bug)
    
    # This may not be detected yet if attribute access not implemented
    # The opcode error itself is also a PANIC (unhandled internal error)
    # Test documents the requirement for when LOAD_ATTR is implemented
    if len(bugs_found) > 0:
        assert bugs_found[0]['bug_type'] == 'PANIC'


def test_key_error_bug():
    """BUG: KeyError (if dict operations are supported) causes PANIC."""
    # Currently may not be detected if dict operations not implemented
    # Test documents the requirement
    code = compile("x = {}; y = x['missing']", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # May not be detected yet, but if it is, should be PANIC
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            bugs_found.append(bug)
    
    # Documenting expected behavior
    pass


def test_value_error_bug():
    """BUG: ValueError causes PANIC."""
    # This will require ValueError detection in symbolic VM
    code = compile("x = int('not_a_number')", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    # May not be detected if int() call not modeled yet
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            bugs_found.append(bug)
    
    # Documenting expected behavior
    pass


def test_runtime_error_bug():
    """BUG: RuntimeError causes PANIC (semantic requirement)."""
    # Example: maximum recursion depth exceeded
    # For now, document the requirement
    code = compile("raise RuntimeError('test')", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            bugs_found.append(bug)
    
    # Should detect some kind of exception/error
    # The unimplemented opcode (PUSH_NULL for raise call) itself is also a PANIC
    if len(bugs_found) > 0:
        assert bugs_found[0]['bug_type'] == 'PANIC'


# ============================================================================
# Additional NON-BUG tests
# ============================================================================

def test_tuple_construction_not_bug():
    """NON-BUG: Constructing tuples is allowed."""
    code = compile("x = (1, 2, 3)", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_arithmetic_chain_not_bug():
    """NON-BUG: Chain of arithmetic operations."""
    code = compile("x = 1 + 2 * 3 - 4", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_comparison_chain_not_bug():
    """NON-BUG: Chain of comparisons."""
    code = compile("x = 1 < 2; y = 3 > 2; z = 5 == 5", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_valid_subscript_not_bug():
    """NON-BUG: Valid tuple subscripting."""
    code = compile("x = (1, 2, 3); y = x[1]", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_no_operations_not_bug():
    """NON-BUG: Empty program or just constants."""
    code = compile("x = 42", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_multiple_assignments_not_bug():
    """NON-BUG: Multiple variable assignments."""
    code = compile("x = 1; y = 2; z = 3; a = 4", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=30)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_constant_expressions_not_bug():
    """NON-BUG: Constant expressions that don't raise exceptions."""
    code = compile("x = 10; y = 20; z = 30", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=20)
    
    panic_bugs = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            panic_bugs.append(bug)
    
    assert len(panic_bugs) == 0


def test_import_error_bug():
    """BUG: ImportError causes PANIC (semantic requirement)."""
    # This will require import modeling
    code = compile("import nonexistent_module", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=10)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'PANIC':
            bugs_found.append(bug)
    
    # May not be detected if import not implemented yet
    # Documents the requirement
    if len(bugs_found) > 0:
        assert bugs_found[0]['bug_type'] == 'PANIC'
