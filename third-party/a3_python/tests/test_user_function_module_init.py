"""
Test for user function inlining in module initialization.

This is a regression test for iteration 130: user functions defined and called
in module init were not being inlined, leading to TYPE_CONFUSION false positives.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def test_user_function_string_return_concat():
    """
    User function returning string should not cause TYPE_CONFUSION when concatenated.
    
    This tests the specific pattern from sklearn/doc/api_reference.py:
    - Function defined in module scope
    - Returns a string
    - Called and result concatenated with another string
    
    Expected: SAFE (no bug, or at least not TYPE_CONFUSION)
    """
    code = """
def _get_guide():
    return "Hello"

description = _get_guide() + " World"
"""
    
    code_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code_obj, max_steps=200)
    
    # Check for bugs in explored paths
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    # Should find no TYPE_CONFUSION bugs
    type_confusion_bugs = [bug for bug in bugs_found if bug['bug_type'] == 'TYPE_CONFUSION']
    assert len(type_confusion_bugs) == 0, (
        f"False positive TYPE_CONFUSION: user function returns string, "
        f"concatenation should succeed. Found bugs: {type_confusion_bugs}"
    )


def test_user_function_with_parameter():
    """
    Test that user functions with parameters can be inlined.
    """
    code = """
def add_greeting(name):
    return "Hello, " + name

message = add_greeting("World")
"""
    
    code_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code_obj, max_steps=200)
    
    # Check for bugs
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    # Should find no TYPE_CONFUSION bugs
    type_confusion_bugs = [bug for bug in bugs_found if bug['bug_type'] == 'TYPE_CONFUSION']
    assert len(type_confusion_bugs) == 0, (
        f"False positive TYPE_CONFUSION with parameterized function: {type_confusion_bugs}"
    )


def test_user_function_multiple_returns():
    """
    Test user function with multiple return paths.
    """
    code = """
def get_value(x):
    if x > 0:
        return "positive"
    else:
        return "non-positive"

result = get_value(5) + " number"
"""
    
    code_obj = compile(code, "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code_obj, max_steps=300)
    
    # Check for bugs
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug:
            bugs_found.append(bug)
    
    # Should find no TYPE_CONFUSION bugs (both paths return strings)
    type_confusion_bugs = [bug for bug in bugs_found if bug['bug_type'] == 'TYPE_CONFUSION']
    assert len(type_confusion_bugs) == 0, (
        f"False positive TYPE_CONFUSION with multiple returns: {type_confusion_bugs}"
    )

