"""
Tests for IMPORT_FROM opcode implementation.

Validates that the symbolic VM correctly handles import statements
like `from module import name`.
"""

import sys
import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def test_import_from_basic():
    """Test basic from-import statement."""
    code = compile("""
from math import sqrt
x = sqrt(4)
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should not report PANIC for IMPORT_FROM
    for path in paths:
        bugs = check_unsafe_regions(path.state, path.trace)
        if bugs and bugs['bug_type'] == 'PANIC':
            # Check if it's due to IMPORT_FROM
            trace_str = '\n'.join(path.trace)
            assert 'IMPORT_FROM' not in trace_str, f"PANIC due to IMPORT_FROM in trace: {trace_str}"


def test_import_from_multiple():
    """Test multiple imports from same module."""
    code = compile("""
from math import sqrt, sin, cos
x = sqrt(4)
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete at least one path
    assert len(paths) > 0, "Should explore at least one path"
    
    # Check no PANIC from IMPORT_FROM
    for path in paths:
        bugs = check_unsafe_regions(path.state, path.trace)
        if bugs and bugs['bug_type'] == 'PANIC':
            trace_str = '\n'.join(path.trace)
            assert 'IMPORT_FROM' not in trace_str, f"PANIC due to IMPORT_FROM"


def test_import_from_preserves_module_on_stack():
    """Test that IMPORT_FROM leaves module on stack for multiple imports."""
    code = compile("""
from math import sqrt, log
x = 1
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete successfully
    assert len(paths) > 0, "Should complete at least one path"
    
    # Check final state doesn't have stack underflow
    for path in paths:
        if path.state.frame_stack:
            assert path.state.exception is None or 'StackUnderflow' not in str(path.state.exception)


def test_import_from_does_not_pop_module():
    """Test that IMPORT_FROM leaves module on TOS for next import."""
    code = compile("""
from os import path, environ
x = 1
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    assert len(paths) > 0, "Should explore successfully"
    
    # All paths should complete without stack errors
    for path in paths:
        bugs = check_unsafe_regions(path.state, path.trace)
        if bugs:
            assert bugs['bug_type'] != 'PANIC' or 'Stack' not in str(bugs.get('message', ''))


def test_import_from_click_parser_pattern():
    """Test the exact pattern that caused PANIC in click tests."""
    # This is the pattern from click's test_parser.py
    code = compile("""
from click.parser import _OptionParser
x = 1
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    # Should explore at least one path
    assert len(paths) > 0, "Should explore at least one path"
    
    # Check traces don't show IMPORT_FROM failure
    for path in paths:
        trace_str = '\n'.join(path.trace)
        # If IMPORT_FROM appears in trace, it should not be followed by EXCEPTION
        if 'IMPORT_FROM' in trace_str:
            # The next line after IMPORT_FROM should not be an exception
            lines = trace_str.split('\n')
            for i, line in enumerate(lines):
                if 'IMPORT_FROM' in line and i+1 < len(lines):
                    next_line = lines[i+1]
                    assert 'EXCEPTION: Opcode IMPORT_FROM' not in next_line


def test_import_from_collections_abc():
    """Test importing from collections.abc (common in flask/requests)."""
    code = compile("""
from collections.abc import Mapping
x = 1
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    assert len(paths) > 0, "Should explore successfully"
    
    # Verify IMPORT_FROM executed successfully
    for path in paths:
        trace_str = '\n'.join(path.trace)
        if 'IMPORT_FROM' in trace_str:
            # Should not have exception immediately after
            assert 'EXCEPTION: Opcode IMPORT_FROM' not in trace_str


def test_import_from_then_store():
    """Test IMPORT_FROM followed by STORE_NAME (standard pattern)."""
    code = compile("""
from math import sqrt
result = sqrt(16)
""", "<test>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=100)
    
    # Should complete
    assert len(paths) > 0
    
    # Check that we can reach STORE_NAME after IMPORT_FROM
    for path in paths:
        trace_str = '\n'.join(path.trace)
        if 'IMPORT_FROM' in trace_str:
            # Should have STORE_NAME after IMPORT_FROM
            assert 'STORE_NAME' in trace_str


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
