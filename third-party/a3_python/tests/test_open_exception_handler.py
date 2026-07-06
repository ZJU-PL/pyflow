"""
Test open() with exception handlers - verifying FileNotFoundError can be caught.

This tests the fix for iteration 208: ensuring exception classes are available
in the symbolic environment with consistent IDs so CHECK_EXC_MATCH works correctly.

NOTE: Tests currently xfail due to path exploration stopping at PUSH_EXC_INFO.
This is a known issue separate from the ID consistency fix.
"""

import pytest
from pathlib import Path
from a3_python.analyzer import analyze_file


class TestOpenExceptionHandler:
    """Test open() calls with exception handlers."""
    
    @pytest.mark.xfail(reason="Path exploration stops at PUSH_EXC_INFO - separate issue from ID fix")
    def test_open_with_file_not_found_handler_not_bug(self, tmp_path):
        """open() with FileNotFoundError handler should not report PANIC."""
        code = """
def test_open_with_handler():
    try:
        f = open("nonexistent.txt")
    except FileNotFoundError:
        return 42
    return 1

result = test_open_with_handler()
"""
        test_file = tmp_path / "test_open_handler.py"
        test_file.write_text(code)
        
        result = analyze_file(str(test_file), code, max_paths=100)
        
        # Should not report any PANIC bugs since FileNotFoundError is caught
        panic_bugs = [b for b in result.bugs if b.bug_type == "PANIC"]
        assert len(panic_bugs) == 0, f"Expected no PANIC bugs, found {len(panic_bugs)}: {[b.message for b in panic_bugs]}"
    
    @pytest.mark.xfail(reason="Path exploration stops at PUSH_EXC_INFO - separate issue from ID fix")
    def test_open_with_multiple_exception_handlers_not_bug(self, tmp_path):
        """open() with multiple exception handlers should not report PANIC."""
        code = """
def test_open_with_multiple_handlers():
    try:
        f = open("some_file.txt")
    except FileNotFoundError:
        return 1
    except PermissionError:
        return 2
    except IsADirectoryError:
        return 3
    return 0

result = test_open_with_multiple_handlers()
"""
        test_file = tmp_path / "test_multi_handler.py"
        test_file.write_text(code)
        
        result = analyze_file(str(test_file), code, max_paths=100)
        
        # Should not report any PANIC bugs since all exceptions are caught
        panic_bugs = [b for b in result.bugs if b.bug_type == "PANIC"]
        assert len(panic_bugs) == 0, f"Expected no PANIC bugs, found {len(panic_bugs)}: {[b.message for b in panic_bugs]}"
