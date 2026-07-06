"""
Test integration of intraprocedural analysis with InterproceduralBugTracker.

This validates that the InterproceduralBugTracker now runs intraprocedural
analysis for each function to find bugs within function bodies.
"""

import tempfile
from pathlib import Path
import pytest

from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker


def test_interprocedural_tracker_finds_intraprocedural_bugs():
    """Test that InterproceduralBugTracker runs intraprocedural analysis."""
    
    # Create a temporary Python file with a cleartext logging bug
    code = """
def main():
    from getpass import getpass
    password = getpass()
    print(password)  # CLEARTEXT_LOGGING or LOG_INJECTION bug

if __name__ == "__main__":
    main()
"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_app.py"
        test_file.write_text(code)
        
        # Build tracker for this directory
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        
        # Find all bugs
        bugs = tracker.find_all_bugs()
        
        # Should find bugs related to printing sensitive data
        # Either CLEARTEXT_LOGGING or LOG_INJECTION (both valid for print)
        sensitive_bugs = [b for b in bugs if b.bug_type in ("CLEARTEXT_LOGGING", "LOG_INJECTION")]
        
        assert len(sensitive_bugs) > 0, f"Expected sensitive data bug, found bugs: {[b.bug_type for b in bugs]}"
        
        bug = sensitive_bugs[0]
        assert bug.crash_function == "test_app.main"
        assert "print" in bug.reason.lower() or "password" in bug.reason.lower() or "sink" in bug.reason.lower()


def test_interprocedural_tracker_caches_intraprocedural_results():
    """Test that intraprocedural analysis results are cached."""
    
    code = """
def helper():
    from getpass import getpass
    password = getpass()
    print(password)

def main():
    helper()
    helper()  # Called twice - should only analyze once

if __name__ == "__main__":
    main()
"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_app.py"
        test_file.write_text(code)
        
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        bugs = tracker.find_all_bugs()
        
        # Should find bugs via intraprocedural analysis  
        # Either CLEARTEXT_LOGGING or LOG_INJECTION
        sensitive_bugs = [b for b in bugs if b.bug_type in ("CLEARTEXT_LOGGING", "LOG_INJECTION")]
        assert len(sensitive_bugs) > 0
        
        # Check that results are cached
        assert "test_app.helper" in tracker._intraprocedural_bugs


def test_both_interprocedural_and_intraprocedural_bugs():
    """Test that bugs are found via summary-based interprocedural analysis."""
    
    code = """
def get_password():
    from getpass import getpass
    return getpass()

def main():
    # Interprocedural bug: get_password() returns σ (sensitive)
    # and main() uses it at a print sink
    password = get_password()
    print(password)  # Should be found via taint summary
    
def helper():
    # Intraprocedural bug: direct in-function sensitive data -> print
    from getpass import getpass
    pwd = getpass()
    print(pwd)  # Should be found by intraprocedural analysis

if __name__ == "__main__":
    main()
    helper()
"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_app.py"
        test_file.write_text(code)
        
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        bugs = tracker.find_all_bugs()
        
        # Should find bugs in both helper (intraprocedural) and possibly main (interprocedural)
        sensitive_bugs = [b for b in bugs if b.bug_type in ("CLEARTEXT_LOGGING", "LOG_INJECTION")]
        assert len(sensitive_bugs) > 0, f"Expected sensitive data bugs, found: {[b.bug_type for b in bugs]}"
        
        # Should find bug in helper function via intraprocedural analysis
        helper_bugs = [b for b in sensitive_bugs if b.crash_function == "test_app.helper"]
        assert len(helper_bugs) > 0, "Expected bug in helper() via intraprocedural analysis"


def test_no_crash_on_function_without_code_object():
    """Test that analysis doesn't crash on functions without code objects."""
    
    code = """
def main():
    pass

if __name__ == "__main__":
    main()
"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_app.py"
        test_file.write_text(code)
        
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        
        # Should not crash
        bugs = tracker.find_all_bugs()
        
        # May or may not find bugs, but shouldn't crash
        assert isinstance(bugs, list)
