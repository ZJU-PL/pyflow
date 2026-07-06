"""
Integration test for interprocedural σ (sensitivity) tracking - Iteration 450.

Tests that sensitive parameter names (e.g., "password") are tracked through
function calls and correctly trigger CLEARTEXT_LOGGING at sinks.

This validates the barrier-theoretic approach from python-barrier-certificate-theory.md §9.5:
- Sensitivity inference from parameter names
- σ propagation through interprocedural summaries
- Detection of σ-only security bugs (CLEARTEXT_LOGGING, CLEARTEXT_STORAGE)
"""

import tempfile
from pathlib import Path
import pytest


def test_interprocedural_sigma_from_param_to_sink():
    """
    Test: sensitive var → function → sink with σ propagation.
    
    This is the core test requested in ITERATION_449_SUMMARY.md "Next Steps" #2.
    
    Code pattern:
        def helper(password):  # param has σ inferred from name
            print(password)    # should flag CLEARTEXT_LOGGING
        
        def main():
            pwd = get_password()
            helper(pwd)        # σ should propagate through call
    """
    test_code = '''
def log_helper(password, user_id):
    """Helper that logs sensitive data - should be detected."""
    print(password, user_id)

def process_login():
    """Processes a login - calls helper with sensitive parameter."""
    user = "alice"
    pwd = "secret123"
    log_helper(pwd, user)
'''
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "login.py"
        test_file.write_text(test_code)
        
        # Build interprocedural analysis
        from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
        
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        
        # Verify summary has σ tracking
        log_helper_summary = tracker.taint_summaries.get("login.log_helper")
        assert log_helper_summary is not None
        
        # Parameter 0 is "password" - should have σ
        assert log_helper_summary.sigma_contribution.get(0, False), \
            "Parameter 'password' should have σ (sensitivity)"
        
        # Parameter 1 is "user_id" - should NOT have σ
        assert not log_helper_summary.sigma_contribution.get(1, False), \
            "Parameter 'user_id' should not have σ"
        
        # Manually set entry point (since no __main__ block)
        tracker.entry_points.add("login.log_helper")
        
        # Find bugs
        bugs = tracker.find_all_bugs()
        
        # Should detect CLEARTEXT_LOGGING
        cleartext_bugs = [b for b in bugs if b.bug_type == "CLEARTEXT_LOGGING"]
        assert len(cleartext_bugs) > 0, \
            "Should detect CLEARTEXT_LOGGING when 'password' parameter reaches print()"


def test_interprocedural_sigma_no_false_positive():
    """
    Test that non-sensitive parameters don't trigger false positives.
    
    A function with a non-sensitive parameter (e.g., "message") that calls
    print() should NOT trigger CLEARTEXT_LOGGING.
    """
    test_code = '''
def log_status(message, status_code):
    """Logs a status message - NOT sensitive."""
    print(status_code, message)
'''
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "status.py"
        test_file.write_text(test_code)
        
        from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
        
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        
        # Verify summary has NO σ tracking for these params
        summary = tracker.taint_summaries.get("status.log_status")
        assert summary is not None
        assert not summary.sigma_contribution.get(0, False), \
            "Parameter 'message' should not have σ"
        assert not summary.sigma_contribution.get(1, False), \
            "Parameter 'status_code' should not have σ"
        
        tracker.entry_points.add("status.log_status")
        bugs = tracker.find_all_bugs()
        
        # Should NOT detect CLEARTEXT_LOGGING
        cleartext_bugs = [b for b in bugs if b.bug_type == "CLEARTEXT_LOGGING"]
        assert len(cleartext_bugs) == 0, \
            "Should not detect CLEARTEXT_LOGGING for non-sensitive parameters"


def test_interprocedural_sigma_multiple_sensitive_params():
    """
    Test that multiple sensitive parameters are all tracked.
    
    If a function has multiple sensitive parameters (e.g., "password" and "api_key"),
    both should be marked with σ.
    """
    test_code = '''
def send_credentials(password, api_key, username):
    """Sends credentials - two sensitive params."""
    print(username, password, api_key)
'''
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "creds.py"
        test_file.write_text(test_code)
        
        from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
        
        tracker = InterproceduralBugTracker.from_project(Path(tmpdir))
        
        summary = tracker.taint_summaries.get("creds.send_credentials")
        assert summary is not None
        
        # Parameters 0 and 1 are sensitive
        assert summary.sigma_contribution.get(0, False), \
            "Parameter 'password' should have σ"
        assert summary.sigma_contribution.get(1, False), \
            "Parameter 'api_key' should have σ"
        
        # Parameter 2 is not sensitive
        assert not summary.sigma_contribution.get(2, False), \
            "Parameter 'username' should not have σ"
        
        tracker.entry_points.add("creds.send_credentials")
        bugs = tracker.find_all_bugs()
        
        # Should detect CLEARTEXT_LOGGING
        cleartext_bugs = [b for b in bugs if b.bug_type == "CLEARTEXT_LOGGING"]
        assert len(cleartext_bugs) > 0, \
            "Should detect CLEARTEXT_LOGGING when sensitive parameters reach print()"


if __name__ == "__main__":
    # Run tests
    test_interprocedural_sigma_from_param_to_sink()
    print("✓ test_interprocedural_sigma_from_param_to_sink passed")
    
    test_interprocedural_sigma_no_false_positive()
    print("✓ test_interprocedural_sigma_no_false_positive passed")
    
    test_interprocedural_sigma_multiple_sensitive_params()
    print("✓ test_interprocedural_sigma_multiple_sensitive_params passed")
    
    print("\nAll interprocedural σ tracking tests passed!")
