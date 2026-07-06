"""
End-to-end test for concrete taint path requirement (Iteration 524).

This test simulates the false positive pattern found in PyGoat triage:
- Generic "function is a sink" detection without taint flow
- Should NOT be reported as a violation
"""

from a3_python.z3model.taint_lattice import TaintLabel, SourceType
from a3_python.contracts.security_lattice import check_sink_taint


def test_redirect_without_taint_flow():
    """
    Simulate PyGoat false positive: URL_REDIRECT sink detection without actual taint.
    
    Pattern from pygoat_triage_iter522.md:
    - Finding: "URL_REDIRECT at challenge.views.DoItFast.delete"
    - Reason: "Function is a URL_REDIRECT sink"
    - Problem: No actual redirect() call with tainted data
    
    This should NOT be reported as a violation.
    """
    # Simulate checking a function that COULD do redirects
    # but doesn't have any actual tainted data flowing to redirect
    
    # Create clean labels (no taint)
    clean_labels = [TaintLabel.clean() for _ in range(3)]
    
    # Check redirect sink
    violations = check_sink_taint(
        function_id='redirect',
        location='challenge/views.py:DoItFast.delete',
        arg_labels=clean_labels,
        kwargs={}
    )
    
    # Should NOT report violation - no taint
    assert len(violations) == 0, (
        "Should not report URL_REDIRECT without tainted data"
    )


def test_redirect_with_taint_flow_is_reported():
    """
    Contrast test: actual redirect with tainted URL SHOULD be reported.
    """
    # User-controlled input with provenance
    user_url = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location='request.GET.get("next")'
    )
    
    # Check redirect sink with tainted URL
    violations = check_sink_taint(
        function_id='redirect',
        location='views.py:redirect_after_login',
        arg_labels=[user_url],
        kwargs={}
    )
    
    # SHOULD report violation - concrete taint path exists
    assert len(violations) > 0, "Should report URL_REDIRECT with tainted URL"
    assert violations[0].bug_type == 'URL_REDIRECT'
    
    # Verify provenance is present in violation
    assert violations[0].taint_label.provenance, "Violation should have provenance"
    assert 'request.GET.get' in str(violations[0].taint_label.provenance)


def test_sql_injection_false_positive_eliminated():
    """
    Test that SQL_INJECTION is only reported with concrete taint path.
    
    This prevents false positives like:
    - "This function calls cursor.execute()" without actual user input
    """
    # Database query with clean (hardcoded) data
    clean_query = TaintLabel.clean()
    
    # Check SQL sink
    violations = check_sink_taint(
        function_id='cursor.execute',
        location='database.py:get_user_by_id',
        arg_labels=[clean_query],
        kwargs={}
    )
    
    # Should NOT report - no taint
    assert len(violations) == 0, "Should not report SQL_INJECTION without tainted query"


def test_sql_injection_true_positive_still_caught():
    """
    Verify true positives are still caught after adding provenance requirement.
    """
    # User input with provenance
    user_input = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location='input("Enter username: ")'
    )
    
    # Construct query with user input (classic SQL injection)
    query = user_input  # Simulates: f"SELECT * FROM users WHERE name = '{user_input}'"
    
    # Check SQL sink
    violations = check_sink_taint(
        function_id='cursor.execute',
        location='database.py:search_users',
        arg_labels=[query],
        kwargs={}
    )
    
    # SHOULD report - true positive
    assert len(violations) > 0, "Should report SQL_INJECTION with tainted query"
    assert violations[0].bug_type == 'SQL_INJECTION'
    assert violations[0].taint_label.provenance


def test_command_injection_with_argv():
    """
    Test command injection detection with sys.argv source.
    """
    # Command-line argument with provenance
    argv_input = TaintLabel.from_untrusted_source(
        SourceType.ARGV,
        location='sys.argv[1]'
    )
    
    # Check subprocess.call with shell=True
    violations = check_sink_taint(
        function_id='subprocess.call',
        location='script.py:run_command',
        arg_labels=[argv_input],
        kwargs={'shell': True}
    )
    
    # SHOULD report
    assert len(violations) > 0
    assert violations[0].bug_type == 'COMMAND_INJECTION'
    assert 'sys.argv' in str(violations[0].taint_label.provenance)


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
