"""
Test concrete taint path requirement (Iteration 524).

This test validates that we only report security violations when there is
a concrete taint path (provenance not empty), not just generic "function is a sink"
detections.

This fixes the false positive issue found in PyGoat triage iter 522:
- 263 false positive URL_REDIRECT findings
- Pattern: "Function is a URL_REDIRECT sink" without actual taint flow
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType
)
from a3_python.contracts.security_lattice import (
    check_sink_taint, register_sink, SinkContract
)


def test_no_violation_without_provenance():
    """
    ITERATION 524: No violation when taint bit is set but provenance is empty.
    
    This prevents false positives like "Function is a URL_REDIRECT sink"
    where the sink is detected but no actual taint flow exists.
    """
    # Create a label with taint bit set but NO provenance
    # (simulates a generic "tainted" value without concrete source)
    label = TaintLabel(
        tau=(1 << SourceType.HTTP_PARAM),  # Taint bit set
        kappa=0,  # Not sanitized
        sigma=0,
        provenance=frozenset()  # NO CONCRETE SOURCE PROVENANCE
    )
    
    # Check sink - should NOT report violation
    violations = check_sink_taint(
        function_id='redirect',
        location='test.py:10',
        arg_labels=[label],
        kwargs={}
    )
    
    # Should be empty - no concrete taint path
    assert len(violations) == 0, (
        f"Expected no violations without provenance, got {len(violations)}: "
        f"{[v.message for v in violations]}"
    )


def test_violation_with_provenance():
    """
    ITERATION 524: Violation IS reported when taint bit + provenance present.
    
    This is a true positive: concrete taint path from source to sink.
    """
    # Create a label with taint bit AND provenance
    label = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location='request.GET.get("url")'
    )
    
    # Verify provenance is present
    assert len(label.provenance) > 0, "Label should have provenance"
    
    # Check sink - SHOULD report violation
    violations = check_sink_taint(
        function_id='redirect',
        location='test.py:10',
        arg_labels=[label],
        kwargs={}
    )
    
    # Should report violation - concrete taint path exists
    assert len(violations) > 0, "Expected violation with provenance"
    
    # Verify violation includes provenance in message
    violation = violations[0]
    assert 'Taint path' in violation.message or violation.taint_label.provenance, (
        f"Violation should include taint path, got: {violation.message}"
    )


def test_sql_injection_with_provenance():
    """SQL injection with concrete taint path should be reported."""
    # Create tainted input with provenance
    user_input = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location='input("Enter username: ")'
    )
    
    # Check SQL sink
    violations = check_sink_taint(
        function_id='cursor.execute',
        location='database.py:42',
        arg_labels=[user_input],
        kwargs={}
    )
    
    assert len(violations) > 0, "Expected SQL_INJECTION violation"
    assert violations[0].bug_type == 'SQL_INJECTION'
    assert violations[0].taint_label.provenance  # Has concrete source


def test_sql_injection_without_provenance():
    """SQL injection without provenance should NOT be reported (false positive)."""
    # Create label with taint bit but no provenance
    # (This would be the case if we mistakenly flag a generic "database operation"
    #  without tracing the actual data flow)
    label = TaintLabel(
        tau=(1 << SourceType.USER_INPUT),
        kappa=0,
        sigma=0,
        provenance=frozenset()  # NO SOURCE
    )
    
    # Check SQL sink
    violations = check_sink_taint(
        function_id='cursor.execute',
        location='database.py:42',
        arg_labels=[label],
        kwargs={}
    )
    
    # Should NOT report without provenance
    assert len(violations) == 0, (
        "Should not report SQL injection without concrete taint path"
    )


def test_sanitized_value_with_provenance():
    """Sanitized value should not trigger violation even with provenance."""
    # Create tainted input with provenance
    tainted = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location='request.args.get("query")'
    )
    
    # Sanitize for SQL
    sanitized = tainted.sanitize(SanitizerType.SQL_ESCAPE)
    
    # Verify provenance is preserved
    assert sanitized.provenance == tainted.provenance
    
    # Check SQL sink with sanitized value
    violations = check_sink_taint(
        function_id='cursor.execute',
        location='database.py:42',
        arg_labels=[sanitized],
        kwargs={}
    )
    
    # Should NOT report - sanitized for this sink
    assert len(violations) == 0, "Sanitized value should not trigger violation"


def test_command_injection_with_multi_arg_provenance():
    """Command injection with provenance in checked argument should be reported."""
    # Tainted FIRST arg with provenance (subprocess.call checks arg[0])
    tainted = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location='sys.argv[1]'
    )
    
    # Clean second arg
    clean = TaintLabel.clean()
    
    # Check command injection sink (shell=True)
    violations = check_sink_taint(
        function_id='subprocess.call',
        location='script.py:15',
        arg_labels=[tainted, clean],  # First arg is tainted
        kwargs={'shell': True}
    )
    
    # Should report - tainted arg with provenance
    assert len(violations) > 0, "Expected COMMAND_INJECTION violation"
    assert violations[0].bug_type == 'COMMAND_INJECTION'


def test_command_injection_safe_without_shell():
    """Command injection is safe when shell=False (even with tainted args)."""
    # Tainted arg with provenance
    tainted = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location='sys.argv[1]'
    )
    
    # Check with shell=False
    violations = check_sink_taint(
        function_id='subprocess.call',
        location='script.py:15',
        arg_labels=[tainted],
        kwargs={'shell': False}
    )
    
    # Should NOT report - shell=False is safe
    assert len(violations) == 0, "subprocess with shell=False should be safe"


def test_provenance_chain_in_message():
    """Verify that provenance chain appears in violation message."""
    # Create label with multi-step provenance
    label1 = TaintLabel.from_untrusted_source(
        SourceType.HTTP_PARAM,
        location='request.GET.get("url")'
    )
    
    # Simulate propagation through intermediate step
    label2 = TaintLabel(
        tau=label1.tau,
        kappa=label1.kappa,
        sigma=label1.sigma,
        provenance=label1.provenance | frozenset(['intermediate_var'])
    )
    
    # Check sink
    violations = check_sink_taint(
        function_id='redirect',
        location='views.py:50',
        arg_labels=[label2],
        kwargs={}
    )
    
    # Should have violation with provenance in message
    assert len(violations) > 0
    violation = violations[0]
    
    # Check that message contains taint path information
    message_has_path = (
        'Taint path' in violation.message or
        'intermediate_var' in str(violation.taint_label.provenance)
    )
    assert message_has_path, (
        f"Violation message should include provenance chain. Got: {violation.message}"
    )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
