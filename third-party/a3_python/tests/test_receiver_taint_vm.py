"""
Test receiver taint checking in security contracts.

Validates that SinkContract.check_receiver flag properly checks taint on
the receiver object (self) for method calls, not just explicit arguments.
"""

import pytest
from a3_python.contracts.security_lattice import (
    get_sink_contract,
    check_sink_taint,
    init_security_contracts,
)
from a3_python.z3model.taint_lattice import (
    TaintLabel,
    SourceType,
    SinkType,
    SanitizerType,
)


def test_pattern_match_receiver_taint():
    """
    Test that Pattern.match checks receiver taint, not argument taint.
    
    For: pattern.match(text)
    - If pattern is tainted (from re.compile(user_input)), flag violation
    - Arguments (text) don't matter for Pattern methods
    """
    init_security_contracts()
    
    # Tainted pattern (compiled from user input)
    tainted_pattern = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location="re.compile(user_input)"
    )
    
    # Clean text argument
    clean_text = TaintLabel.clean()
    
    # Check: Pattern.match called with tainted receiver
    # Pass receiver_label separately (new parameter)
    violations = check_sink_taint(
        "Pattern.match",
        "test_location",
        [clean_text],  # args (text being matched - clean)
        {},  # kwargs
        receiver_label=tainted_pattern  # receiver (pattern object - tainted)
    )
    
    # Should detect REGEX_INJECTION because receiver is tainted
    assert len(violations) == 1, f"Expected 1 violation for tainted receiver, got {len(violations)}"
    assert violations[0].bug_type == "REGEX_INJECTION"
    assert violations[0].cwe == "CWE-730"  # Regex injection
    
    # Verify provenance includes original taint source  
    # Provenance is a frozenset of location strings
    assert len(tainted_pattern.provenance) > 0, "Tainted pattern should have provenance"
    provenance_str = " ".join(tainted_pattern.provenance)
    assert "re.compile" in provenance_str or "user_input" in provenance_str


def test_pattern_match_clean_receiver():
    """
    Test that Pattern.match does NOT flag violation when receiver is clean.
    
    For: pattern.match(tainted_text)
    - If pattern is clean (from re.compile(r"literal")), no violation
    - Even if text argument is tainted
    """
    init_security_contracts()
    
    # Clean pattern (compiled from literal)
    clean_pattern = TaintLabel.clean()
    
    # Tainted text argument
    tainted_text = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location="input()"
    )
    
    # Check: Pattern.match called with clean receiver, tainted arg
    violations = check_sink_taint(
        "Pattern.match",
        "test_location",
        [tainted_text],  # args (text being matched - tainted)
        {},  # kwargs
        receiver_label=clean_pattern  # receiver (pattern object - clean)
    )
    
    # Should NOT detect violation (receiver is clean)
    assert len(violations) == 0, f"Expected 0 violations for clean receiver, got {len(violations)}"


def test_receiver_taint_requires_provenance():
    """
    Test that receiver taint violations require concrete provenance.
    
    Generic taint without provenance should not trigger violations
    (to avoid false positives from conservative analysis).
    """
    init_security_contracts()
    
    # Tainted receiver without provenance (generic/conservative taint)
    # Create a label with taint but empty provenance using dataclasses.replace()
    import dataclasses
    base_label = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location="source"
    )
    # Remove provenance to simulate conservative/generic taint
    generic_taint = dataclasses.replace(base_label, provenance=frozenset())
    
    violations = check_sink_taint(
        "Pattern.match",
        "test_location",
        [],
        {},
        receiver_label=generic_taint
    )
    
    # Should NOT report (no provenance = conservative approximation)
    assert len(violations) == 0, "Generic taint without provenance should not trigger violations"


def test_sanitized_receiver():
    """
    Test that sanitized receiver does not trigger violation.
    
    For: pattern.match(text) where pattern from re.compile(re.escape(user_input))
    - Receiver has taint source, but is sanitized for REGEX_PATTERN sink
    """
    init_security_contracts()
    
    # Tainted but sanitized pattern
    tainted = TaintLabel.from_untrusted_source(
        SourceType.USER_INPUT,
        location="user_input"
    )
    sanitized_pattern = tainted.sanitize(SanitizerType.RE_ESCAPE)
    
    violations = check_sink_taint(
        "Pattern.match",
        "test_location",
        [],
        {},
        receiver_label=sanitized_pattern
    )
    
    # Should NOT trigger (sanitized)
    assert len(violations) == 0, "Sanitized receiver should not trigger violations"


def test_check_receiver_flag_is_set():
    """
    Verify that Pattern methods have check_receiver=True flag set.
    """
    init_security_contracts()
    
    contracts = [
        "Pattern.match",
        "Pattern.search",
        "Pattern.findall",
        "Pattern.finditer",
        "Pattern.fullmatch",
        "Pattern.split",
        "Pattern.sub",
        "Pattern.subn",
    ]
    
    for func_name in contracts:
        contract = get_sink_contract(func_name)
        assert contract is not None, f"{func_name} should be registered"
        assert contract.check_receiver, f"{func_name} should have check_receiver=True"
        assert len(contract.tainted_arg_indices) == 0, f"{func_name} should have empty tainted_arg_indices"

