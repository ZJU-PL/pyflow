"""
Tests for the full taint product lattice implementation (leak_theory.md).

Tests the Z3-integrated (τ, κ, σ) lattice model for all 47 CodeQL security bug types.
"""

import pytest
import z3

from a3_python.z3model.taint_lattice import (
    SourceType, SinkType, SanitizerType,
    TaintLabel, SymbolicTaintLabel,
    PCTaint, SymbolicPCTaint,
    SecurityBugType, CODEQL_BUG_TYPES,
    SecurityViolation, create_violation,
    create_unsafe_region_constraint, create_barrier_certificate,
    label_join, label_join_many,
    symbolic_label_join, symbolic_label_join_many,
    tau_zero, kappa_zero, kappa_full, sigma_zero,
    TAU_WIDTH, KAPPA_WIDTH, SIGMA_WIDTH,
    SANITIZER_TO_SINKS,
)


class TestTaintLabelBasics:
    """Test concrete TaintLabel operations."""
    
    def test_clean_label(self):
        """Clean label has no taint and full sanitization."""
        label = TaintLabel.clean()
        assert label.tau == 0
        assert label.kappa == (1 << KAPPA_WIDTH) - 1
        assert label.sigma == 0
        assert not label.has_untrusted_taint()
        assert not label.has_sensitivity()
    
    def test_untrusted_source_label(self):
        """Untrusted source sets τ bit and clears κ."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "test:1")
        assert label.tau == (1 << SourceType.HTTP_PARAM)
        assert label.kappa == 0  # Not sanitized
        assert label.sigma == 0
        assert label.has_untrusted_taint()
        assert not label.has_sensitivity()
    
    def test_sensitive_source_label(self):
        """Sensitive source sets σ bit."""
        label = TaintLabel.from_sensitive_source(SourceType.PASSWORD, "test:2")
        assert label.tau == 0
        assert label.sigma == (1 << SourceType.PASSWORD)
        assert not label.has_untrusted_taint()
        assert label.has_sensitivity()
    
    def test_label_join(self):
        """Join merges τ (∪), κ (∩), σ (∪)."""
        l1 = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        l2 = TaintLabel.from_untrusted_source(SourceType.ENVIRONMENT)
        
        joined = l1.join(l2)
        
        assert joined.tau == ((1 << SourceType.HTTP_PARAM) | (1 << SourceType.ENVIRONMENT))
        assert joined.kappa == 0  # ∩ of two empty sets
        assert joined.sigma == 0


class TestSinkSafety:
    """Test sink safety checks."""
    
    def test_clean_is_safe_for_all_sinks(self):
        """Clean label is safe for all sinks."""
        label = TaintLabel.clean()
        for sink in SinkType:
            assert label.is_safe_for_sink(sink), f"Clean should be safe for {sink.name}"
    
    def test_tainted_unsafe_for_injection_sink(self):
        """Tainted but unsanitized is unsafe for injection sinks."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        # Should be unsafe for SQL injection
        assert not label.is_safe_for_sink(SinkType.SQL_EXECUTE)
        assert not label.is_safe_for_sink(SinkType.COMMAND_SHELL)
        assert not label.is_safe_for_sink(SinkType.CODE_EVAL)
    
    def test_sanitized_is_safe(self):
        """Sanitized tainted value is safe for the sanitized sink."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        # Sanitize for SQL
        sanitized = label.sanitize(SanitizerType.PARAMETERIZED_QUERY)
        
        # Now safe for SQL
        assert sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)
        # But still unsafe for command injection
        assert not sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL)
    
    def test_sensitive_unsafe_for_log_sink(self):
        """Sensitive data is unsafe for logging sinks."""
        label = TaintLabel.from_sensitive_source(SourceType.PASSWORD)
        
        # Should be unsafe for logging (sensitivity check)
        assert not label.is_safe_for_sink(SinkType.LOG_OUTPUT)
        assert not label.is_safe_for_sink(SinkType.FILE_WRITE)


class TestSymbolicTaintLabel:
    """Test Z3 symbolic taint labels."""
    
    def test_clean_symbolic_label(self):
        """Clean symbolic label has zero τ/σ and full κ."""
        label = SymbolicTaintLabel.clean()
        
        solver = z3.Solver()
        solver.add(label.tau != tau_zero())
        assert solver.check() == z3.unsat
        
        solver = z3.Solver()
        solver.add(label.sigma != sigma_zero())
        assert solver.check() == z3.unsat
    
    def test_untrusted_source_symbolic(self):
        """Untrusted source creates symbolic label with τ bit set."""
        label = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        expected_bit = z3.BitVecVal(1 << SourceType.HTTP_PARAM, TAU_WIDTH)
        solver = z3.Solver()
        solver.add(label.tau != expected_bit)
        assert solver.check() == z3.unsat
    
    def test_symbolic_join(self):
        """Symbolic join follows lattice rules."""
        l1 = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        l2 = SymbolicTaintLabel.from_untrusted_source(SourceType.ENVIRONMENT)
        
        joined = l1.join(l2)
        
        # Result should have both bits set
        expected_tau = z3.BitVecVal(
            (1 << SourceType.HTTP_PARAM) | (1 << SourceType.ENVIRONMENT),
            TAU_WIDTH
        )
        solver = z3.Solver()
        solver.add(joined.tau != expected_tau)
        assert solver.check() == z3.unsat
    
    def test_unsafe_constraint_sat(self):
        """Unsafety constraint is SAT for tainted, unsanitized value."""
        label = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        unsafe = label.is_unsafe_for_sink_constraint(SinkType.SQL_EXECUTE)
        
        solver = z3.Solver()
        solver.add(unsafe)
        assert solver.check() == z3.sat
    
    def test_safety_constraint_sat_for_clean(self):
        """Safety constraint is SAT for clean value."""
        label = SymbolicTaintLabel.clean()
        
        safe = label.is_safe_for_sink_constraint(SinkType.SQL_EXECUTE)
        
        solver = z3.Solver()
        solver.add(safe)
        assert solver.check() == z3.sat


class TestCodeQLBugTypes:
    """Test all 47 CodeQL bug types are defined."""
    
    def test_all_47_bug_types_present(self):
        """All 47 CodeQL security bug types are defined."""
        assert len(CODEQL_BUG_TYPES) >= 47
    
    def test_injection_bugs_check_tau(self):
        """Injection bugs should check τ (untrusted taint)."""
        injection_bugs = [
            "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION",
            "PATH_INJECTION", "LDAP_INJECTION", "XPATH_INJECTION",
            "NOSQL_INJECTION", "REGEX_INJECTION", "SSRF", "XXE",
            "UNSAFE_DESERIALIZATION", "HEADER_INJECTION",
            "REFLECTED_XSS", "URL_REDIRECT", "TEMPLATE_INJECTION"
        ]
        for bug in injection_bugs:
            if bug in CODEQL_BUG_TYPES:
                assert CODEQL_BUG_TYPES[bug].checks_tau, f"{bug} should check τ"
    
    def test_sensitivity_bugs_check_sigma(self):
        """Sensitivity bugs should check σ."""
        sensitivity_bugs = [
            "CLEARTEXT_LOGGING", "CLEARTEXT_STORAGE",
            "CLEARTEXT_TRANSMISSION", "STACK_TRACE_EXPOSURE",
            "INFORMATION_EXPOSURE"
        ]
        for bug in sensitivity_bugs:
            if bug in CODEQL_BUG_TYPES:
                assert CODEQL_BUG_TYPES[bug].checks_sigma, f"{bug} should check σ"


class TestPCTaint:
    """Test implicit flow (PC taint) tracking."""
    
    def test_clean_pc_taint(self):
        """Clean PC taint has no effect."""
        pc = PCTaint()
        assert pc.is_clean()
        
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        result = pc.apply_to_assignment(label)
        assert result.tau == label.tau
    
    def test_pc_taint_propagates(self):
        """PC taint adds to assigned values."""
        pc = PCTaint(tau_pc=1 << SourceType.ENVIRONMENT)
        
        # Clean value gets PC taint
        label = TaintLabel.clean()
        result = pc.apply_to_assignment(label)
        assert result.tau == (1 << SourceType.ENVIRONMENT)
    
    def test_branch_merges_condition_taint(self):
        """Entering branch merges condition taint into PC."""
        pc = PCTaint()
        cond_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        new_pc = pc.merge_from_condition(cond_label)
        
        assert new_pc.tau_pc == (1 << SourceType.HTTP_PARAM)


class TestUnsafeRegionConstraint:
    """Test unsafe region constraint generation."""
    
    def test_sql_injection_constraint(self):
        """SQL injection constraint detects tainted query."""
        bug_type = CODEQL_BUG_TYPES["SQL_INJECTION"]
        label = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        constraint = create_unsafe_region_constraint(bug_type, label)
        
        solver = z3.Solver()
        solver.add(constraint)
        assert solver.check() == z3.sat
    
    def test_sanitized_constraint_unsat(self):
        """Sanitized value makes constraint UNSAT."""
        bug_type = CODEQL_BUG_TYPES["SQL_INJECTION"]
        label = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        # Sanitize for SQL
        sanitized = label.sanitize(SinkType.SQL_EXECUTE)
        
        constraint = create_unsafe_region_constraint(bug_type, sanitized)
        
        solver = z3.Solver()
        solver.add(constraint)
        # Should be UNSAT because sanitized
        assert solver.check() == z3.unsat


class TestBarrierCertificate:
    """Test barrier certificate generation for security."""
    
    def test_barrier_positive_for_clean(self):
        """Barrier is positive (safe) for clean value."""
        bug_type = CODEQL_BUG_TYPES["SQL_INJECTION"]
        label = SymbolicTaintLabel.clean()
        
        barrier = create_barrier_certificate(bug_type, label)
        
        # Barrier should be >= 1 (safe) for clean
        solver = z3.Solver()
        solver.add(barrier >= 1)
        assert solver.check() == z3.sat
    
    def test_barrier_negative_for_tainted(self):
        """Barrier is low (unsafe) for tainted unsanitized value."""
        bug_type = CODEQL_BUG_TYPES["SQL_INJECTION"]
        label = SymbolicTaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        barrier = create_barrier_certificate(bug_type, label, guard_sanitized=z3.BoolVal(False))
        
        # Barrier should be 0 (edge of unsafe)
        solver = z3.Solver()
        solver.add(barrier <= 0)
        assert solver.check() == z3.sat


class TestSanitizerToSinks:
    """Test sanitizer to sink mapping."""
    
    def test_shell_quote_sanitizes_command(self):
        """shlex.quote sanitizes for COMMAND_SHELL."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.SHELL_QUOTE]
        assert SinkType.COMMAND_SHELL in sinks
    
    def test_html_escape_sanitizes_output(self):
        """html.escape sanitizes for HTML_OUTPUT."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.HTML_ESCAPE]
        assert SinkType.HTML_OUTPUT in sinks
    
    def test_parameterized_query_sanitizes_sql(self):
        """Parameterized query sanitizes for SQL_EXECUTE."""
        sinks = SANITIZER_TO_SINKS[SanitizerType.PARAMETERIZED_QUERY]
        assert SinkType.SQL_EXECUTE in sinks


class TestSecurityViolation:
    """Test security violation creation."""
    
    def test_create_violation_from_bug_type(self):
        """Create violation includes CWE and description."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "app.py:10")
        
        violation = create_violation("SQL_INJECTION", "app.py:20", label)
        
        assert violation.bug_type == "SQL_INJECTION"
        assert violation.cwe == "CWE-089"
        assert violation.sink_type == SinkType.SQL_EXECUTE
        assert "app.py:20" in violation.sink_location
    
    def test_violation_source_summary(self):
        """Violation has source summary."""
        label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
        
        violation = create_violation("SQL_INJECTION", "test:1", label)
        
        summary = violation.get_source_summary()
        assert "HTTP_PARAM" in summary


class TestLatticeConstants:
    """Test lattice dimension constants."""
    
    def test_tau_width(self):
        """τ has correct width for source types."""
        assert TAU_WIDTH == 16
        assert TAU_WIDTH >= len([s for s in SourceType])
    
    def test_kappa_width(self):
        """κ has correct width for sink types."""
        assert KAPPA_WIDTH == 32
        assert KAPPA_WIDTH >= len([s for s in SinkType])
    
    def test_sigma_width(self):
        """σ has correct width for sensitivity sources."""
        assert SIGMA_WIDTH == 16


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
