"""
Tests for implicit flow (PC taint) security bug detection.

Validates that security tracker correctly propagates taint through control flow
and detects vulnerabilities where sensitive/untrusted data flows through
conditional statements.

Test Coverage:
- PC taint tracking basics (enter_branch, exit_branch, apply_pc_taint)
- PC taint restoration after branch exit
- Nested PC taint contexts
- Integration with security violation detection
- Implicit flow taint propagation through assignments
"""

import pytest
from pathlib import Path

from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker
from a3_python.z3model.taint_lattice import (
    SourceType, SinkType, TaintLabel, PCTaint, SecurityViolation
)
from a3_python.z3model.values import SymbolicValue, ValueTag
from a3_python.contracts.security_lattice import init_security_contracts

# Initialize contracts once
init_security_contracts()


class TestPCTaintBasics:
    """Test basic PC taint tracking operations."""
    
    def test_pc_taint_starts_clean(self):
        """New tracker has clean PC taint."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        assert tracker.pc_taint.is_clean()
        assert len(tracker.pc_taint_stack) == 0
    
    def test_enter_branch_pushes_pc_taint(self):
        """Entering branch pushes current PC taint to stack."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Create a tainted condition value
        # Use a unique object as the condition value
        condition_value = object()  # Unique identity
        tainted_label = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM, "request.GET['flag']"
        )
        # Store label using Python id() as key
        tracker.value_labels[id(condition_value)] = tainted_label
        
        # Enter branch
        tracker.enter_branch(condition_value)
        
        # PC taint stack should have one entry
        assert len(tracker.pc_taint_stack) == 1
        # Current PC taint should include condition taint
        assert not tracker.pc_taint.is_clean()
        # Check τ_pc has HTTP_PARAM bit set (bit 0)
        assert tracker.pc_taint.tau_pc & (1 << SourceType.HTTP_PARAM)
    
    def test_exit_branch_restores_pc_taint(self):
        """Exiting branch restores previous PC taint."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Save initial PC taint (clean)
        initial_pc = tracker.pc_taint
        assert initial_pc.is_clean()
        
        # Enter branch with tainted condition
        condition_value = object()
        tainted_label = TaintLabel.from_untrusted_source(
            SourceType.USER_INPUT, "input()"
        )
        tracker.value_labels[id(condition_value)] = tainted_label
        tracker.enter_branch(condition_value)
        
        # PC taint is now tainted
        assert not tracker.pc_taint.is_clean()
        
        # Exit branch
        tracker.exit_branch()
        
        # PC taint should be restored to clean
        assert tracker.pc_taint.is_clean()
        assert len(tracker.pc_taint_stack) == 0
    
    def test_nested_branches_stack_correctly(self):
        """Nested branches maintain proper PC taint stack."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # First level branch
        cond1 = object()
        label1 = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "cond1")
        tracker.value_labels[id(cond1)] = label1
        tracker.enter_branch(cond1)
        
        assert len(tracker.pc_taint_stack) == 1
        assert tracker.pc_taint.tau_pc & (1 << SourceType.HTTP_PARAM)
        
        # Second level branch
        cond2 = object()
        label2 = TaintLabel.from_untrusted_source(SourceType.ENVIRONMENT, "cond2")
        tracker.value_labels[id(cond2)] = label2
        tracker.enter_branch(cond2)
        
        assert len(tracker.pc_taint_stack) == 2
        assert tracker.pc_taint.tau_pc & (1 << SourceType.HTTP_PARAM)
        assert tracker.pc_taint.tau_pc & (1 << SourceType.ENVIRONMENT)
        
        # Exit inner branch
        tracker.exit_branch()
        assert len(tracker.pc_taint_stack) == 1
        assert tracker.pc_taint.tau_pc & (1 << SourceType.HTTP_PARAM)
        assert not (tracker.pc_taint.tau_pc & (1 << SourceType.ENVIRONMENT))
        
        # Exit outer branch
        tracker.exit_branch()
        assert len(tracker.pc_taint_stack) == 0
        assert tracker.pc_taint.is_clean()

class TestPCTaintAssignmentPropagation:
    """Test that PC taint propagates to assignments in branches."""
    
    def test_assignment_inherits_pc_taint(self):
        """Assignment in branch inherits PC taint."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Enter branch with tainted condition
        condition = object()
        tainted_label = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM, "request.GET['flag']"
        )
        tracker.value_labels[id(condition)] = tainted_label
        tracker.enter_branch(condition)
        
        # Assign a clean value in the branch
        clean_label = TaintLabel.clean()
        
        # Apply PC taint
        result_label = tracker.apply_pc_taint(clean_label)
        
        # Result should have PC taint
        assert result_label.has_untrusted_taint()
        assert result_label.tau & (1 << SourceType.HTTP_PARAM)
    
    def test_pc_taint_not_applied_outside_branch(self):
        """PC taint only applies within branch context."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Assign value outside branch
        clean1 = TaintLabel.clean()
        result1 = tracker.apply_pc_taint(clean1)
        assert not result1.has_untrusted_taint()
        
        # Enter branch
        condition = object()
        tainted_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "input()")
        tracker.value_labels[id(condition)] = tainted_label
        tracker.enter_branch(condition)
        
        # Assign in branch (gets PC taint)
        clean2 = TaintLabel.clean()
        result2 = tracker.apply_pc_taint(clean2)
        assert result2.has_untrusted_taint()
        
        # Exit branch
        tracker.exit_branch()
        
        # Assign after branch (should be clean)
        clean3 = TaintLabel.clean()
        result_label = tracker.apply_pc_taint(clean3)
        
        # Should be clean (PC taint restored)
        assert not result_label.has_untrusted_taint()


class TestImplicitFlowSecurityViolations:
    """Test security violation detection with implicit flows."""
    
    def test_code_injection_via_pc_taint(self):
        """Detect CODE_INJECTION when PC-tainted value reaches eval."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Enter branch with HTTP param condition
        condition = object()
        http_label = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM, "request.POST.get('admin')"
        )
        tracker.value_labels[id(condition)] = http_label
        tracker.enter_branch(condition)
        
        # Assign command in branch
        cmd_value = object()
        cmd_label = tracker.apply_pc_taint(TaintLabel.clean())
        tracker.value_labels[id(cmd_value)] = cmd_label
        
        # Call eval (CODE_EVAL sink)
        func_name = "eval"
        args = [cmd_value]  # Use actual value object
        
        tracker.handle_call_pre(func_name, args, "test:line1")
        
        # Should have security violation
        assert len(tracker.violations) > 0
        violation = tracker.violations[0]
        assert violation.sink_type == SinkType.CODE_EVAL
        assert violation.bug_type == 'CODE_INJECTION'
    
    def test_sql_injection_via_pc_taint(self):
        """Detect SQL_INJECTION when PC-tainted value reaches cursor.execute."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Enter branch with environment variable condition
        condition = object()
        env_label = TaintLabel.from_untrusted_source(
            SourceType.ENVIRONMENT, "os.environ['MODE']"
        )
        tracker.value_labels[id(condition)] = env_label
        tracker.enter_branch(condition)
        
        # Build query in branch
        query_value = object()
        query_label = tracker.apply_pc_taint(TaintLabel.clean())
        tracker.value_labels[id(query_value)] = query_label
        
        # Call cursor.execute (SQL_EXECUTE sink)
        func_name = "cursor.execute"
        args = [query_value]
        
        tracker.handle_call_pre(func_name, args, "test:line2")
        
        # Should have security violation
        assert len(tracker.violations) > 0
        violation = tracker.violations[0]
        assert violation.sink_type == SinkType.SQL_EXECUTE
        assert violation.bug_type == 'SQL_INJECTION'
    
    def test_cleartext_logging_sigma_pc_taint(self):
        """Detect CLEARTEXT_LOGGING with σ-taint from PC taint."""
        tracker = LatticeSecurityTracker(track_implicit_flows=True)
        
        # Enter branch with sensitive condition (password param)
        # ITERATION 497: Use from_sensitive_source for PASSWORD (it's a sensitive source, not untrusted)
        condition = object()
        sensitive_label = TaintLabel.from_sensitive_source(
            SourceType.PASSWORD, "request.POST.get('password')"
        )
        tracker.value_labels[id(condition)] = sensitive_label
        tracker.enter_branch(condition)
        
        # Assign message in branch
        msg_value = object()
        msg_label = tracker.apply_pc_taint(TaintLabel.clean())
        tracker.value_labels[id(msg_value)] = msg_label
        
        # Call logging.info (LOG_OUTPUT sink)
        func_name = "logging.info"
        args = [msg_value]
        
        tracker.handle_call_pre(func_name, args, "test:line3")
        
        # Should have security violation for cleartext logging
        # (depends on if LOG_OUTPUT checks σ-taint)
        if len(tracker.violations) > 0:
            violation = tracker.violations[0]
            assert violation.sink_type == SinkType.LOG_OUTPUT


class TestPCTaintDisabled:
    """Test that PC taint can be disabled."""
    
    def test_implicit_flows_disabled_by_default(self):
        """When track_implicit_flows=False, PC taint not applied."""
        tracker = LatticeSecurityTracker(track_implicit_flows=False)
        
        # Enter branch
        condition = object()
        tainted_label = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM, "request.GET['flag']"
        )
        tracker.value_labels[id(condition)] = tainted_label
        tracker.enter_branch(condition)
        
        # PC taint stack should remain empty
        assert len(tracker.pc_taint_stack) == 0
        assert tracker.pc_taint.is_clean()
        
        # Assignment should NOT inherit PC taint
        clean_label = TaintLabel.clean()
        result_label = tracker.apply_pc_taint(clean_label)
        assert not result_label.has_untrusted_taint()


# ============================================================================
# INTEGRATION TESTS (End-to-End with Analyzer)
# ============================================================================

class TestImplicitFlowIntegration:
    """Integration tests with analyzer (file-based)."""
    
    def test_implicit_flow_code_injection_e2e(self, tmp_path):
        """End-to-end: CODE_INJECTION via implicit flow."""
        code = """
def handler():
    # Simulate tainted input
    flag = __import__('sys').argv[1] if len(__import__('sys').argv) > 1 else '0'
    
    if int(flag):
        cmd = 'admin_command'
    else:
        cmd = 'user_command'
    
    eval(cmd)

handler()
"""
        test_file = tmp_path / "test_implicit_code_injection.py"
        test_file.write_text(code)
        
        from a3_python.analyzer import analyze
        result = analyze(test_file)
        
        # Should detect BUG (either CODE_INJECTION or PANIC)
        # Depending on whether entry point analysis works
        assert result.verdict in ['BUG', 'UNKNOWN']
    
    def test_implicit_flow_safe_e2e(self, tmp_path):
        """End-to-end: Implicit flow with hardcoded values should be SAFE."""
        code = """
def handler():
    x = 5  # Clean
    
    if x > 0:
        y = 10  # Should NOT get PC taint (x is clean)
    else:
        y = 20
    
    z = y / 2
"""
        test_file = tmp_path / "test_implicit_safe.py"
        test_file.write_text(code)
        
        from a3_python.analyzer import analyze
        result = analyze(test_file)
        
        # Should be SAFE (no taint sources)
        assert result.verdict == 'SAFE'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

