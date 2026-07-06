"""
Tests for TIMING_CHANNEL unsafe region.

Tests both BUG cases (secret-dependent timing) and NON-BUG cases
(constant-time operations, non-secret dependencies).

TIMING_CHANNEL detection requires timing taint tracking through the symbolic VM.
These tests verify that:
1. Secret sources create timing taint
2. Control-flow dependencies on secrets create timing channels
3. Variable-time operations on secrets create timing channels
4. Observable timing points are detected
5. Constant-time operations don't create timing channels
6. Non-secret control flow doesn't create timing channels
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState
from a3_python.unsafe.registry import check_unsafe_regions
from a3_python.unsafe import timing_channel


def test_timing_channel_explicit_flag():
    """
    BUG: Explicit timing_channel_detected flag set.
    
    Minimal test: state with timing_channel_detected=True should be detected.
    """
    state = SymbolicMachineState()
    state.timing_channel_detected = True
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel with explicit flag"


def test_no_timing_channel_clean_state():
    """
    NON-BUG: Clean state with no timing taints.
    
    Default state should not be a timing channel.
    """
    state = SymbolicMachineState()
    
    assert not timing_channel.is_unsafe_timing_channel(state), "Clean state should not be timing channel"


def test_timing_channel_pc_taint_at_observable_point():
    """
    BUG: Secret-dependent control flow at observable timing point.
    
    If branching on secret and then returning (observable timing), it's a channel.
    Example: if password == guess: return True
    """
    state = SymbolicMachineState()
    state.pc_taint = {"Secret"}
    state.observable_timing_point = "return"
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel: PC taint at return"


def test_no_timing_channel_pc_taint_not_observable():
    """
    NON-BUG: Secret-dependent control flow but not at observable point yet.
    
    Branching on secret is not a leak until timing becomes observable.
    """
    state = SymbolicMachineState()
    state.pc_taint = {"Secret"}
    state.observable_timing_point = None
    
    assert not timing_channel.is_unsafe_timing_channel(state), "PC taint without observable point is not channel"


def test_timing_channel_loop_taint():
    """
    BUG: Secret-dependent loop iteration count at observable point.
    
    Example: for i in range(secret): compute()
    """
    state = SymbolicMachineState()
    state.loop_taint = {"Secret"}
    state.observable_timing_point = "return"
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel: loop taint at return"


def test_no_timing_channel_loop_taint_not_observable():
    """
    NON-BUG: Secret-dependent loop but not at observable point.
    
    Loop with secret iteration count is not a leak until timing is observable.
    """
    state = SymbolicMachineState()
    state.loop_taint = {"Secret"}
    state.observable_timing_point = None
    
    assert not timing_channel.is_unsafe_timing_channel(state), "Loop taint without observable point is not channel"


def test_timing_channel_variable_time_operation():
    """
    BUG: Variable-time operation on tainted operand.
    
    Example: secret_password == user_input (string comparison is variable-time)
    """
    state = SymbolicMachineState()
    state.variable_time_operation = "string_compare"
    state.operand_tainted = True
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel: variable-time op on secret"


def test_no_timing_channel_variable_time_clean_operand():
    """
    NON-BUG: Variable-time operation on non-tainted operand.
    
    String comparison on public data is not a timing channel.
    """
    state = SymbolicMachineState()
    state.variable_time_operation = "string_compare"
    state.operand_tainted = False
    
    assert not timing_channel.is_unsafe_timing_channel(state), "Variable-time op on public data is not channel"


def test_timing_channel_timing_violations():
    """
    BUG: State with timing_violations list.
    
    If timing_violations is non-empty, it's a timing channel.
    """
    state = SymbolicMachineState()
    state.timing_violations = [
        ("branch_on_secret", "line 42", "password", "return"),
    ]
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel with violation list"


def test_timing_channel_string_compare_tainted():
    """
    BUG: String comparison on tainted value.
    
    Example: if password == user_input: ...
    Python string comparison is variable-time (short-circuits on mismatch).
    """
    state = SymbolicMachineState()
    state.string_compare_tainted = True
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel: tainted string compare"


def test_no_timing_channel_string_compare_clean():
    """
    NON-BUG: String comparison on non-tainted values.
    
    Comparing public strings is not a timing channel.
    """
    state = SymbolicMachineState()
    state.string_compare_tainted = False
    
    assert not timing_channel.is_unsafe_timing_channel(state), "String compare on public data is not channel"


def test_timing_channel_collection_scan_tainted():
    """
    BUG: Collection membership test on tainted data.
    
    Example: if secret_key in key_list: ...
    List membership is variable-time (linear scan, depends on position).
    """
    state = SymbolicMachineState()
    state.collection_scan_tainted = True
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel: tainted collection scan"


def test_no_timing_channel_collection_scan_clean():
    """
    NON-BUG: Collection membership test on non-tainted data.
    
    Searching in public collections is not a timing channel.
    """
    state = SymbolicMachineState()
    state.collection_scan_tainted = False
    
    assert not timing_channel.is_unsafe_timing_channel(state), "Collection scan on public data is not channel"


def test_timing_channel_early_exit_tainted():
    """
    BUG: Early exit (return/break) in secret-dependent branch.
    
    Example:
        for item in list:
            if item == secret:
                return True
    
    The timing reveals whether secret was found and at what position.
    """
    state = SymbolicMachineState()
    state.early_exit_tainted = True
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel: tainted early exit"


def test_no_timing_channel_early_exit_clean():
    """
    NON-BUG: Early exit in non-secret control flow.
    
    Early returns on public conditions are not timing channels.
    """
    state = SymbolicMachineState()
    state.early_exit_tainted = False
    
    assert not timing_channel.is_unsafe_timing_channel(state), "Early exit on public condition is not channel"


def test_timing_channel_multiple_indicators():
    """
    BUG: Multiple timing channel indicators.
    
    Real-world scenario: secret-dependent branch with variable-time operation
    at observable point.
    """
    state = SymbolicMachineState()
    state.pc_taint = {"Secret"}
    state.observable_timing_point = "return"
    state.variable_time_operation = "string_compare"
    state.operand_tainted = True
    
    assert timing_channel.is_unsafe_timing_channel(state), "Should detect timing channel with multiple indicators"


def test_no_timing_channel_no_indicators():
    """
    NON-BUG: No timing channel indicators present.
    
    State with none of the timing channel flags should be safe.
    """
    state = SymbolicMachineState()
    state.pc_taint = None
    state.loop_taint = None
    state.observable_timing_point = None
    state.variable_time_operation = None
    state.operand_tainted = False
    
    assert not timing_channel.is_unsafe_timing_channel(state), "No indicators should mean no timing channel"


def test_timing_channel_extract_counterexample():
    """
    Test counterexample extraction for TIMING_CHANNEL.
    
    Verify that extract_counterexample produces required fields.
    """
    state = SymbolicMachineState()
    state.timing_channel_detected = True
    state.pc_taint = {"Secret"}
    state.observable_timing_point = "return"
    state.current_function = "authenticate"
    state.current_line = 42
    
    path_trace = ["LOAD_FAST", "COMPARE_OP", "POP_JUMP_IF_TRUE", "RETURN_VALUE"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert result["bug_type"] == "TIMING_CHANNEL", "Should identify bug type"
    assert result["trace"] == path_trace, "Should include execution trace"
    assert "explanation" in result, "Should include explanation"
    assert "timing_violation" in result, "Should include timing violation details"


def test_timing_channel_extract_with_violations():
    """
    Test counterexample extraction with timing_violations list.
    """
    state = SymbolicMachineState()
    state.timing_violations = [
        ("branch_on_secret", "line 42", "password", "return"),
        ("loop_on_secret", "line 43", "key_length", "external_call"),
    ]
    state.pc_taint = {"Secret"}
    state.observable_timing_point = "return"
    
    path_trace = ["LOAD_FAST", "COMPARE_OP", "POP_JUMP_IF_TRUE"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert "timing_violation" in result, "Should include timing violation"
    assert "violations" in result["timing_violation"], "Should include violations list"
    assert result["timing_violation"]["count"] == 2, "Should count violations"


def test_timing_channel_extract_loop_details():
    """
    Test counterexample extraction with loop taint details.
    """
    state = SymbolicMachineState()
    state.loop_taint = {"Secret"}
    state.loop_taint_details = {
        "loop_type": "for",
        "bound_tainted": True,
        "iterations_depend_on": "secret_value"
    }
    state.observable_timing_point = "return"
    
    path_trace = ["LOAD_FAST", "GET_ITER", "FOR_ITER"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert result["loop_tainted"] is True, "Should flag loop taint"
    assert "loop_details" in result, "Should include loop details"


def test_timing_channel_extract_string_compare():
    """
    Test counterexample extraction for string comparison leak.
    """
    state = SymbolicMachineState()
    state.string_compare_tainted = {"password_check"}
    state.observable_timing_point = "return"
    
    path_trace = ["LOAD_FAST", "COMPARE_OP", "RETURN_VALUE"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert "string_compare_leak" in result, "Should flag string compare leak"


def test_timing_channel_extract_collection_scan():
    """
    Test counterexample extraction for collection scan leak.
    """
    state = SymbolicMachineState()
    state.collection_scan_tainted = {"key_search"}
    state.observable_timing_point = "return"
    
    path_trace = ["LOAD_FAST", "CONTAINS_OP", "RETURN_VALUE"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert "collection_scan_leak" in result, "Should flag collection scan leak"


def test_timing_channel_extract_early_exit():
    """
    Test counterexample extraction for early exit leak.
    """
    state = SymbolicMachineState()
    state.early_exit_tainted = True
    state.observable_timing_point = "return"
    
    path_trace = ["LOAD_FAST", "COMPARE_OP", "POP_JUMP_IF_TRUE", "RETURN_VALUE"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert "early_exit_leak" in result, "Should flag early exit leak"


def test_timing_channel_extract_with_context():
    """
    Test counterexample extraction with function and line context.
    """
    state = SymbolicMachineState()
    state.timing_channel_detected = True
    state.current_function = "verify_password"
    state.current_line = 123
    state.path_condition = "password == user_input"
    
    path_trace = ["LOAD_FAST", "COMPARE_OP", "RETURN_VALUE"]
    
    result = timing_channel.extract_counterexample(state, path_trace)
    
    assert result["function"] == "verify_password", "Should include function name"
    assert result["line"] == 123, "Should include line number"
    assert "path_condition" in result, "Should include path condition"
