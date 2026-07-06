"""
Tests for INFO_LEAK unsafe region.

Tests both BUG cases (tainted data flows to sink) and NON-BUG cases
(proper sanitization/declassification).

INFO_LEAK detection requires taint tracking through the symbolic VM.
These tests verify that:
1. Tainted sources are properly labeled
2. Taint propagates through operations
3. Sinks detect tainted values
4. Declassification properly removes taints
5. Implicit flows (control-flow taint) are tracked
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM, SymbolicMachineState
from a3_python.unsafe.registry import check_unsafe_regions
from a3_python.unsafe import info_leak


def test_info_leak_explicit_flag():
    """
    BUG: Explicit tainted_value_at_sink flag set.
    
    Minimal test: state with tainted_value_at_sink=True should be detected.
    """
    state = SymbolicMachineState()
    state.tainted_value_at_sink = True
    
    assert info_leak.is_unsafe_info_leak(state), "Should detect info leak with explicit flag"


def test_no_info_leak_clean_state():
    """
    NON-BUG: Clean state with no taints.
    
    Default state should not be an info leak.
    """
    state = SymbolicMachineState()
    
    assert not info_leak.is_unsafe_info_leak(state), "Clean state should not be info leak"


def test_info_leak_taint_violation():
    """
    BUG: State with taint_violations list.
    
    If taint_violations is non-empty, it's an info leak.
    """
    state = SymbolicMachineState()
    state.taint_violations = [
        ("secret_value", "print", {"Secret"}),
    ]
    
    assert info_leak.is_unsafe_info_leak(state), "Should detect info leak with taint violation"


def test_info_leak_exception_tainted():
    """
    BUG: Exception message contains tainted data.
    
    If exception is raised with tainted data in message, it's a leak.
    """
    state = SymbolicMachineState()
    state.exception = "ValueError"
    state.exception_tainted = True
    
    assert info_leak.is_unsafe_info_leak(state), "Should detect info leak in exception message"


def test_info_leak_control_flow_taint():
    """
    BUG: Control flow tainted (branched on secret) and at sink.
    
    Implicit flow: if secret == x: print("match") leaks via control flow.
    """
    state = SymbolicMachineState()
    state.pc_taint = {"Secret"}
    state.at_sink_operation = True
    
    assert info_leak.is_unsafe_info_leak(state), "Should detect implicit flow info leak"


def test_no_info_leak_control_flow_taint_not_at_sink():
    """
    NON-BUG: Control flow tainted but not at sink yet.
    
    Being in a secret-dependent branch is not a leak until we hit a sink.
    """
    state = SymbolicMachineState()
    state.pc_taint = {"Secret"}
    state.at_sink_operation = False
    
    assert not info_leak.is_unsafe_info_leak(state), "Control flow taint without sink is not leak"


def test_info_leak_output_tainted():
    """
    BUG: Tainted network/file output.
    
    Writing tainted data to file or network is a leak.
    """
    state = SymbolicMachineState()
    state.output_tainted = True
    
    assert info_leak.is_unsafe_info_leak(state), "Should detect tainted output as info leak"


def test_extract_counterexample_basic():
    """
    Test counterexample extraction for info leak.
    
    Should produce a witness with leak details.
    """
    state = SymbolicMachineState()
    state.tainted_value_at_sink = True
    state.taint_violations = [
        ("password", "print", {"Credential"}),
    ]
    state.taint_sources = ["os.environ['API_KEY']"]
    state.sink_location = "line 42: print(api_key)"
    state.leaked_taint_labels = {"Credential", "Secret"}
    
    trace = ["LOAD_FAST 'api_key'", "CALL print", "RETURN_VALUE"]
    ce = info_leak.extract_counterexample(state, trace)
    
    assert ce['bug_type'] == 'INFO_LEAK'
    assert ce['trace'] == trace
    assert 'taint_violations' in ce
    assert len(ce['taint_violations']) == 1
    assert ce['taint_violations'][0]['sink'] == 'print'
    assert 'Credential' in ce['taint_violations'][0]['taints']
    assert ce['taint_sources'] == ["os.environ['API_KEY']"]
    assert ce['sink_location'] == "line 42: print(api_key)"
    assert 'Credential' in ce['taint_labels']
    assert 'Secret' in ce['taint_labels']


def test_extract_counterexample_implicit_flow():
    """
    Test counterexample extraction for implicit flow leak.
    
    Should capture control-flow taint details.
    """
    state = SymbolicMachineState()
    state.pc_taint = {"Secret"}
    state.at_sink_operation = True
    state.implicit_flow_leak = {
        "branch_condition": "secret == guess",
        "sink": "print('match')",
        "taint_source": "getpass.getpass()"
    }
    
    trace = ["COMPARE_OP", "POP_JUMP_IF_FALSE", "CALL print"]
    ce = info_leak.extract_counterexample(state, trace)
    
    assert ce['bug_type'] == 'INFO_LEAK'
    assert 'implicit_flow' in ce
    assert ce['implicit_flow']['branch_condition'] == "secret == guess"


def test_extract_counterexample_exception_leak():
    """
    Test counterexample extraction for exception message leak.
    
    Should capture exception taint details.
    """
    state = SymbolicMachineState()
    state.exception = "ValueError"
    state.exception_tainted = True
    
    trace = ["RAISE_VARARGS"]
    ce = info_leak.extract_counterexample(state, trace)
    
    assert ce['bug_type'] == 'INFO_LEAK'
    assert 'exception_leak' in ce
    assert ce['exception_leak']['exception_type'] == 'ValueError'
    assert ce['exception_leak']['tainted'] is True


# Integration tests would require full taint tracking in symbolic VM
# These are placeholder tests that verify the unsafe predicate logic
# Once taint tracking is fully implemented in the symbolic VM, we can add:
#
# def test_taint_source_os_environ():
#     """BUG: os.environ values are tainted, printing them leaks."""
#     code = compile("import os\nprint(os.environ['API_KEY'])", "<string>", "exec")
#     # ... run symbolic execution with taint tracking
#
# def test_taint_propagation_arithmetic():
#     """BUG: Taint propagates through arithmetic: tainted + clean = tainted."""
#     code = compile("x = secret_input()\ny = x + 1\nprint(y)", "<string>", "exec")
#     # ... verify y is tainted
#
# def test_declassification_hash():
#     """NON-BUG: hashing declassifies: print(hashlib.sha256(secret)) is safe."""
#     code = compile("import hashlib\nprint(hashlib.sha256(secret).hexdigest())", "<string>", "exec")
#     # ... verify hash output is not tainted
#
# def test_implicit_flow_if_secret():
#     """BUG: if secret == x: print('yes') leaks via control flow."""
#     code = compile("if secret == 'foo':\n  print('match')", "<string>", "exec")
#     # ... verify implicit flow detected


def test_multiple_taint_labels():
    """
    Test handling of multiple taint labels on same value.
    
    A value can be both Secret and PII (e.g., SSN).
    """
    state = SymbolicMachineState()
    state.taint_violations = [
        ("ssn", "logging.info", {"Secret", "PII"}),
    ]
    state.leaked_taint_labels = {"Secret", "PII"}
    
    assert info_leak.is_unsafe_info_leak(state)
    
    ce = info_leak.extract_counterexample(state, [])
    assert "Secret" in ce['taint_labels']
    assert "PII" in ce['taint_labels']


def test_multiple_violations():
    """
    Test multiple taint violations in same execution.
    
    A program might leak multiple secrets to multiple sinks.
    """
    state = SymbolicMachineState()
    state.taint_violations = [
        ("api_key", "print", {"Credential"}),
        ("user_email", "logging.error", {"PII"}),
    ]
    
    assert info_leak.is_unsafe_info_leak(state)
    
    ce = info_leak.extract_counterexample(state, [])
    assert len(ce['taint_violations']) == 2


def test_no_leak_no_taint():
    """
    NON-BUG: Normal program with no tainted data.
    
    print(1 + 2) should not be a leak.
    """
    state = SymbolicMachineState()
    # All taint fields are default (empty/False)
    
    assert not info_leak.is_unsafe_info_leak(state)


def test_no_leak_tainted_but_not_at_sink():
    """
    NON-BUG: Tainted data exists but doesn't reach sink.
    
    x = secret; y = 1 + 1; print(y) should not leak.
    """
    state = SymbolicMachineState()
    # Tainted data exists in state but not at sink
    state.taint_sources = ["os.environ['SECRET']"]
    # But no violations, no sink reached
    
    assert not info_leak.is_unsafe_info_leak(state)


# Mark tests that require full taint tracking implementation as expected failures
@pytest.mark.xfail(reason="Requires full taint tracking in symbolic VM")
def test_taint_tracking_print_env_var():
    """
    BUG: Print environment variable (taint source → sink).
    
    This test will pass once taint tracking is fully implemented in symbolic VM.
    """
    code = compile("import os\nkey = os.environ.get('API_KEY', '')\nprint(key)", "<string>", "exec")
    vm = SymbolicVM()
    # Need to configure VM to treat os.environ as taint source
    # and print as sink
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'INFO_LEAK':
            bugs_found.append(bug)
    
    assert len(bugs_found) > 0, "Should detect info leak when printing env var"


@pytest.mark.xfail(reason="Requires full taint tracking in symbolic VM")
def test_no_leak_with_sanitization():
    """
    NON-BUG: Print sanitized version of secret.
    
    print(len(password)) should not leak (length is declassified).
    """
    code = compile("password = 'secret'\nprint(len(password))", "<string>", "exec")
    vm = SymbolicVM()
    paths = vm.explore_bounded(code, max_steps=50)
    
    bugs_found = []
    for path in paths:
        bug = check_unsafe_regions(path.state, path.trace)
        if bug and bug['bug_type'] == 'INFO_LEAK':
            bugs_found.append(bug)
    
    # Length is declassified, not a leak
    # (This is debatable; some systems consider length sensitive)
    assert len(bugs_found) == 0, "Should not detect leak for declassified length"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
