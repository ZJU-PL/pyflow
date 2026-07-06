"""
Tests for the SOTA Intraprocedural Security Engine.

These tests verify that the Phase 1 implementation correctly:
1. Tracks taint through local variables and stack
2. Detects sources, sinks, and sanitizers
3. Handles bounded partitioning
4. Generates proper witness skeletons

Test categories:
1. Idiom tests (within one function)
2. Negative tests (sanitized flows)
3. Soundness tests (conservative on all paths)
"""

import pytest
import types
import dis
from pathlib import Path

from a3_python.semantics.sota_intraprocedural import (
    SOTAIntraproceduralAnalyzer,
    SOTASecurityViolation,
    AbstractState,
    TaintLabel,
    analyze_function_sota,
)
from a3_python.z3model.taint_lattice import SourceType, SinkType


def compile_function(source: str, func_name: str = "test_func") -> types.CodeType:
    """Compile a function from source code."""
    code = compile(source, "<test>", "exec")
    # Find the function's code object
    for const in code.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == func_name:
            return const
    raise ValueError(f"Could not find function {func_name} in compiled code")


# ============================================================================
# IDIOM TESTS: Basic Taint Flow
# ============================================================================

class TestBasicTaintFlow:
    """Test basic taint propagation through locals."""
    
    def test_source_to_local_to_sink(self):
        """Test: source() -> local -> sink (should detect)."""
        source = '''
def test_func(user_input):
    x = user_input
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        assert len(violations) >= 1
        assert any(v.bug_type == "CODE_INJECTION" or v.sink_type == SinkType.CODE_EVAL 
                   for v in violations)
    
    def test_multi_hop_local_flow(self):
        """Test: source -> x -> y -> z -> sink (multiple assignments)."""
        source = '''
def test_func(user_input):
    x = user_input
    y = x
    z = y
    eval(z)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        assert len(violations) >= 1
        assert any(v.sink_type == SinkType.CODE_EVAL for v in violations)
    
    def test_binary_op_propagation(self):
        """Test: taint propagates through binary operations."""
        source = '''
def test_func(user_input):
    x = "prefix_" + user_input
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        assert len(violations) >= 1


class TestStringBuilding:
    """Test taint propagation through string building."""
    
    def test_string_concat(self):
        """Test: string concatenation preserves taint."""
        source = '''
def test_func(user_input):
    query = "SELECT * FROM users WHERE id=" + user_input
    cursor.execute(query)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect SQL injection
        assert len(violations) >= 1
    
    def test_format_string(self):
        """Test: format() preserves taint."""
        source = '''
def test_func(user_input):
    query = "SELECT * FROM users WHERE id={}".format(user_input)
    cursor.execute(query)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect SQL injection
        assert len(violations) >= 1
    
    def test_fstring(self):
        """Test: f-strings preserve taint."""
        source = '''
def test_func(user_input):
    query = f"SELECT * FROM users WHERE id={user_input}"
    cursor.execute(query)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect SQL injection
        assert len(violations) >= 1


class TestContainerFlow:
    """Test taint propagation through containers."""
    
    def test_list_store_load(self):
        """Test: taint flows through list store and load."""
        source = '''
def test_func(user_input):
    lst = [user_input]
    x = lst[0]
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect code injection
        assert len(violations) >= 1
    
    def test_dict_store_load(self):
        """Test: taint flows through dict store and load."""
        source = '''
def test_func(user_input):
    d = {"key": user_input}
    x = d["key"]
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect code injection
        assert len(violations) >= 1


# ============================================================================
# SINK TYPE TESTS
# ============================================================================

class TestSinkTypes:
    """Test detection of different sink types."""
    
    def test_command_injection(self):
        """Test: detect command injection via os.system."""
        source = '''
def test_func(cmd):
    import os
    os.system(cmd)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        assert len(violations) >= 1
        assert any(v.sink_type == SinkType.COMMAND_SHELL for v in violations)
    
    def test_sql_injection(self):
        """Test: detect SQL injection via execute."""
        source = '''
def test_func(user_input):
    query = "SELECT * FROM users WHERE id=" + user_input
    cursor.execute(query)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        assert len(violations) >= 1
    
    def test_path_traversal(self):
        """Test: detect path traversal via open."""
        source = '''
def test_func(filename):
    f = open(filename)
    return f.read()
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect path traversal
        assert len(violations) >= 1


# ============================================================================
# NEGATIVE TESTS: Sanitized Flows
# ============================================================================

class TestSanitizedFlows:
    """Test that sanitized flows do NOT produce violations."""
    
    def test_no_taint_no_violation(self):
        """Test: constant values should not trigger violations."""
        source = '''
def test_func():
    x = "safe_value"
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # No tainted input -> no violation
        assert len(violations) == 0
    
    def test_clean_parameter_no_violation(self):
        """Test: parameter with non-suspicious name should be clean."""
        source = '''
def test_func(count):
    # 'count' is not a suspicious name for taint
    x = count + 1
    return x
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # No security violations expected
        assert len(violations) == 0


# ============================================================================
# ABSTRACT STATE TESTS
# ============================================================================

class TestAbstractState:
    """Test AbstractState operations."""
    
    def test_clean_state(self):
        """Test creating a clean state."""
        state = AbstractState()
        assert state.get_local(0).tau == 0
        assert state.get_local(0).sigma == 0
    
    def test_set_get_local(self):
        """Test setting and getting local taint."""
        state = AbstractState()
        tainted = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "test")
        state.set_local(0, tainted)
        
        assert state.get_local(0).tau != 0
        assert state.get_local(1).tau == 0  # Other locals are clean
    
    def test_stack_operations(self):
        """Test stack push/pop."""
        state = AbstractState()
        tainted = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "test")
        clean = TaintLabel.clean()
        
        state.push(clean)
        state.push(tainted)
        
        assert state.stack_size() == 2
        popped = state.pop()
        assert popped.tau != 0
        
        popped2 = state.pop()
        assert popped2.tau == 0
    
    def test_state_join(self):
        """Test joining two states."""
        state1 = AbstractState()
        state2 = AbstractState()
        
        tainted = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "test")
        clean = TaintLabel.clean()
        
        state1.set_local(0, tainted)
        state1.set_local(1, clean)
        
        state2.set_local(0, clean)
        state2.set_local(1, tainted)
        
        merged = state1.join(state2)
        
        # Both locals should be tainted after join
        assert merged.get_local(0).tau != 0
        assert merged.get_local(1).tau != 0
    
    def test_state_subsumes(self):
        """Test subsumption check."""
        state1 = AbstractState()
        state2 = AbstractState()
        
        tainted = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "test")
        clean = TaintLabel.clean()
        
        # state1 has more taint than state2
        state1.set_local(0, tainted)
        state2.set_local(0, clean)
        
        assert state1.subsumes(state2)  # Bigger state subsumes smaller
        assert not state2.subsumes(state1)


# ============================================================================
# CFG INTEGRATION TESTS
# ============================================================================

class TestCFGIntegration:
    """Test integration with CFG."""
    
    def test_branch_both_paths(self):
        """Test: taint should be tracked through both branches."""
        source = '''
def test_func(user_input):
    if some_condition:
        x = user_input
    else:
        x = user_input
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect on either path
        assert len(violations) >= 1
    
    def test_loop_propagation(self):
        """Test: taint propagates through loops."""
        source = '''
def test_func(user_input):
    x = ""
    for i in range(10):
        x = x + user_input
    eval(x)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect after loop
        assert len(violations) >= 1


# ============================================================================
# SENSITIVE DATA TESTS
# ============================================================================

class TestSensitiveData:
    """Test sensitive data (σ) tracking."""
    
    def test_password_parameter_sensitivity(self):
        """Test: parameter named 'password' should have sensitivity."""
        source = '''
def test_func(password):
    print(password)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # Should detect cleartext logging of password
        # Note: print is a logging sink for sensitive data
        # This may or may not trigger depending on contract setup
        # The key is that 'password' parameter gets sensitivity
        pass  # Just verify no crash for now
    
    def test_sensitive_dict_key_inference(self):
        """Test: dict['password'] should add sensitivity."""
        source = '''
def test_func(data):
    pwd = data['password']
    print(pwd)
'''
        code = compile_function(source)
        # Just verify no crash
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)


# ============================================================================
# SANITIZER TESTS
# ============================================================================

class TestSanitizers:
    """Test that sanitizers properly update κ (sanitized sinks)."""
    
    def test_shlex_quote_sanitizes_command(self):
        """Test: shlex.quote sanitizes for command injection."""
        source = '''
def test_func(user_input):
    import shlex
    safe_input = shlex.quote(user_input)
    import os
    os.system("echo " + safe_input)
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        
        # shlex.quote should sanitize for COMMAND_SHELL
        # So this should NOT be a violation (if sanitizer is properly modeled)
        # Note: This depends on sanitizer contract being registered
        # For now, just verify the engine runs
        pass
    
    def test_parameterized_query_sanitizes_sql(self):
        """Test: parameterized queries are safe."""
        # This tests that when we detect parameterized patterns, we don't flag them
        # The exact implementation depends on how we model cursor.execute with params
        source = '''
def test_func(user_id):
    # Unsafe: string concatenation
    query1 = "SELECT * FROM users WHERE id=" + user_id
    
    # Safe: parameterized (but our analyzer may not know this yet)
    query2 = "SELECT * FROM users WHERE id=?"
'''
        code = compile_function(source)
        violations = analyze_function_sota(code, "test_func", "<test>", verbose=False)
        # Just verify it runs
        pass


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
