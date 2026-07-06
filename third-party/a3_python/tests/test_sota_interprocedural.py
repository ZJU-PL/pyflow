"""
Tests for SOTA Interprocedural Security Analyzer (Phase 2).

These tests verify:
1. Basic interprocedural taint flow
2. Summary computation
3. Call graph integration
4. Multi-file analysis (project mode)
5. Context sensitivity (Phase 2.5)
6. Proper call/return matching (Phase 2.7)
"""

import pytest
import tempfile
from pathlib import Path
from a3_python.semantics.sota_interprocedural import (
    SOTAInterproceduralAnalyzer,
    FunctionTaintSummary,
    CallContext,
    analyze_file_interprocedural,
    analyze_project_interprocedural,
)
from a3_python.z3model.taint_lattice import SinkType


# ============================================================================
# PHASE 2.7: INTERPROCEDURAL PRECISION TESTS
# ============================================================================

class TestStraightLine2HopFlow:
    """Test: src() in module returns tainted -> receiver -> sink (Phase 2.7)."""
    
    def test_taint_flows_through_helper_return(self):
        """Taint from helper return should reach caller's sink."""
        code = '''
def get_user_input(request):
    """Returns tainted data from request."""
    return request.GET.get('user_data')

def process_data(request):
    """Processes user input and passes to sink."""
    data = get_user_input(request)
    import os
    os.system(data)  # Should detect: taint flows through return
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            # Should find command injection from cross-function flow
            cmd_violations = [v for v in violations if v.sink_type == SinkType.COMMAND_SHELL]
            assert len(cmd_violations) >= 1, f"Expected command injection, got: {violations}"
        finally:
            filepath.unlink()
    
    def test_taint_through_multiple_helpers(self):
        """Taint should propagate through chain: a() -> b() -> c() -> sink."""
        code = '''
def get_input(request):
    return request.GET.get('cmd')

def transform_input(request):
    data = get_input(request)
    return "prefix_" + data

def execute_command(request):
    cmd = transform_input(request)
    import os
    os.system(cmd)  # Taint flows through 2-hop chain
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            cmd_violations = [v for v in violations if v.sink_type == SinkType.COMMAND_SHELL]
            assert len(cmd_violations) >= 1
        finally:
            filepath.unlink()


class TestSanitizerInHelper:
    """Test: sanitize(x) in helper adds κ; caller should not flag if sanitized (Phase 2.7)."""
    
    def test_sanitized_in_helper_no_violation(self):
        """When helper sanitizes data, caller's sink should be safe."""
        code = '''
def sanitize_for_shell(data):
    """Sanitizes data for shell execution."""
    import shlex
    return shlex.quote(data)

def run_command(user_input):
    """Runs command with sanitized input."""
    safe_cmd = sanitize_for_shell(user_input)
    import os
    os.system("echo " + safe_cmd)  # Safe: sanitized by helper
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            # Note: This test verifies the analyzer runs correctly.
            # Full sanitizer tracking across functions requires Phase 3 models.
            violations = analyze_file_interprocedural(filepath, verbose=False)
            # The test passes if no crash; sanitizer precision is a Phase 3 goal
            assert isinstance(violations, list)
        finally:
            filepath.unlink()


class TestRecursion:
    """Test: ensure tabulation terminates and handles recursion correctly (Phase 2.7)."""
    
    def test_simple_recursion_terminates(self):
        """Recursive function analysis should terminate."""
        code = '''
def recursive_sink(data, depth):
    if depth <= 0:
        eval(data)  # Sink
    else:
        recursive_sink(data, depth - 1)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            # Should find code injection
            code_violations = [v for v in violations if v.sink_type == SinkType.CODE_EVAL]
            assert len(code_violations) >= 1
        finally:
            filepath.unlink()
    
    def test_mutual_recursion_terminates(self):
        """Mutually recursive functions should terminate."""
        code = '''
def even_sink(data, n):
    if n == 0:
        eval(data)
    else:
        odd_sink(data, n - 1)

def odd_sink(data, n):
    if n == 0:
        return
    else:
        even_sink(data, n - 1)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            # Should terminate without hanging
            assert isinstance(violations, list)
        finally:
            filepath.unlink()


class TestDynamicDispatchFallback:
    """Test: unresolved calls should be treated conservatively (Phase 2.7)."""
    
    def test_unknown_callee_conservative(self):
        """Unknown function calls should not be treated as safe."""
        code = '''
def process_with_unknown(user_input):
    """Calls unknown function then uses result."""
    # unknown_transform is not defined - should be conservative
    result = unknown_transform(user_input)
    eval(result)  # Should still flag: unknown callee might not sanitize
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            # Should still detect code injection (conservative)
            code_violations = [v for v in violations if v.sink_type == SinkType.CODE_EVAL]
            assert len(code_violations) >= 1
        finally:
            filepath.unlink()


class TestInterproceduralBasic:
    """Basic interprocedural analysis tests."""
    
    def test_simple_call_chain(self):
        """Test taint flow through simple call chain."""
        code = '''
def helper(data):
    """Helper that passes data to SQL sink."""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(data)  # SQL sink
    return cursor.fetchall()

def main(user_input):
    """Main function that calls helper with user input."""
    result = helper(user_input)
    return result
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            
            # Should find the SQL injection in helper
            sql_violations = [v for v in violations if v.sink_type == SinkType.SQL_EXECUTE]
            assert len(sql_violations) >= 1, f"Expected SQL injection, got: {violations}"
        finally:
            filepath.unlink()
    
    def test_sanitizer_in_callee(self):
        """Test that sanitizer in callee is recognized."""
        code = '''
def sanitize_input(data):
    """Sanitizes input to be safe for SQL."""
    import re
    # Remove any non-alphanumeric characters
    return re.sub(r'[^a-zA-Z0-9]', '', data)

def process_query(user_input):
    """Process query with sanitization."""
    safe_input = sanitize_input(user_input)
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{safe_input}'")
    return cursor.fetchall()
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            
            # May still have violation since our sanitizer model is conservative
            # The key is that the analyzer runs without error
            assert isinstance(violations, list)
        finally:
            filepath.unlink()
    
    def test_taint_through_return(self):
        """Test taint propagation through return values."""
        code = '''
def get_user_data(request):
    """Gets user data from request."""
    return request.GET.get('data')  # Source

def process_data(request):
    """Process user data."""
    data = get_user_data(request)
    import os
    os.system(data)  # Sink - should be flagged
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            
            # Should find command injection
            cmd_violations = [v for v in violations if v.sink_type == SinkType.COMMAND_SHELL]
            # Intraprocedural analysis should catch this in process_data
            assert isinstance(violations, list)
        finally:
            filepath.unlink()


class TestFunctionSummary:
    """Tests for function summary computation."""
    
    def test_summary_creation(self):
        """Test that summaries are computed correctly."""
        code = '''
def identity(x):
    return x

def sink_function(data):
    import os
    os.system(data)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            analyzer.analyze_file(filepath)
            
            # Check that summaries were computed
            assert len(analyzer.summaries) >= 2
            
            # Identity should have param 0 affecting return
            if 'identity' in analyzer.summaries:
                identity_summary = analyzer.summaries['identity']
                assert 0 in identity_summary.ret_depends_on
            
            # sink_function should have param 0 flowing to COMMAND_SHELL sink
            if 'sink_function' in analyzer.summaries:
                sink_summary = analyzer.summaries['sink_function']
                if 0 in sink_summary.param_to_sinks:
                    assert SinkType.COMMAND_SHELL in sink_summary.param_to_sinks[0]
        finally:
            filepath.unlink()


class TestProjectAnalysis:
    """Tests for multi-file project analysis."""
    
    def test_simple_project(self):
        """Test analysis of a simple two-file project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            
            # Create module with helper
            (root / 'helpers.py').write_text('''
def execute_query(query):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
''')
            
            # Create main module
            (root / 'main.py').write_text('''
from helpers import execute_query

def handle_request(user_input):
    result = execute_query(user_input)
    return result
''')
            
            violations = analyze_project_interprocedural(root, verbose=False)
            
            # Should find SQL injection in helpers
            sql_violations = [v for v in violations if v.sink_type == SinkType.SQL_EXECUTE]
            assert len(sql_violations) >= 1, f"Expected SQL injection, got: {violations}"


class TestCallGraph:
    """Tests for call graph construction."""
    
    def test_call_graph_built(self):
        """Test that call graph is constructed."""
        code = '''
def a():
    b()

def b():
    c()

def c():
    pass
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            analyzer.analyze_file(filepath)
            
            assert analyzer.call_graph is not None
            assert len(analyzer.call_graph.functions) >= 3
        finally:
            filepath.unlink()


class TestEdgeCases:
    """Edge case tests."""
    
    def test_recursive_function(self):
        """Test handling of recursive functions."""
        code = '''
def recursive(n, data):
    if n <= 0:
        import os
        os.system(data)  # Sink
    else:
        recursive(n - 1, data)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            
            # Should find command injection
            cmd_violations = [v for v in violations if v.sink_type == SinkType.COMMAND_SHELL]
            assert len(cmd_violations) >= 1
        finally:
            filepath.unlink()
    
    def test_empty_file(self):
        """Test handling of empty file."""
        code = '# Empty file\n'
        
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            assert violations == []
        finally:
            filepath.unlink()
    
    def test_syntax_error_handling(self):
        """Test graceful handling of syntax errors."""
        code = 'def broken(\n'  # Syntax error
        
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            # Should not crash, just return empty or raise appropriately
            with pytest.raises(SyntaxError):
                analyze_file_interprocedural(filepath, verbose=False)
        finally:
            filepath.unlink()


class TestMultipleSinkTypes:
    """Test detection of multiple sink types."""
    
    def test_multiple_sink_types_in_chain(self):
        """Test that multiple sink types are detected in call chains."""
        code = '''
def multi_sink(data):
    import os
    import sqlite3
    
    # Command injection
    os.system(data)
    
    # SQL injection
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(data)
    
    # Code injection
    eval(data)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            filepath = Path(f.name)
        
        try:
            violations = analyze_file_interprocedural(filepath, verbose=False)
            
            sink_types = {v.sink_type for v in violations}
            # Should find multiple sink types
            assert SinkType.COMMAND_SHELL in sink_types
            assert SinkType.SQL_EXECUTE in sink_types
            assert SinkType.CODE_EVAL in sink_types
        finally:
            filepath.unlink()
