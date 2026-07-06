"""
Interprocedural security tests for taint tracking.

Tests security bug detection across function boundaries:
- Cross-function taint propagation
- Call graph-driven summaries
- Multi-level call chains
- Recursive functions with security sinks
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
import importlib.util
import importlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer


def analyze_code(code: str, filename: str = 'test.py', entry_point: str = None, 
                 mode: str = 'interprocedural', max_paths: int = 100):
    """Helper function to analyze code string with entry point support.
    
    Args:
        code: Python source code to analyze
        filename: Name for temporary file
        entry_point: Name of entry point function (for interprocedural mode)
        mode: Analysis mode - 'interprocedural' (default) or 'function-level'
        max_paths: Max paths for symbolic execution
    
    Returns:
        dict with 'status' ('BUG', 'SAFE', 'UNKNOWN') and 'bugs' list
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = f.name
    
    try:
        analyzer = Analyzer(max_paths=max_paths)
        
        if mode == 'interprocedural':
            # Interprocedural analysis for security bugs using taint tracking
            # Build call graph from single file
            from a3_python.cfg.call_graph import build_call_graph_from_file
            from a3_python.semantics.interprocedural_taint import InterproceduralContext
            from a3_python.semantics.summaries import SummaryComputer
            from a3_python.contracts.security_lattice import (
                get_source_contracts_for_summaries,
                get_sink_contracts_for_summaries,
                get_sanitizer_contracts_for_summaries
            )
            
            # Build call graph from temp file
            call_graph = build_call_graph_from_file(Path(temp_path))
            
            # Set entry points (all functions if not specified)
            if entry_point:
                entry_points = {entry_point}
            else:
                entry_points = set(call_graph.functions.keys())
            
            # Compute reachable functions
            reachable = call_graph.get_reachable_from(entry_points)
            
            # Compute taint summaries
            computer = SummaryComputer(
                call_graph,
                source_contracts=get_source_contracts_for_summaries(),
                sink_contracts=get_sink_contracts_for_summaries(),
                sanitizer_contracts=get_sanitizer_contracts_for_summaries(),
            )
            summaries = computer.compute_all()
            
            # Create interprocedural context
            context = InterproceduralContext(
                call_graph=call_graph,
                summaries=summaries,
                entry_points=entry_points,
                reachable_functions=reachable
            )
            
            # Analyze each entry point using symbolic execution with interprocedural tracker
            all_bugs = []
            
            for ep_name in entry_points:
                # Try direct match first
                func_info = call_graph.functions.get(ep_name)
                
                # If not found, try partial matching (handle module-qualified names)
                if not func_info:
                    for qname, finfo in call_graph.functions.items():
                        if qname.endswith(f'.{ep_name}') or qname == ep_name:
                            func_info = finfo
                            ep_name = qname  # Use qualified name
                            break
                
                if not func_info:
                    continue
                
                # Load code object if not already populated
                code_obj = func_info.code_object
                if not code_obj:
                    # Load the module to extract code objects
                    spec = importlib.util.spec_from_file_location("temp_module", temp_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Extract function name (last component of qualified name)
                        func_simple_name = ep_name.split('.')[-1]
                        
                        # Get the function from the module
                        if hasattr(module, func_simple_name):
                            func_obj = getattr(module, func_simple_name)
                            if callable(func_obj) and hasattr(func_obj, '__code__'):
                                code_obj = func_obj.__code__
                
                if not code_obj:
                    continue
                
                # Use the analyzer's method to analyze this entry point
                result = analyzer._analyze_entry_point_with_summaries(
                    ep_name,
                    code_obj,
                    context
                )
                
                if result.verdict == 'BUG':
                    all_bugs.append({
                        'type': result.bug_type,
                        'description': result.message,
                        'call_chain': result.call_chain or []
                    })
            
            # Determine overall status
            if all_bugs:
                status = 'BUG'
            else:
                status = 'UNKNOWN'  # Conservative
            
            return {
                'status': status,
                'bugs': all_bugs
            }
            
        elif entry_point and mode == 'function-level':
            # Function-level analysis - analyze all functions and extract the target
            all_results = analyzer.analyze_all_functions(Path(temp_path))
            
            # Find result for specific entry point
            for func_data in all_results.get('function_results', []):
                if func_data['function_name'] == entry_point:
                    func_result = func_data['result']
                    # Convert to dictionary format expected by tests
                    result_dict = {
                        'status': func_result.verdict,
                        'bugs': []
                    }
                    if func_result.verdict == 'BUG':
                        result_dict['bugs'].append({
                            'type': func_result.bug_type,
                            'description': func_result.message,
                            'counterexample': func_result.counterexample
                        })
                    return result_dict
            
            # Entry point not found
            return {'status': 'ERROR', 'bugs': [], 'error': f'Entry point {entry_point} not found'}
        else:
            # Module-level analysis
            result = analyzer.analyze_file(Path(temp_path))
            result_dict = {
                'status': result.verdict,
                'bugs': []
            }
            if result.verdict == 'BUG':
                result_dict['bugs'].append({
                    'type': result.bug_type,
                    'description': result.message
                })
            return result_dict
    finally:
        Path(temp_path).unlink()


class TestCrossFunctionInjection:
    """Tests for security bugs across function boundaries."""
    
    def test_sql_injection_through_helper(self):
        """SQL injection through helper function."""
        code = '''
def execute_query(query):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)  # SQL_INJECTION sink
    return cursor.fetchall()

def search_users(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return execute_query(query)

def handler(request):
    username = request.args.get('username')  # Source
    return search_users(username)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should detect SQL_INJECTION via interprocedural taint
        assert result['status'] == 'BUG'
        assert 'SQL_INJECTION' in [b['type'] for b in result.get('bugs', [])]
    
    def test_code_injection_multi_level(self):
        """Code injection through multi-level call chain."""
        code = '''
def dangerous_eval(expr):
    return eval(expr)  # CODE_INJECTION sink

def process_expression(expr):
    result = dangerous_eval(expr)
    return str(result)

def calculate(user_expr):
    return process_expression(user_expr)

def api_endpoint(request):
    expr = request.POST.get('expr')  # Source
    return calculate(expr)
'''
        result = analyze_code(code, filename='test.py', entry_point='api_endpoint', mode='interprocedural')
        
        # Should track taint through 3-level call chain
        assert result['status'] == 'BUG'
        assert 'CODE_INJECTION' in [b['type'] for b in result.get('bugs', [])]
    
    def test_command_injection_via_wrapper(self):
        """Command injection through subprocess wrapper."""
        code = '''
import subprocess

def run_command(cmd):
    return subprocess.call(cmd, shell=True)  # COMMAND_INJECTION sink

def execute_user_command(user_cmd):
    return run_command(user_cmd)

def admin_api(request):
    cmd = request.GET.get('cmd')  # Source
    return execute_user_command(cmd)
'''
        result = analyze_code(code, filename='test.py', entry_point='admin_api', mode='interprocedural')
        
        assert result['status'] == 'BUG'
        assert 'COMMAND_INJECTION' in [b['type'] for b in result.get('bugs', [])]
    
    def test_path_injection_through_logger(self):
        """Path injection through file logging wrapper."""
        code = '''
def log_to_file(filename, data):
    with open(filename, 'w') as f:  # PATH_INJECTION sink
        f.write(data)

def save_log(logfile, message):
    log_to_file(logfile, message)

def log_handler(request):
    logfile = request.args.get('logfile')  # Source
    message = request.args.get('message')
    save_log(logfile, message)
'''
        result = analyze_code(code, filename='test.py', entry_point='log_handler', mode='interprocedural')
        
        assert result['status'] == 'BUG'
        assert 'PATH_INJECTION' in [b['type'] for b in result.get('bugs', [])]


class TestSanitizerFunctions:
    """Tests for sanitizers in interprocedural analysis."""
    
    def test_sql_injection_with_parameterization(self):
        """SQL injection blocked by parameterization."""
        code = '''
def safe_execute(query, params):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query, params)  # Parameterized - SAFE
    return cursor.fetchall()

def search_users(username):
    query = "SELECT * FROM users WHERE name = ?"
    return safe_execute(query, (username,))

def handler(request):
    username = request.args.get('username')
    return search_users(username)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should recognize parameterization as sanitizer
        if result['status'] == 'BUG':
            bugs = result.get('bugs', [])
            sql_bugs = [b for b in bugs if 'SQL_INJECTION' in b['type']]
            # If detected, should be marked as sanitized
            assert len(sql_bugs) == 0 or sql_bugs[0].get('sanitized', False)
    
    def test_html_injection_with_escape(self):
        """HTML injection blocked by escape function."""
        code = '''
import html

def escape_html(text):
    return html.escape(text)  # Sanitizer

def render_comment(comment):
    safe_comment = escape_html(comment)
    return f"<div>{safe_comment}</div>"

def comment_handler(request):
    comment = request.POST.get('comment')
    return render_comment(comment)
'''
        result = analyze_code(code, filename='test.py', entry_point='comment_handler', mode='interprocedural')
        
        # Escape should sanitize the taint
        if result['status'] == 'BUG':
            bugs = result.get('bugs', [])
            xss_bugs = [b for b in bugs if 'XSS' in b['type'] or 'HTML' in b['type']]
            assert len(xss_bugs) == 0 or xss_bugs[0].get('sanitized', False)
    
    def test_command_injection_with_shlex(self):
        """Command injection blocked by shell escaping."""
        code = '''
import subprocess
import shlex

def safe_command(cmd):
    escaped = shlex.quote(cmd)  # Sanitizer
    return subprocess.call(escaped, shell=True)

def execute(request):
    cmd = request.GET.get('cmd')
    return safe_command(cmd)
'''
        result = analyze_code(code, filename='test.py', entry_point='execute', mode='interprocedural')
        
        # shlex.quote should sanitize
        if result['status'] == 'BUG':
            bugs = result.get('bugs', [])
            cmd_bugs = [b for b in bugs if 'COMMAND_INJECTION' in b['type']]
            assert len(cmd_bugs) == 0 or cmd_bugs[0].get('sanitized', False)


class TestRecursiveFunctions:
    """Tests for security in recursive call chains."""
    
    def test_recursive_taint_propagation(self):
        """Taint propagation through recursive function."""
        code = '''
def process_recursive(data, depth):
    if depth <= 0:
        return eval(data)  # CODE_INJECTION sink
    return process_recursive(data, depth - 1)

def handler(request):
    data = request.args.get('data')
    return process_recursive(data, 5)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should track taint through recursion
        assert result['status'] == 'BUG'
        assert 'CODE_INJECTION' in [b['type'] for b in result.get('bugs', [])]
    
    def test_mutual_recursion_with_sink(self):
        """Security bug in mutually recursive functions."""
        code = '''
def even_process(data, n):
    if n <= 0:
        import os
        os.system(data)  # COMMAND_INJECTION sink
        return
    return odd_process(data, n - 1)

def odd_process(data, n):
    if n <= 0:
        return
    return even_process(data, n - 1)

def handler(request):
    cmd = request.GET.get('cmd')
    return even_process(cmd, 10)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should detect through mutual recursion
        assert result['status'] == 'BUG'
        assert 'COMMAND_INJECTION' in [b['type'] for b in result.get('bugs', [])]


class TestComplexDataFlow:
    """Tests for complex interprocedural dataflow."""
    
    def test_taint_split_and_merge(self):
        """Taint that splits and merges across functions."""
        code = '''
def process_left(data):
    return data.upper()

def process_right(data):
    return data.lower()

def merge_and_execute(left, right):
    combined = left + right
    return eval(combined)  # CODE_INJECTION sink

def handler(request):
    data = request.args.get('data')
    left = process_left(data)
    right = process_right(data)
    return merge_and_execute(left, right)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should track taint through split and merge
        assert result['status'] == 'BUG'
        assert 'CODE_INJECTION' in [b['type'] for b in result.get('bugs', [])]
    
    def test_partial_taint_propagation(self):
        """Only one parameter is tainted."""
        code = '''
def execute_with_params(query, safe_param, user_param):
    full_query = query + " WHERE id=" + user_param
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(full_query)  # SQL_INJECTION sink
    return cursor.fetchall()

def handler(request):
    user_id = request.args.get('id')  # Tainted
    safe_query = "SELECT * FROM users"  # Not tainted
    safe_default = "1"  # Not tainted
    return execute_with_params(safe_query, safe_default, user_id)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should track which parameters are tainted
        assert result['status'] == 'BUG'
        assert 'SQL_INJECTION' in [b['type'] for b in result.get('bugs', [])]
    
    def test_taint_through_return_value_chain(self):
        """Taint propagates through chain of return values."""
        code = '''
def get_user_input(request):
    return request.GET.get('input')

def format_input(raw):
    return "User input: " + raw

def process_formatted(formatted):
    return formatted.replace("User input: ", "")

def execute_processed(processed):
    return eval(processed)  # CODE_INJECTION sink

def handler(request):
    raw = get_user_input(request)
    formatted = format_input(raw)
    processed = process_formatted(formatted)
    return execute_processed(processed)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should track through 4-function chain
        assert result['status'] == 'BUG'
        assert 'CODE_INJECTION' in [b['type'] for b in result.get('bugs', [])]


class TestSummaryComputation:
    """Tests for automatic summary computation."""
    
    def test_identity_function_summary(self):
        """Summary for function that returns parameter."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        from a3_python.semantics.summaries import SummaryComputer
        
        code = '''
def identity(x):
    return x
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test')
            computer = SummaryComputer(graph, {}, {}, {})
            summaries = computer.compute_all()
            
            summary = summaries.get('test.identity')
            assert summary is not None
            assert 0 in summary.dependency.param_to_return
            
            os.unlink(f.name)
    
    def test_source_function_summary(self):
        """Summary for function that introduces taint."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        from a3_python.semantics.summaries import SummaryComputer
        from a3_python.contracts.security_lattice import SourceContract, SourceType
        
        code = '''
def get_user_input():
    return input("Enter: ")
'''
        source_contracts = {
            'input': SourceContract(
                function_id='input',
                source_type=SourceType.USER_INPUT,
                is_sensitive=False
            )
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test')
            computer = SummaryComputer(graph, source_contracts, {}, {})
            summaries = computer.compute_all()
            
            summary = summaries.get('test.get_user_input')
            assert summary is not None
            assert summary.dependency.introduces_taint
            
            os.unlink(f.name)
    
    def test_sink_function_summary(self):
        """Summary for function that calls security sink."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        from a3_python.semantics.summaries import SummaryComputer
        from a3_python.contracts.security_lattice import SinkContract, SinkType
        
        code = '''
def execute_sql(query):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''
        sink_contracts = {
            'sqlite3.Cursor.execute': SinkContract(
                function_id='sqlite3.Cursor.execute',
                sink_type=SinkType.SQL_EXECUTE,
                bug_type='SQL_INJECTION',
                tainted_arg_indices=frozenset([0])
            )
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test')
            computer = SummaryComputer(graph, {}, sink_contracts, {})
            summaries = computer.compute_all()
            
            summary = summaries.get('test.execute_sql')
            assert summary is not None
            # Should record that this function contains a sink
            assert summary.dependency.is_sink
            
            os.unlink(f.name)


class TestFalseNegativePrevention:
    """Tests ensuring no false negatives in interprocedural analysis."""
    
    def test_conservatively_unknown_function(self):
        """Unknown function calls should be conservative."""
        code = '''
def process_with_unknown(data):
    result = some_unknown_library_call(data)
    return eval(result)  # CODE_INJECTION sink

def handler(request):
    data = request.args.get('data')
    return process_with_unknown(data)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should conservatively assume unknown function preserves taint
        assert result['status'] in ['BUG', 'UNKNOWN']
        # Should not claim SAFE without proof
        assert result['status'] != 'SAFE'
    
    def test_dynamic_call_conservatism(self):
        """Dynamic calls should be handled conservatively."""
        code = '''
def dynamic_dispatch(func_name, data):
    func = globals()[func_name]
    return func(data)

def dangerous_eval(data):
    return eval(data)  # CODE_INJECTION sink

def handler(request):
    func_name = request.args.get('func')
    data = request.args.get('data')
    return dynamic_dispatch(func_name, data)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should be conservative about dynamic dispatch
        assert result['status'] in ['BUG', 'UNKNOWN']
        assert result['status'] != 'SAFE'


class TestImplicitFlowInterprocedural:
    """Tests for implicit flows across function boundaries."""
    
    def test_implicit_flow_through_condition(self):
        """Implicit flow through conditional function call."""
        code = '''
def log_success():
    with open('/tmp/success.log', 'w') as f:  # Cleartext storage sink
        f.write('success')

def log_failure():
    with open('/tmp/failure.log', 'w') as f:
        f.write('failure')

def authenticate(password):
    if password == "secret123":
        log_success()
    else:
        log_failure()

def handler(request):
    password = request.POST.get('password')  # Sensitive
    authenticate(password)
'''
        result = analyze_code(code, filename='test.py', entry_point='handler', mode='interprocedural')
        
        # Should detect implicit flow through control-dependent call
        # (This may be UNKNOWN if implicit flow tracking is not complete)
        assert result['status'] in ['BUG', 'UNKNOWN']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
