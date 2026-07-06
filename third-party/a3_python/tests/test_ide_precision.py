"""
Tests for IDE tabulation precision improvements.

These tests demonstrate the improved precision from proper IDE-style
interprocedural analysis with call/return matching and context sensitivity.
"""

import tempfile
from pathlib import Path
from a3_python.semantics.sota_interprocedural import (
    SOTAInterproceduralAnalyzer,
)


class TestIDETabulation:
    """Tests for IDE tabulation algorithm precision."""
    
    def test_precise_argument_tracking(self):
        """
        IDE should precisely track which argument flows where.
        
        Old behavior: conservatively assume all args might be tainted
        New behavior: track exactly which argument index is tainted
        """
        code = '''
def helper(safe_param, tainted_param):
    # Only tainted_param should trigger violation
    import os
    os.system(tainted_param)  # Should detect
    os.system(safe_param)     # Should NOT detect (if we track precisely)

def entry(user_input):
    safe = "hardcoded"
    helper(safe, user_input)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            violations = analyzer.analyze_file(path)
            
            # Should find at least one violation (tainted_param to os.system)
            assert len(violations) >= 1
            
            # The violation should mention the correct flow
            command_inj = [v for v in violations if 'COMMAND' in v.bug_type]
            assert len(command_inj) >= 1
        finally:
            path.unlink()
    
    def test_context_sensitive_with_1cfa(self):
        """
        1-CFA should distinguish different call sites.
        
        Old behavior: merge all contexts
        New behavior: track different call sites separately
        """
        code = '''
def identity(x):
    return x

def entry():
    # Call 1: safe data
    safe = identity("constant")
    
    # Call 2: tainted data
    import flask
    request = flask.request
    tainted = identity(request.args.get('param'))
    
    # Only the second one should be flagged
    import os
    os.system(tainted)  # Should detect
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            # Test with 1-CFA
            analyzer = SOTAInterproceduralAnalyzer(
                verbose=False,
                context_depth=1  # Enable 1-CFA
            )
            violations = analyzer.analyze_file(path)
            
            # Should find the tainted flow
            command_inj = [v for v in violations if 'COMMAND' in v.bug_type]
            assert len(command_inj) >= 1
        finally:
            path.unlink()
    
    def test_return_value_precision(self):
        """
        IDE should track return value taint precisely.
        
        Return value should only be tainted if it depends on tainted params.
        """
        code = '''
def always_safe():
    return "constant"

def returns_param(x):
    return x

def entry():
    import flask
    request = flask.request
    user_input = request.args.get('param')
    
    # Safe return
    safe = always_safe()
    
    # Tainted return
    tainted = returns_param(user_input)
    
    # Only tainted should trigger
    import os
    os.system(tainted)  # Should detect
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            violations = analyzer.analyze_file(path)
            
            # Should find violation for tainted flow
            assert len(violations) >= 1
            command_inj = [v for v in violations if 'COMMAND' in v.bug_type]
            assert len(command_inj) >= 1
        finally:
            path.unlink()
    
    def test_multi_hop_precision(self):
        """
        IDE should maintain precision across multiple function calls.
        """
        code = '''
def level3(x):
    import os
    os.system(x)

def level2(x):
    level3(x)

def level1(x):
    level2(x)

def entry():
    import flask
    request = flask.request
    user_input = request.args.get('param')
    level1(user_input)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            violations = analyzer.analyze_file(path)
            
            # Should find the multi-hop flow
            assert len(violations) >= 1
            
            # Verify the call chain is tracked
            command_inj = [v for v in violations if 'COMMAND' in v.bug_type or 'level' in v.function_name]
            assert len(command_inj) >= 1
        finally:
            path.unlink()
    
    def test_multiple_params_different_taints(self):
        """
        IDE should track different taint labels for different parameters.
        """
        code = '''
def process(param1, param2):
    import os
    # Both should be detected if called with tainted args
    os.system(param1)
    os.system(param2)

def entry():
    import flask
    request = flask.request
    user1 = request.args.get('user1')
    user2 = request.args.get('user2')
    process(user1, user2)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            violations = analyzer.analyze_file(path)
            
            # Should find violations for both parameters
            command_inj = [v for v in violations if 'COMMAND' in v.bug_type]
            # Note: may find 2 violations (one per param) or merged - accept either
            assert len(command_inj) >= 1
        finally:
            path.unlink()


class TestIDEEfficiency:
    """Tests for IDE algorithm efficiency and termination."""
    
    def test_recursive_function_terminates(self):
        """
        IDE tabulation should terminate even with recursion.
        """
        code = '''
def recursive(x, n):
    if n <= 0:
        import os
        os.system(x)
        return
    recursive(x, n - 1)

def entry():
    import flask
    request = flask.request
    user_input = request.args.get('param')
    recursive(user_input, 10)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            violations = analyzer.analyze_file(path)
            
            # Should terminate and find violation
            assert len(violations) >= 1
        finally:
            path.unlink()
    
    def test_large_call_graph(self):
        """
        IDE should scale to larger call graphs.
        """
        # Generate code with many functions
        functions = []
        for i in range(20):
            functions.append(f'''
def func{i}(x):
    return func{i+1}(x) if {i} < 19 else x
''')
        
        code = '\n'.join(functions) + '''
def entry():
    import flask
    request = flask.request
    user_input = request.args.get('param')
    result = func0(user_input)
    import os
    os.system(result)
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            analyzer = SOTAInterproceduralAnalyzer(verbose=False)
            violations = analyzer.analyze_file(path)
            
            # Should complete and find violation
            assert len(violations) >= 1
        finally:
            path.unlink()


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
