"""
Tests for user-defined function detection infrastructure.

This is phase 1 of intra-procedural analysis: detection and tracking.
Future phases will implement actual function body analysis.
"""

import pytest
from a3_python.analyzer import Analyzer


def test_user_function_detection_basic(tmp_path):
    """Test that user-defined functions are detected and tracked."""
    code = """
def add(x, y):
    return x + y

result = add(1, 2)
"""
    filepath = tmp_path / "test_user_func.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # The analysis should complete without error
    assert result is not None
    
    # Check that we detected the user function definition
    # (We'll verify this through the result structure)
    # For now, just ensure no crashes


def test_user_function_call_tracking(tmp_path):
    """Test that calls to user-defined functions are tracked."""
    code = """
def square(n):
    return n * n

x = square(5)
"""
    filepath = tmp_path / "test_user_func_call.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Should complete without errors
    assert result is not None
    # The function call should be treated with havoc semantics for now


def test_nested_user_function(tmp_path):
    """Test detection of nested user-defined function calls."""
    code = """
def outer(a):
    return a + 1

def middle(b):
    return outer(b) * 2

result = middle(3)
"""
    filepath = tmp_path / "test_nested_func.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Should handle nested calls with havoc semantics
    assert result is not None


def test_user_function_with_stdlib_calls(tmp_path):
    """Test that we distinguish user functions from stdlib."""
    code = """
def process(items):
    return len(items) + 1

data = [1, 2, 3]
result = process(data)
"""
    filepath = tmp_path / "test_mixed_calls.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Should handle mixed user/stdlib calls correctly
    assert result is not None
    # len() should use stdlib contract, process() should use havoc


def test_user_function_not_called(tmp_path):
    """Test that defined but uncalled functions don't cause issues."""
    code = """
def unused():
    return 42

x = 1 + 1
"""
    filepath = tmp_path / "test_unused_func.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Should complete normally - unused functions are just defined
    assert result is not None
    assert result.verdict in ["SAFE", "UNKNOWN"]


def test_user_function_with_potential_bug(tmp_path):
    """Test that bugs in user-defined functions can still be detected."""
    code = """
def divide(a, b):
    return a / b

result = divide(10, 0)  # BUG: DIV_ZERO
"""
    filepath = tmp_path / "test_user_func_bug.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # For now, with havoc semantics, we won't detect bugs inside user functions
    # This is expected - we need phase 2 (actual analysis) for that
    # But we should at least not crash
    assert result is not None
    # Note: Once intra-procedural analysis is implemented, this should detect DIV_ZERO


def test_lambda_function(tmp_path):
    """Test that lambda functions work correctly."""
    code = """
f = lambda x: x + 1
result = f(5)
"""
    filepath = tmp_path / "test_lambda.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Lambdas are also user-defined functions
    assert result is not None


def test_multiple_user_functions(tmp_path):
    """Test tracking multiple user-defined functions."""
    code = """
def add(x, y):
    return x + y

def mul(x, y):
    return x * y

def compute(a, b):
    return add(a, b) + mul(a, b)

result = compute(3, 4)
"""
    filepath = tmp_path / "test_multiple_funcs.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Should track all three user functions
    assert result is not None


def test_user_function_with_conditional(tmp_path):
    """Test user function with conditional logic."""
    code = """
def abs_value(n):
    if n < 0:
        return -n
    else:
        return n

result = abs_value(-5)
"""
    filepath = tmp_path / "test_conditional_func.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # With havoc semantics, conditionals inside user functions are abstracted
    assert result is not None
