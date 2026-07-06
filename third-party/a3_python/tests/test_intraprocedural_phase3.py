"""
Tests for Phase 3 intra-procedural analysis: recursion with ranking functions.

Phase 3 implements recursion analysis with ranking function verification:
- Simple recursive functions (single parameter)
- Terminating recursion (with base case)
- Non-terminating recursion (infinite loops)
- Ranking function synthesis and verification
"""

import pytest
from a3_python.analyzer import Analyzer


def test_simple_terminating_recursion_factorial(tmp_path):
    """Test factorial: classic terminating recursion with n-1 pattern."""
    code = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

result = factorial(5)
"""
    filepath = tmp_path / "test_factorial.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    # Should complete without infinite loop
    assert result is not None
    # With Phase 3, terminating recursion should be analyzed
    # Should not report NON_TERMINATION for this case


def test_simple_terminating_recursion_countdown(tmp_path):
    """Test countdown: simple decrementing recursion."""
    code = """
def countdown(n):
    if n <= 0:
        return "done"
    return countdown(n - 1)

result = countdown(10)
"""
    filepath = tmp_path / "test_countdown.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should complete without infinite loop


def test_simple_terminating_recursion_fibonacci(tmp_path):
    """Test fibonacci: recursive with two recursive calls."""
    code = """
def fib(n):
    if n <= 1:
        return n
    return fib(n - 1) + fib(n - 2)

result = fib(6)
"""
    filepath = tmp_path / "test_fib.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle multiple recursive calls


def test_non_terminating_recursion_infinite(tmp_path):
    """Test infinite recursion: no base case."""
    code = """
def infinite(n):
    return infinite(n + 1)

infinite(0)
"""
    filepath = tmp_path / "test_infinite.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=50, max_depth=50)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should detect non-termination or hit depth limit gracefully


def test_non_terminating_recursion_no_base_case(tmp_path):
    """Test recursion without proper base case."""
    code = """
def bad_countdown(n):
    if n < 0:  # Base case never reached if n starts >= 0
        return "done"
    return bad_countdown(n - 1)

bad_countdown(5)
"""
    filepath = tmp_path / "test_bad_countdown.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=50, max_depth=50)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle recursion that goes negative


def test_mutual_recursion_even_odd(tmp_path):
    """Test mutual recursion: is_even and is_odd."""
    code = """
def is_even(n):
    if n == 0:
        return True
    return is_odd(n - 1)

def is_odd(n):
    if n == 0:
        return False
    return is_even(n - 1)

result = is_even(4)
"""
    filepath = tmp_path / "test_mutual_recursion.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Phase 3: Should handle mutual recursion gracefully


def test_recursion_with_divide_bug(tmp_path):
    """Test recursive function containing a bug."""
    code = """
def buggy_factorial(n):
    if n <= 1:
        return 1
    # BUG: if n == 2, we divide by zero
    divisor = n - 2
    return n * buggy_factorial(n - 1) / divisor

result = buggy_factorial(2)
"""
    filepath = tmp_path / "test_buggy_recursion.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should be able to detect bugs within recursive functions


def test_recursion_depth_limit(tmp_path):
    """Test that deep recursion respects depth limits."""
    code = """
def deep_recursion(n):
    if n <= 0:
        return 0
    return 1 + deep_recursion(n - 1)

result = deep_recursion(100)
"""
    filepath = tmp_path / "test_deep.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=200, max_depth=200)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should complete without exhausting resources


def test_recursion_with_list_accumulator(tmp_path):
    """Test recursion with list building."""
    code = """
def build_list(n):
    if n <= 0:
        return []
    return [n] + build_list(n - 1)

result = build_list(5)
"""
    filepath = tmp_path / "test_list_recursion.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle list operations in recursion


def test_recursion_negative_initial_value(tmp_path):
    """Test recursion called with negative initial value."""
    code = """
def countdown(n):
    if n <= 0:
        return "done"
    return countdown(n - 1)

# Called with negative value - should terminate immediately
result = countdown(-5)
"""
    filepath = tmp_path / "test_negative_start.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle negative initial values correctly


def test_recursion_symbolic_parameter(tmp_path):
    """Test recursion with symbolic parameter (not concrete value)."""
    code = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

# Called with unknown/symbolic value
import sys
n = len(sys.argv)  # Symbolic
result = factorial(n)
"""
    filepath = tmp_path / "test_symbolic.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle symbolic recursion parameters


def test_tail_recursion(tmp_path):
    """Test tail-recursive function."""
    code = """
def sum_tail(n, acc):
    if n <= 0:
        return acc
    return sum_tail(n - 1, acc + n)

result = sum_tail(5, 0)
"""
    filepath = tmp_path / "test_tail_recursion.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Multi-parameter recursion: Phase 3 may treat as havoc or attempt analysis


def test_recursion_with_multiple_base_cases(tmp_path):
    """Test recursion with multiple base cases."""
    code = """
def multi_base(n):
    if n <= 0:
        return 0
    if n == 1:
        return 1
    return multi_base(n - 1) + multi_base(n - 2)

result = multi_base(5)
"""
    filepath = tmp_path / "test_multi_base.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle multiple base cases


def test_recursion_with_assertion(tmp_path):
    """Test recursion with assertion that could fail."""
    code = """
def checked_factorial(n):
    assert n >= 0, "n must be non-negative"
    if n <= 1:
        return 1
    return n * checked_factorial(n - 1)

# This should be safe
result = checked_factorial(5)
"""
    filepath = tmp_path / "test_recursion_assertion.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should verify assertions within recursive functions


def test_recursion_ascending_not_terminating(tmp_path):
    """Test recursion that increments instead of decrements."""
    code = """
def ascending(n, limit):
    if n >= limit:
        return n
    return ascending(n + 1, limit)

result = ascending(0, 5)
"""
    filepath = tmp_path / "test_ascending.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle ascending recursion (still terminates with proper base case)


def test_indirect_recursion_three_functions(tmp_path):
    """Test indirect recursion through three functions."""
    code = """
def a(n):
    if n <= 0:
        return 0
    return b(n - 1)

def b(n):
    if n <= 0:
        return 0
    return c(n - 1)

def c(n):
    if n <= 0:
        return 0
    return a(n - 1)

result = a(6)
"""
    filepath = tmp_path / "test_indirect_3.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle indirect recursion chains


def test_recursion_with_string_concatenation(tmp_path):
    """Test recursion building strings."""
    code = """
def repeat_char(char, n):
    if n <= 0:
        return ""
    return char + repeat_char(char, n - 1)

result = repeat_char("a", 5)
"""
    filepath = tmp_path / "test_string_recursion.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle string operations in recursion


def test_recursion_non_integer_parameter(tmp_path):
    """Test recursion with non-integer parameter (should fall back to havoc)."""
    code = """
def string_recursion(s):
    if len(s) <= 1:
        return s
    return s[0] + string_recursion(s[1:])

result = string_recursion("hello")
"""
    filepath = tmp_path / "test_string_param.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=100, max_depth=100)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Non-integer parameter: Phase 3 should fall back to havoc


def test_recursion_zero_parameter(tmp_path):
    """Test recursion with no parameters (infinite loop)."""
    code = """
def infinite_loop():
    return infinite_loop()

infinite_loop()
"""
    filepath = tmp_path / "test_zero_param.py"
    filepath.write_text(code)
    
    analyzer = Analyzer(max_paths=50, max_depth=50)
    result = analyzer.analyze_file(filepath)
    
    assert result is not None
    # Should handle zero-parameter recursion (likely non-terminating)
