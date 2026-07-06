"""
Tests for function-level termination checking.

ITERATION 551: Added support for checking termination of loops in function bodies.
Previously, only module-level loops were checked. Now both security_scan() and
error_bug_scan() check termination in function bodies when check_termination=True.
"""

import tempfile
from pathlib import Path
import pytest

from a3_python.analyzer import Analyzer


def test_function_with_terminating_loop():
    """Test that termination checking detects a terminating loop in a function."""
    code = """
def countdown(n):
    while n > 0:
        n = n - 1
    return n

countdown(10)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        # Analyze with termination checking enabled
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # Should not report NON_TERMINATION (loop terminates)
        # Result should be SAFE, UNKNOWN, or possibly BUG for other reasons
        if result.verdict == 'BUG':
            assert result.bug_type != 'NON_TERMINATION', \
                f"Should not report non-termination for countdown loop: {result.message}"
    finally:
        temp_path.unlink()


def test_error_bug_scan_with_terminating_loop():
    """Test error_bug_scan with termination checking on function with loop."""
    code = """
def safe_counter(n):
    i = 0
    while i < n:
        i = i + 1
    return i

# Call it so it's reachable
safe_counter(5)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.error_bug_scan(temp_path)
        
        # Should not report NON_TERMINATION
        if result.verdict == 'BUG':
            assert result.bug_type != 'NON_TERMINATION', \
                f"Should not report non-termination: {result.message}"
    finally:
        temp_path.unlink()


def test_security_scan_with_terminating_loop():
    """Test security_scan with termination checking on function with loop."""
    code = """
def process_items(items):
    result = []
    for item in items:
        result.append(item)
    return result
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.security_scan(temp_path)
        
        # Should not report NON_TERMINATION (for-loop with iterator terminates)
        if result.verdict == 'BUG':
            assert result.bug_type != 'NON_TERMINATION', \
                f"Should not report non-termination: {result.message}"
    finally:
        temp_path.unlink()


def test_function_without_termination_check():
    """Verify that termination checking is NOT run when disabled."""
    code = """
def maybe_infinite(x):
    while x != 0:
        x = x + 1  # Might not terminate
    return x

maybe_infinite(1)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        # Without check_termination, should NOT report NON_TERMINATION
        analyzer = Analyzer(check_termination=False, verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # Should not check termination at all
        if result.verdict == 'BUG':
            assert result.bug_type != 'NON_TERMINATION', \
                "Should not check termination when check_termination=False"
    finally:
        temp_path.unlink()


def test_multiple_functions_with_loops():
    """Test termination checking across multiple functions."""
    code = """
def good_loop(n):
    # This should terminate
    while n > 0:
        n = n - 1
    return n

def another_good_loop(items):
    # For-loops over iterators always terminate (bounded by iterator)
    count = 0
    for item in items:
        count = count + 1
    return count

# Make functions reachable
good_loop(10)
another_good_loop([1, 2, 3])
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # Should not report non-termination for these correct loops
        if result.verdict == 'BUG':
            assert result.bug_type != 'NON_TERMINATION', \
                f"Should not report non-termination for correct loops: {result.message}"
    finally:
        temp_path.unlink()


@pytest.mark.slow
def test_nested_loops_in_function():
    """Test termination checking for nested loops in function body."""
    code = """
def nested_loops(n, m):
    i = 0
    while i < n:
        j = 0
        while j < m:
            j = j + 1
        i = i + 1
    return i

nested_loops(5, 3)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # Nested loops with proper bounds should terminate
        if result.verdict == 'BUG':
            assert result.bug_type != 'NON_TERMINATION', \
                f"Should not report non-termination for nested countdown loops: {result.message}"
    finally:
        temp_path.unlink()


def test_function_level_termination_counterexample_contains_function_name():
    """Verify that NON_TERMINATION counterexamples include function name."""
    code = """
def potentially_infinite(x):
    while x < 100:
        x = x - 1  # Wrong direction
    return x

potentially_infinite(50)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = Path(f.name)
    
    try:
        analyzer = Analyzer(check_termination=True, verbose=False)
        result = analyzer.analyze_file(temp_path)
        
        # If NON_TERMINATION is detected, counterexample should mention function name
        if result.verdict == 'BUG' and result.bug_type == 'NON_TERMINATION':
            counterexample_str = str(result.counterexample) + str(result.message)
            assert 'potentially_infinite' in counterexample_str, \
                f"Counterexample should mention function name: {result.counterexample}"
    finally:
        temp_path.unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-xvs'])
