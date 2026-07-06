"""
Tests for type annotation evaluation semantics (Python 3.9+).

Type parameterization like Mapping[str, str] or Callable[[A], B] 
creates GenericAlias objects and should not raise IndexError.
"""
import pytest
import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer


def analyze_code(code: str, max_paths: int = 100):
    """Helper function to analyze code string."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = f.name
    
    try:
        analyzer = Analyzer(max_paths=max_paths)
        result = analyzer.analyze_file(temp_path)
        return result
    finally:
        Path(temp_path).unlink()


def test_type_annotation_mapping():
    """Test that Mapping[str, str] type annotation doesn't raise IndexError."""
    code = """
from typing import Mapping

# This should succeed - type parameterization, not list subscript
QueryParams = Mapping[str, str]
"""
    result = analyze_code(code, max_paths=100)
    
    # Should NOT report BOUNDS bug (IndexError)
    if result.verdict == 'BUG':
        assert result.bug_type != 'BOUNDS', \
            f"Expected no BOUNDS bug from type annotation, got: {result.bug_type}"


def test_type_annotation_callable():
    """Test that Callable[[Request], Response] type annotation doesn't raise IndexError."""
    code = """
from typing import Callable

# Type parameterization with list syntax inside
Handler = Callable[[int], str]
"""
    result = analyze_code(code, max_paths=100)
    
    # Should NOT report BOUNDS bug (IndexError)
    if result.verdict == 'BUG':
        assert result.bug_type != 'BOUNDS', \
            f"Expected no BOUNDS bug from type annotation, got: {result.bug_type}"


def test_type_annotation_list():
    """Test that list[int] type annotation doesn't raise IndexError (Python 3.9+)."""
    code = """
# Built-in generic: list[int] (Python 3.9+)
# This uses lowercase 'list', not typing.List
IntList = list[int]
"""
    result = analyze_code(code, max_paths=100)
    
    # Should NOT report BOUNDS bug (IndexError)
    if result.verdict == 'BUG':
        assert result.bug_type != 'BOUNDS', \
            f"Expected no BOUNDS bug from type annotation, got: {result.bug_type}"


def test_type_annotation_dict():
    """Test that dict[str, int] type annotation doesn't raise IndexError (Python 3.9+)."""
    code = """
# Built-in generic: dict[str, int] (Python 3.9+)
StrIntDict = dict[str, int]
"""
    result = analyze_code(code, max_paths=100)
    
    # Should NOT report BOUNDS bug (IndexError)
    if result.verdict == 'BUG':
        assert result.bug_type != 'BOUNDS', \
            f"Expected no BOUNDS bug from type annotation, got: {result.bug_type}"


def test_real_list_subscript_still_detected():
    """Verify that real list subscript bugs are still detected."""
    code = """
# Direct list subscript at module level (not in uncalled function)
xs = [1, 2, 3]
result = xs[10]  # This should be detected as BOUNDS
"""
    result = analyze_code(code, max_paths=100)
    
    # Should report BOUNDS bug (real IndexError)
    assert result.verdict == 'BUG', f"Expected BUG but got {result.verdict}"
    assert result.bug_type == 'BOUNDS', f"Expected BOUNDS bug but got: {result.bug_type}"


def test_type_annotation_nested():
    """Test nested type parameterization like dict[str, list[int]]."""
    code = """
from typing import Dict, List

# Nested generic types
NestedType = Dict[str, List[int]]
"""
    result = analyze_code(code, max_paths=100)
    
    # Should NOT report BOUNDS bug
    if result.verdict == 'BUG':
        assert result.bug_type != 'BOUNDS', \
            f"Expected no BOUNDS bug from type annotation, got: {result.bug_type}"


def test_type_annotation_at_module_level():
    """Test type annotations evaluated at module initialization."""
    code = """
from typing import Mapping

# Module-level type annotation (evaluated at import time)
HEADERS: Mapping[str, str] = {}
"""
    result = analyze_code(code, max_paths=100)
    
    # Should NOT report BOUNDS bug from type annotation
    if result.verdict == 'BUG':
        assert result.bug_type != 'BOUNDS', \
            f"Expected no BOUNDS bug from type annotation, got: {result.bug_type}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
