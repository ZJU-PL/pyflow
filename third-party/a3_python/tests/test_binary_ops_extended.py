"""
Tests for extended binary operations support.

Covers:
- Mixed numeric operations (int + float, etc.)
- String repetition (str * int, int * str)
- List concatenation (list + list)
- List repetition (list * int, int * list)

These tests verify that the semantic model correctly handles
Python's binary operation semantics across different type combinations.
"""

import pytest
from pathlib import Path
from a3_python.analyzer import analyze


class TestIntFloatOperations:
    """Test mixed int/float arithmetic operations."""
    
    def test_int_plus_float_safe(self, tmp_path):
        """int + float should work without error."""
        code = "x = 3\ny = 2.5\nz = x + y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_float_plus_int_safe(self, tmp_path):
        """float + int should work without error."""
        code = "x = 2.5\ny = 3\nz = x + y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_int_times_float_safe(self, tmp_path):
        """int * float should work without error."""
        code = "x = 3\ny = 2.5\nz = x * y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_float_div_zero_bug(self, tmp_path):
        """float / 0 should detect DIV_ZERO."""
        code = "x = 7.0\ny = 0\nz = x / y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == "BUG"
        assert result.bug_type == "DIV_ZERO"


class TestStringOperations:
    """Test string concatenation and repetition."""
    
    def test_string_concat_safe(self, tmp_path):
        """String concatenation should work (already supported)."""
        code = 'x = "hello"\ny = "world"\nz = x + y\n'
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_string_times_int_safe(self, tmp_path):
        """str * int repetition should work."""
        code = 'x = "ab"\ny = 3\nz = x * y\n'
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_int_times_string_safe(self, tmp_path):
        """int * str repetition should work."""
        code = 'x = 3\ny = "ab"\nz = x * y\n'
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]


class TestListOperations:
    """Test list concatenation and repetition."""
    
    def test_list_concat_safe(self, tmp_path):
        """List concatenation should work."""
        code = "x = [1, 2]\ny = [3, 4]\nz = x + y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_list_times_int_safe(self, tmp_path):
        """list * int repetition should work."""
        code = "x = [1, 2]\ny = 3\nz = x * y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_int_times_list_safe(self, tmp_path):
        """int * list repetition should work."""
        code = "x = 3\ny = [1, 2]\nz = x * y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ["SAFE", "UNKNOWN"]


class TestTypeErrors:
    """Test that invalid type combinations still detect errors."""
    
    def test_string_plus_int_type_error(self, tmp_path):
        """str + int should detect TYPE_CONFUSION or raise exception."""
        code = 'x = "hello"\ny = 3\nz = x + y\n'
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        # Should either be BUG or UNKNOWN, but NOT SAFE
        assert result.verdict != "SAFE"
    
    def test_list_plus_int_type_error(self, tmp_path):
        """list + int should detect TYPE_CONFUSION or raise exception."""
        code = "x = [1, 2]\ny = 3\nz = x + y\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict != "SAFE"
