"""
Tests for exception path forking from relational summaries.

Verifies that when a relational summary indicates exception_raised,
the VM properly sets state.exception and triggers exception handling.
"""

import pytest
import tempfile
import os
from pathlib import Path
from a3_python.analyzer import analyze


class TestExceptionPathForking:
    """Test exception handling from relational summaries."""
    
    def test_math_sqrt_negative_raises_fp_domain(self, tmp_path):
        """Test that math.sqrt(-1) triggers FP_DOMAIN bug detection."""
        code = """
import math
x = -1
y = math.sqrt(x)  # BUG: FP_DOMAIN (negative input to sqrt)
"""
        
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        
        # Should detect BUG
        assert result.verdict == "BUG"
        
        # Should have bug_type
        assert result.bug_type is not None
        # Should be either FP_DOMAIN or PANIC
        assert result.bug_type in ["FP_DOMAIN", "PANIC"]
    
    def test_math_sqrt_positive_no_bug(self, tmp_path):
        """Test that math.sqrt(4) does not trigger bugs."""
        code = """
import math
x = 4
y = math.sqrt(x)  # SAFE: positive input
"""
        
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        
        # Should not detect FP_DOMAIN bugs
        assert result.verdict in ["SAFE", "UNKNOWN"]
    
    def test_math_log_negative_raises_fp_domain(self, tmp_path):
        """Test that math.log(-1) triggers FP_DOMAIN bug detection."""
        code = """
import math
x = -1
y = math.log(x)  # BUG: FP_DOMAIN (negative input to log)
"""
        
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        
        # Should detect BUG
        assert result.verdict == "BUG"
        assert result.bug_type in ["FP_DOMAIN", "PANIC"]
    
    def test_math_log_zero_raises_fp_domain(self, tmp_path):
        """Test that math.log(0) triggers FP_DOMAIN bug detection."""
        code = """
import math
x = 0
y = math.log(x)  # BUG: FP_DOMAIN (zero input to log)
"""
        
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        
        # Should detect BUG
        assert result.verdict == "BUG"
        assert result.bug_type in ["FP_DOMAIN", "PANIC"]
    
    def test_math_asin_out_of_range_raises_fp_domain(self, tmp_path):
        """Test that math.asin(2) triggers FP_DOMAIN bug detection."""
        code = """
import math
x = 2
y = math.asin(x)  # BUG: FP_DOMAIN (out of range [-1, 1])
"""
        
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        
        # Should detect BUG
        assert result.verdict == "BUG"
        assert result.bug_type in ["FP_DOMAIN", "PANIC"]
    
    def test_math_acos_out_of_range_raises_fp_domain(self, tmp_path):
        """Test that math.acos(-2) triggers FP_DOMAIN bug detection."""
        code = """
import math
x = -2
y = math.acos(x)  # BUG: FP_DOMAIN (out of range [-1, 1])
"""
        
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        
        # Should detect BUG
        assert result.verdict == "BUG"
        assert result.bug_type in ["FP_DOMAIN", "PANIC"]

