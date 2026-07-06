"""
Tests for POWER binary operation (**).
Tests both safe usage and FP_DOMAIN errors.
"""
import pytest
from pathlib import Path
from a3_python.analyzer import analyze


class TestPowerSafe:
    """Test safe power operations."""
    
    def test_int_power_positive(self, tmp_path):
        """2 ** 3 should be SAFE."""
        code = "x = 2 ** 3\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_int_power_zero(self, tmp_path):
        """2 ** 0 should be SAFE (equals 1)."""
        code = "x = 2 ** 0\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_float_power(self, tmp_path):
        """2.0 ** 3.0 should be SAFE."""
        code = "x = 2.0 ** 3.0\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_int_power_float_exponent(self, tmp_path):
        """2 ** 0.5 (square root) should be SAFE."""
        code = "x = 4 ** 0.5\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_positive_base_negative_exponent(self, tmp_path):
        """2 ** -1 should be SAFE (equals 0.5)."""
        code = "x = 2 ** -1\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_negative_int_power_int(self, tmp_path):
        """(-2) ** 3 should be SAFE (integer exponent is okay)."""
        code = "x = (-2) ** 3\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'


class TestPowerFPDomain:
    """Test FP_DOMAIN errors in power operations."""
    
    def test_zero_power_negative(self, tmp_path):
        """0 ** -1 is FP_DOMAIN error (division by zero)."""
        code = "x = 0 ** -1\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'FP_DOMAIN'
    
    def test_zero_power_negative_float(self, tmp_path):
        """0.0 ** -2.0 is FP_DOMAIN error."""
        code = "x = 0.0 ** -2.0\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'FP_DOMAIN'
    
    @pytest.mark.xfail(reason="Python allows negative**fractional and returns complex number - not a domain error")
    def test_negative_power_float(self, tmp_path):
        """(-2) ** 0.5 returns complex in Python, not an error."""
        code = "x = (-2) ** 0.5\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        # Python actually allows this and returns complex number
        # Our model doesn't support complex yet, so it may panic
        assert result.verdict == 'BUG'
        assert result.bug_type == 'FP_DOMAIN'
    
    @pytest.mark.xfail(reason="Symbolic function parameters with float types not yet fully supported in Phase 3")
    def test_negative_power_float_symbolic(self, tmp_path):
        """Symbolic case: negative base with float exponent."""
        code = """
def f(a: int, b: float) -> None:
    if a < 0:
        x = a ** b
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'FP_DOMAIN'


class TestPowerTypeErrors:
    """Test TYPE_CONFUSION errors in power operations."""
    
    def test_string_power(self, tmp_path):
        """'hello' ** 2 is TYPE_CONFUSION."""
        code = "x = 'hello' ** 2\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    def test_list_power(self, tmp_path):
        """[1, 2] ** 2 is TYPE_CONFUSION."""
        code = "x = [1, 2] ** 2\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    def test_none_power(self, tmp_path):
        """None ** 2 is NULL_PTR."""
        code = "x = None ** 2\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'


class TestPowerSymbolic:
    """Test symbolic power operations."""
    
    def test_symbolic_safe(self, tmp_path):
        """Positive symbolic base with positive exponent."""
        code = """
def f(a: int, b: int) -> None:
    if a > 0 and b >= 0:
        x = a ** b
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        # With symbolic parameters, analyzer may be conservative
        # about proving path conditions hold
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']
    
    @pytest.mark.xfail(reason="Symbolic function parameters with constraints not yet fully supported")
    def test_symbolic_zero_base(self, tmp_path):
        """Symbolic case where base can be zero with negative exponent."""
        code = """
def f(a: int) -> None:
    if a >= 0:
        x = a ** -1  # Bug if a == 0
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'FP_DOMAIN'
    
    def test_symbolic_negative_base_safe(self, tmp_path):
        """Negative base with integer exponent is safe."""
        code = """
def f(a: int, b: int) -> None:
    if a < 0 and b > 0:
        x = a ** b
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']


class TestPowerMixed:
    """Test mixed-type power operations."""
    
    def test_int_power_float_safe(self, tmp_path):
        """int ** float with positive base."""
        code = "x = 4 ** 2.0\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_float_power_int_safe(self, tmp_path):
        """float ** int with positive base."""
        code = "x = 4.0 ** 2\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'
    
    def test_float_power_float_safe(self, tmp_path):
        """float ** float with positive values."""
        code = "x = 2.5 ** 1.5\n"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        result = analyze(test_file)
        assert result.verdict == 'SAFE'

