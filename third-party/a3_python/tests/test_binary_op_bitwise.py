"""
Test BINARY_OP bitwise operations: <<, >>, &, |, ^

Tests semantic coverage for bitwise operations on integers.
"""

import pytest
from pathlib import Path
from a3_python.analyzer import analyze


class TestBitwiseOperations:
    """Test bitwise operations (<<, >>, &, |, ^)."""
    
    # LEFT SHIFT (<<)
    def test_lshift_basic(self, tmp_path):
        """Basic left shift: 1 << 2 = 4."""
        code = """
def f():
    x = 1 << 2
    return x
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_lshift_variables(self, tmp_path):
        """Left shift with variables - can fail with negative b."""
        code = """
def f(a, b):
    return a << b
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        # With unconstrained symbolic b, negative b causes ValueError
        # Correct verdict is BUG (or UNKNOWN), not SAFE
        assert result.verdict in ['BUG', 'UNKNOWN']
    
    def test_lshift_large_shift(self, tmp_path):
        """Left shift with large shift amount."""
        code = """
def f():
    x = 1
    y = x << 100
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_lshift_none_left(self, tmp_path):
        """Left shift with None as left operand - NULL_PTR."""
        code = "x = None << 1\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'
    
    def test_lshift_none_right(self, tmp_path):
        """Left shift with None as right operand - NULL_PTR."""
        code = "x = 1 << None\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'
    
    def test_lshift_type_error_float(self, tmp_path):
        """Left shift with float - TYPE_CONFUSION."""
        code = "x = 1.5 << 2\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    def test_lshift_type_error_str(self, tmp_path):
        """Left shift with string - TYPE_CONFUSION."""
        code = 'x = "abc" << 2\n'
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    # RIGHT SHIFT (>>)
    def test_rshift_basic(self, tmp_path):
        """Basic right shift: 8 >> 2 = 2."""
        code = """
def f():
    x = 8 >> 2
    return x
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_rshift_variables(self, tmp_path):
        """Right shift with variables - can fail with negative b."""
        code = """
def f(a, b):
    return a >> b
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        # With unconstrained symbolic b, negative b causes ValueError
        assert result.verdict in ['BUG', 'UNKNOWN']
    
    def test_rshift_negative(self, tmp_path):
        """Right shift of negative number."""
        code = """
def f():
    x = -8
    y = x >> 1
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_rshift_none_operand(self, tmp_path):
        """Right shift with None - NULL_PTR."""
        code = "x = None >> 1\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'
    
    def test_rshift_type_error(self, tmp_path):
        """Right shift with incompatible type - TYPE_CONFUSION."""
        code = "x = 8.5 >> 1\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    # BITWISE AND (&)
    def test_and_basic(self, tmp_path):
        """Basic bitwise AND: 5 & 3 = 1."""
        code = """
def f():
    x = 5 & 3
    return x
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_and_variables(self, tmp_path):
        """Bitwise AND with variables - type-safe with integers."""
        code = """
def f(a, b):
    return a & b
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        # Bitwise AND works on any integers (or compatible types)
        # May report BUG if type confusion is detected
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']
    
    def test_and_zero(self, tmp_path):
        """Bitwise AND with zero."""
        code = """
def f():
    x = 42
    y = x & 0
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_and_none_operand(self, tmp_path):
        """Bitwise AND with None - NULL_PTR."""
        code = "x = 5 & None\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'
    
    def test_and_type_error(self, tmp_path):
        """Bitwise AND with incompatible type - TYPE_CONFUSION."""
        code = 'x = 5 & "abc"\n'
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    # BITWISE OR (|)
    def test_or_basic(self, tmp_path):
        """Basic bitwise OR: 5 | 3 = 7."""
        code = """
def f():
    x = 5 | 3
    return x
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_or_variables(self, tmp_path):
        """Bitwise OR with variables."""
        code = """
def f(a, b):
    return a | b
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']
    
    def test_or_zero(self, tmp_path):
        """Bitwise OR with zero."""
        code = """
def f():
    x = 42
    y = x | 0
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_or_none_operand(self, tmp_path):
        """Bitwise OR with None - NULL_PTR."""
        code = "x = None | 5\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'
    
    def test_or_type_error(self, tmp_path):
        """Bitwise OR with incompatible type - TYPE_CONFUSION."""
        code = "x = 5 | [1, 2, 3]\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    # BITWISE XOR (^)
    def test_xor_basic(self, tmp_path):
        """Basic bitwise XOR: 5 ^ 3 = 6."""
        code = """
def f():
    x = 5 ^ 3
    return x
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_xor_variables(self, tmp_path):
        """Bitwise XOR with variables."""
        code = """
def f(a, b):
    return a ^ b
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict in ['SAFE', 'BUG', 'UNKNOWN']
    
    def test_xor_same_value(self, tmp_path):
        """Bitwise XOR with same value (always 0)."""
        code = """
def f():
    x = 42
    y = x ^ x
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_xor_none_operand(self, tmp_path):
        """Bitwise XOR with None - NULL_PTR."""
        code = "x = 5 ^ None\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'NULL_PTR'
    
    def test_xor_type_error(self, tmp_path):
        """Bitwise XOR with incompatible type - TYPE_CONFUSION."""
        code = "x = 5 ^ 3.14\n"
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'BUG'
        assert result.bug_type == 'TYPE_CONFUSION'
    
    # COMBINED OPERATIONS
    def test_combined_bitwise_ops(self, tmp_path):
        """Multiple bitwise operations combined."""
        code = """
def f():
    x = 5
    y = 3
    z = (x & y) | (x ^ y)
    return z
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_shift_and_mask(self, tmp_path):
        """Shift and mask pattern (common in bit manipulation)."""
        code = """
def f():
    x = 0xFF
    y = (x << 8) & 0xFFFF
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_bit_flag_manipulation(self, tmp_path):
        """Bit flag manipulation pattern."""
        code = """
def f():
    flags = 0
    FLAG_A = 1 << 0
    FLAG_B = 1 << 1
    FLAG_C = 1 << 2
    
    flags = flags | FLAG_A | FLAG_C
    has_flag_b = (flags & FLAG_B) != 0
    return flags
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_bitwise_inverse_pattern(self, tmp_path):
        """Bitwise operations with ~-like pattern (using XOR with -1)."""
        code = """
def f():
    x = 5
    y = x ^ (-1)
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    # EDGE CASES
    def test_lshift_by_zero(self, tmp_path):
        """Left shift by zero."""
        code = """
def f():
    x = 42
    y = x << 0
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_rshift_by_zero(self, tmp_path):
        """Right shift by zero."""
        code = """
def f():
    x = 42
    y = x >> 0
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_and_with_negative(self, tmp_path):
        """Bitwise AND with negative number."""
        code = """
def f():
    x = 5
    y = -1
    z = x & y
    return z
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'
    
    def test_mixed_shifts_and_bitwise(self, tmp_path):
        """Complex expression with shifts and bitwise ops."""
        code = """
def f():
    x = 1
    y = ((x << 4) | (x << 2)) & 0xFF
    return y
"""
        p = tmp_path / "test.py"
        p.write_text(code)
        
        result = analyze(p)
        assert result.verdict == 'SAFE'

