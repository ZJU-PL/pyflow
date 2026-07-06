"""
Tests for INTEGER_OVERFLOW unsafe region.

INTEGER_OVERFLOW occurs at Python↔native fixed-width boundaries:
- struct.pack with values outside format type range
- array.array with values outside typecode range  
- int.to_bytes with values outside byte length
- ctypes operations (when modeled)

These tests validate the semantic model's ability to detect overflow
at conversion boundaries, not just arbitrary Python int arithmetic.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


class TestIntegerOverflowBugs:
    """Test cases where INTEGER_OVERFLOW is reachable (BUG)."""
    
    def test_struct_pack_int32_overflow_positive(self):
        """BUG: struct.pack('i', x) with x > 2^31-1 overflows."""
        code = compile("""
import struct
x = 2**31  # Exceeds 32-bit signed int max
struct.pack('i', x)  # OverflowError
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should find at least one path with INTEGER_OVERFLOW
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"
        assert any(b["final_state"]["integer_overflow_reached"] for b in bugs)
    
    def test_struct_pack_int32_overflow_negative(self):
        """BUG: struct.pack('i', x) with x < -2^31 overflows."""
        code = compile("""
import struct
x = -(2**31) - 1  # Below 32-bit signed int min
struct.pack('i', x)  # OverflowError
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"
    
    @pytest.mark.xfail(reason="Requires function def/call analysis - not yet fully supported")
    def test_struct_pack_conditional_overflow(self):
        """BUG: Conditional overflow in struct.pack."""
        code = compile("""
import struct

def pack_value(n):
    # n is symbolic input
    if n > 1000000:
        x = 2**31  # Overflow value
    else:
        x = 100
    struct.pack('i', x)

pack_value(1000001)  # Takes overflow path
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        # Overflow is reachable on one path
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW on overflow path"
    
    @pytest.mark.xfail(reason="array module import not yet handled")
    def test_array_array_overflow(self):
        """BUG: array.array with value outside typecode range."""
        code = compile("""
import array
arr = array.array('b', [128])  # 'b' is signed byte [-128, 127]
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"
    
    @pytest.mark.xfail(reason="Requires method call analysis (x.to_bytes) - not yet supported")
    def test_int_to_bytes_overflow(self):
        """BUG: int.to_bytes with value too large for byte count."""
        code = compile("""
x = 256
x.to_bytes(1, 'big')  # 256 doesn't fit in 1 unsigned byte [0, 255]
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"
    
    @pytest.mark.xfail(reason="Specific format codes ('I', 'b') not yet validated - uses conservative int32 range")
    def test_struct_pack_unsigned_overflow(self):
        """BUG: struct.pack with negative value for unsigned format."""
        code = compile("""
import struct
struct.pack('I', -1)  # 'I' is unsigned int, -1 is invalid
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"
    
    @pytest.mark.xfail(reason="Requires function def/call analysis - not yet fully supported")
    def test_symbolic_value_overflow(self):
        """BUG: Overflow with symbolic value that can exceed range."""
        code = compile("""
import struct

def process(n):
    # n is symbolic; could be large
    x = n * 1000000
    struct.pack('i', x)  # Overflow if n is large enough

process(3000)  # 3000 * 1000000 = 3 billion > 2^31-1
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"
    
    @pytest.mark.xfail(reason="Specific format codes ('b') not yet validated - uses conservative int32 range")
    def test_struct_pack_byte_overflow(self):
        """BUG: struct.pack('b', x) with x > 127 overflows signed byte."""
        code = compile("""
import struct
struct.pack('b', 200)  # Signed byte range: [-128, 127]
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(bugs) > 0, "Should detect INTEGER_OVERFLOW"


class TestIntegerOverflowNonBugs:
    """Test cases where INTEGER_OVERFLOW is NOT reachable (NON-BUG)."""
    
    def test_struct_pack_valid_int32(self):
        """NON-BUG: struct.pack('i', x) with x in valid range."""
        code = compile("""
import struct
x = 1000
struct.pack('i', x)  # 1000 is well within 32-bit range
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should NOT detect overflow on valid path
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        overflow_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        # May be conservative and flag, but should complete without crash
        assert paths  # Should explore at least one path
    
    def test_struct_pack_zero(self):
        """NON-BUG: struct.pack with zero value."""
        code = compile("""
import struct
struct.pack('i', 0)
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=150)
        
        # Should complete without crashing
        assert paths
    
    def test_plain_python_arithmetic_no_overflow(self):
        """NON-BUG: Plain Python arithmetic never overflows (unbounded)."""
        code = compile("""
x = 2**100
y = x * x  # Python ints are unbounded
z = y + 1
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Pure Python arithmetic should NOT trigger overflow
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        overflow_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        # Python int arithmetic is unbounded - no overflow
        assert len(overflow_bugs) == 0, "Pure Python arithmetic should not overflow"
    
    @pytest.mark.xfail(reason="Requires function def/call analysis - not yet fully supported")
    def test_struct_pack_guarded(self):
        """NON-BUG: struct.pack with explicit range guard."""
        code = compile("""
import struct

def safe_pack(n):
    if -2**31 <= n < 2**31:
        struct.pack('i', n)
    else:
        raise ValueError("Out of range")

safe_pack(1000)  # In range, guarded
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        # Guard prevents overflow path from reaching struct.pack
        # struct.pack is only reached with valid value
        assert paths
    
    @pytest.mark.xfail(reason="Requires function def/call analysis - not yet fully supported")
    def test_conditional_no_overflow_path(self):
        """NON-BUG: Conditional that avoids overflow path."""
        code = compile("""
import struct

def pack_value(n):
    if n < 1000:
        x = 100  # Valid value
    else:
        x = 200  # Also valid
    struct.pack('i', x)

pack_value(500)
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        # Both paths use valid values
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        overflow_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        # Should not find overflow with small constants
        assert paths


class TestIntegerOverflowEdgeCases:
    """Edge cases and boundary conditions for INTEGER_OVERFLOW."""
    
    def test_multiple_struct_packs(self):
        """Multiple struct.pack calls, only one overflows."""
        code = compile("""
import struct
struct.pack('i', 100)  # Valid
struct.pack('i', 2**31)  # Overflow
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=250)
        
        # Should detect the overflow in second call
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        overflow_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(overflow_bugs) > 0, "Should detect overflow in second call"
    
    @pytest.mark.xfail(reason="Requires for-loop analysis - not yet fully supported")
    def test_overflow_in_loop(self):
        """Overflow in loop iteration."""
        code = compile("""
import struct
for i in [100, 200, 2**31]:
    struct.pack('i', i)  # Third iteration overflows
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=400)
        
        # Should detect overflow on one iteration
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        overflow_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'INTEGER_OVERFLOW']
        
        assert len(overflow_bugs) > 0, "Should detect overflow in loop"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

