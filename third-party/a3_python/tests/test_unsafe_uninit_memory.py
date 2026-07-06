"""
Tests for UNINIT_MEMORY unsafe region.

UNINIT_MEMORY occurs when reading from uninitialized memory:
- Reading from uninitialized native buffers (ctypes, array.array)
- Accessing uninitialized __slots__ attributes
- Using memoryview/buffer objects before initialization
- Native extension memory reads before initialization
- Reading from unallocated struct/mmap regions

These tests validate the semantic model's ability to detect uninitialized
memory access by tracking initialization state of buffers and memory regions.
"""

import pytest
from a3_python.unsafe import uninit_memory
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


class MockState:
    """Mock state for unit testing predicates."""
    def __init__(self):
        self.exception = None
        self.exception_message = ""
        self.halted = False
        self.frame_stack = []
        self.uninit_memory_reached = False
        self.buffer_states = {}


class MockBufferState:
    """Mock buffer state tracking."""
    def __init__(self, uninitialized_read=False, buffer_type="unknown", access_type="read"):
        self.uninitialized_read = uninitialized_read
        self.buffer_type = buffer_type
        self.access_type = access_type


class TestUninitMemoryPredicateUnit:
    """Unit tests for is_unsafe_uninit_memory predicate."""
    
    def test_uninit_memory_flag_set(self):
        """Predicate returns True when uninit_memory_reached flag is set."""
        state = MockState()
        state.uninit_memory_reached = True
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_buffer_uninitialized_read(self):
        """Predicate returns True when buffer state shows uninitialized read."""
        state = MockState()
        state.buffer_states = {
            "buffer_123": MockBufferState(uninitialized_read=True, buffer_type="ctypes_buffer")
        }
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_multiple_buffers_one_uninit(self):
        """Predicate returns True when one of multiple buffers has uninit read."""
        state = MockState()
        state.buffer_states = {
            "buffer_1": MockBufferState(uninitialized_read=False),
            "buffer_2": MockBufferState(uninitialized_read=True, buffer_type="array"),
            "buffer_3": MockBufferState(uninitialized_read=False)
        }
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_attribute_error_slot_access(self):
        """Predicate returns True for AttributeError on uninitialized __slots__."""
        state = MockState()
        state.exception = "AttributeError"
        state.exception_message = "object has no attribute 'x' (uninitialized slot)"
        state.is_slot_access = True
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_value_error_uninitialized_buffer(self):
        """Predicate returns True for ValueError on uninitialized buffer."""
        state = MockState()
        state.exception = "ValueError"
        state.exception_message = "buffer not initialized"
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_value_error_invalid_buffer(self):
        """Predicate returns True for ValueError indicating invalid/uninit buffer."""
        state = MockState()
        state.exception = "ValueError"
        state.exception_message = "invalid buffer state"
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_system_error_uninitialized(self):
        """Predicate returns True for SystemError from native uninit memory."""
        state = MockState()
        state.exception = "SystemError"
        state.exception_message = "uninitialized memory access in native extension"
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_no_uninit_memory(self):
        """Predicate returns False when no uninitialized memory is accessed."""
        state = MockState()
        assert not uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_initialized_buffer_no_error(self):
        """Predicate returns False for properly initialized buffers."""
        state = MockState()
        state.buffer_states = {
            "buffer_123": MockBufferState(uninitialized_read=False, buffer_type="bytearray")
        }
        assert not uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_attribute_error_not_slot(self):
        """Predicate returns False for AttributeError on regular missing attribute."""
        state = MockState()
        state.exception = "AttributeError"
        state.exception_message = "object has no attribute 'x'"
        # No is_slot_access flag, so this is just a missing attribute
        assert not uninit_memory.is_unsafe_uninit_memory(state)


class TestUninitMemoryExtractorUnit:
    """Unit tests for extract_counterexample."""
    
    def test_extract_with_flag(self):
        """Extractor produces correct structure when flag is set."""
        state = MockState()
        state.uninit_memory_reached = True
        state.uninit_buffer_id = "buffer_456"
        state.uninit_buffer_type = "ctypes"
        state.uninit_access_type = "read"
        
        result = uninit_memory.extract_counterexample(state, ["step1", "step2"])
        
        assert result["bug_type"] == "UNINIT_MEMORY"
        assert result["trace"] == ["step1", "step2"]
        assert result["final_state"]["uninit_memory_reached"] is True
        assert result["final_state"]["buffer_id"] == "buffer_456"
        assert result["final_state"]["buffer_type"] == "ctypes"
        assert result["final_state"]["access_type"] == "read"
    
    def test_extract_from_buffer_states(self):
        """Extractor infers details from buffer_states."""
        state = MockState()
        state.buffer_states = {
            "buf_789": MockBufferState(
                uninitialized_read=True,
                buffer_type="memoryview",
                access_type="index"
            )
        }
        
        result = uninit_memory.extract_counterexample(state, ["trace"])
        
        assert result["final_state"]["buffer_id"] == "buf_789"
        assert result["final_state"]["buffer_type"] == "memoryview"
        assert result["final_state"]["access_type"] == "index"
    
    def test_extract_from_exception(self):
        """Extractor infers buffer type from exception."""
        state = MockState()
        state.exception = "AttributeError"
        state.exception_message = "slot not initialized"
        state.uninit_memory_reached = True
        
        result = uninit_memory.extract_counterexample(state, [])
        
        assert result["final_state"]["buffer_type"] == "slot_attribute"
        assert result["final_state"]["access_type"] == "attribute_access"


class TestUninitMemoryIntegration:
    """Integration tests with symbolic VM (when available)."""
    
    @pytest.mark.xfail(reason="Requires symbolic VM buffer tracking implementation")
    def test_read_uninit_ctypes_buffer(self):
        """BUG: Reading from ctypes buffer before initialization."""
        code = compile("""
import ctypes
buf = ctypes.create_string_buffer(10)  # Uninitialized
value = buf[0]  # Read uninitialized memory
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'UNINIT_MEMORY']
        
        assert len(bugs) > 0, "Should detect UNINIT_MEMORY"
        assert "buffer" in str(bugs[0]).lower()
    
    @pytest.mark.xfail(reason="Requires __slots__ tracking")
    def test_read_uninit_slot(self):
        """BUG: Accessing uninitialized __slots__ attribute."""
        code = compile("""
class Point:
    __slots__ = ('x', 'y')

p = Point()
value = p.x  # Slot 'x' never assigned, uninitialized
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'UNINIT_MEMORY']
        
        assert len(bugs) > 0, "Should detect UNINIT_MEMORY"
    
    @pytest.mark.xfail(reason="Requires array tracking")
    def test_read_uninit_array_element(self):
        """BUG: Reading array element before assignment."""
        code = """
import array
arr = array.array('i', [0] * 10)
# Simulate uninitialized region (would need native interface)
# In practice, Python array.array initializes to zero
# This would need explicit native extension simulation
value = arr[5]  # Would be uninitialized in native context
"""
        # This is more of a conceptual test - Python's array initializes
        # Real uninit would come from native extensions
        pytest.skip("Python array.array initializes memory; need native extension simulation")
    
    def test_safe_initialized_buffer(self):
        """NON-BUG: Reading from properly initialized buffer."""
        code = compile("""
import array
arr = array.array('i', [1, 2, 3])
value = arr[0]  # Safe: initialized to 1
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should not detect UNINIT_MEMORY
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        uninit_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'UNINIT_MEMORY']
        
        assert len(uninit_bugs) == 0, "Should not detect UNINIT_MEMORY on initialized buffer"
    
    def test_safe_slot_with_default(self):
        """NON-BUG: Accessing __slots__ with default value."""
        code = compile("""
class Point:
    __slots__ = ('x', 'y')
    def __init__(self):
        self.x = 0
        self.y = 0

p = Point()
value = p.x  # Safe: initialized in __init__
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        # Should not detect UNINIT_MEMORY
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        uninit_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'UNINIT_MEMORY']
        
        assert len(uninit_bugs) == 0, "Should not detect UNINIT_MEMORY on initialized slot"
    
    @pytest.mark.xfail(reason="Requires memoryview tracking")
    def test_read_uninit_memoryview(self):
        """BUG: Reading from uninitialized memoryview."""
        code = """
import array
arr = array.array('b', [0] * 10)
mv = memoryview(arr)
# Simulate reading uninitialized portion
# (would need explicit tracking of initialization state)
value = mv[0]
"""
        pytest.skip("Requires explicit memoryview initialization tracking")
    
    def test_safe_bytearray_with_init(self):
        """NON-BUG: bytearray is initialized by constructor."""
        code = compile("""
ba = bytearray(10)  # Initialized to zeros
value = ba[0]  # Safe: initialized to 0
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should not detect UNINIT_MEMORY
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        uninit_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'UNINIT_MEMORY']
        
        assert len(uninit_bugs) == 0, "Should not detect UNINIT_MEMORY on initialized bytearray"
    
    def test_safe_regular_attribute_access(self):
        """NON-BUG: Regular instance attribute access after assignment."""
        code = compile("""
class Point:
    pass

p = Point()
p.x = 10
value = p.x  # Safe: initialized to 10
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        # Should not detect UNINIT_MEMORY
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        uninit_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'UNINIT_MEMORY']
        
        assert len(uninit_bugs) == 0, "Should not detect UNINIT_MEMORY on initialized attribute"


class TestUninitMemorySemantics:
    """Tests validating semantic model correctness."""
    
    def test_uninit_memory_at_native_boundary(self):
        """UNINIT_MEMORY is primarily a native-boundary concern."""
        # In pure Python, all objects are initialized
        # UNINIT_MEMORY occurs at:
        # 1. ctypes/cffi native memory
        # 2. Native extension objects
        # 3. Buffer protocol with uninitialized backing
        # 4. __slots__ without assignment (AttributeError)
        
        # This test documents the semantic model
        state = MockState()
        
        # Pure Python case: no uninit memory
        assert not uninit_memory.is_unsafe_uninit_memory(state)
        
        # Native boundary case: uninit buffer
        state.buffer_states = {
            "native_buf": MockBufferState(uninitialized_read=True, buffer_type="ctypes")
        }
        assert uninit_memory.is_unsafe_uninit_memory(state)
    
    def test_uninit_vs_unassigned_distinction(self):
        """Distinguish uninitialized memory from unassigned variables."""
        # Unassigned variable: NameError (caught by NameError detection)
        state1 = MockState()
        state1.exception = "NameError"
        state1.exception_message = "name 'x' is not defined"
        # This is NOT uninit memory, it's a name resolution issue
        assert not uninit_memory.is_unsafe_uninit_memory(state1)
        
        # Uninitialized slot: AttributeError with slot context
        state2 = MockState()
        state2.exception = "AttributeError"
        state2.exception_message = "slot 'x' not initialized"
        state2.is_slot_access = True
        # This IS uninit memory (slot allocated but not written)
        assert uninit_memory.is_unsafe_uninit_memory(state2)
    
    def test_uninit_memory_requires_allocation(self):
        """UNINIT_MEMORY requires memory to be allocated but not initialized."""
        # Not allocated: would be NULL_PTR or NameError
        # Allocated but not initialized: UNINIT_MEMORY
        # Allocated and initialized: safe
        
        state = MockState()
        state.uninit_memory_reached = True
        state.uninit_buffer_id = "buffer_allocated_but_not_init"
        
        assert uninit_memory.is_unsafe_uninit_memory(state)
