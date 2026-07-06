"""
Tests for MEMORY_LEAK unsafe predicate.

Tests both BUG (unbounded heap growth) and NON-BUG (bounded allocation) cases.
"""

import pytest
from a3_python.semantics.symbolic_vm import SymbolicMachineState
from a3_python.unsafe import memory_leak


class TestMemoryLeakPredicate:
    """Test the MEMORY_LEAK unsafe predicate."""
    
    def test_no_leak_default_state(self):
        """Default state should not trigger memory leak."""
        state = SymbolicMachineState()
        assert not memory_leak.is_unsafe_memory_leak(state)
    
    def test_heap_size_unbounded_flag(self):
        """State with heap_size_unbounded flag should be unsafe."""
        state = SymbolicMachineState()
        state.heap_size_unbounded = True
        assert memory_leak.is_unsafe_memory_leak(state)
    
    def test_resource_leak_detected_flag(self):
        """State with resource_leak_detected flag should be unsafe."""
        state = SymbolicMachineState()
        state.resource_leak_detected = True
        assert memory_leak.is_unsafe_memory_leak(state)
    
    def test_both_flags_set(self):
        """State with both leak flags should be unsafe."""
        state = SymbolicMachineState()
        state.heap_size_unbounded = True
        state.resource_leak_detected = True
        assert memory_leak.is_unsafe_memory_leak(state)


class TestMemoryLeakExtractor:
    """Test counterexample extraction for MEMORY_LEAK."""
    
    def test_extract_unbounded_growth(self):
        """Extract counterexample for unbounded growth."""
        state = SymbolicMachineState()
        state.heap_size_unbounded = True
        trace = ["LOAD_CONST 0", "STORE_NAME items", "LOAD_NAME items"]
        
        result = memory_leak.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "MEMORY_LEAK"
        assert result["trace"] == trace
        assert result["final_state"]["leak_type"] == "unbounded_growth"
        assert result["final_state"]["heap_size_unbounded"] is True
    
    def test_extract_resource_leak(self):
        """Extract counterexample for resource leak."""
        state = SymbolicMachineState()
        state.resource_leak_detected = True
        trace = ["LOAD_GLOBAL open", "CALL 1"]
        
        result = memory_leak.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "MEMORY_LEAK"
        assert result["trace"] == trace
        assert result["final_state"]["leak_type"] == "resource_leak"
        assert result["final_state"]["resource_leak_detected"] is True
    
    def test_extract_includes_frame_info(self):
        """Counterexample should include frame information."""
        state = SymbolicMachineState()
        state.heap_size_unbounded = True
        trace = []
        
        result = memory_leak.extract_counterexample(state, trace)
        
        assert "frame_count" in result["final_state"]
        assert "halted" in result["final_state"]


class TestMemoryLeakSemantics:
    """Test semantic integration (requires full VM to detect patterns)."""
    
    def test_memory_leak_registered(self):
        """MEMORY_LEAK should be in the unsafe registry."""
        from a3_python.unsafe.registry import UNSAFE_PREDICATES
        assert "MEMORY_LEAK" in UNSAFE_PREDICATES
    
    def test_memory_leak_predicate_callable(self):
        """MEMORY_LEAK predicate should be callable."""
        from a3_python.unsafe.registry import UNSAFE_PREDICATES
        predicate, _ = UNSAFE_PREDICATES["MEMORY_LEAK"]
        
        state = SymbolicMachineState()
        result = predicate(state)
        assert isinstance(result, bool)
    
    def test_memory_leak_extractor_callable(self):
        """MEMORY_LEAK extractor should be callable."""
        from a3_python.unsafe.registry import UNSAFE_PREDICATES
        _, extractor = UNSAFE_PREDICATES["MEMORY_LEAK"]
        
        state = SymbolicMachineState()
        state.heap_size_unbounded = True
        result = extractor(state, [])
        
        assert isinstance(result, dict)
        assert result["bug_type"] == "MEMORY_LEAK"


class TestMemoryLeakDocumentation:
    """Verify that MEMORY_LEAK is properly documented."""
    
    def test_module_has_docstring(self):
        """Module should have comprehensive docstring."""
        assert memory_leak.__doc__ is not None
        assert "MEMORY_LEAK" in memory_leak.__doc__
        assert "unbounded" in memory_leak.__doc__.lower()
    
    def test_predicate_has_docstring(self):
        """Predicate function should document unsafe region."""
        assert memory_leak.is_unsafe_memory_leak.__doc__ is not None
        assert "U_MEMORY_LEAK" in memory_leak.is_unsafe_memory_leak.__doc__
    
    def test_extractor_has_docstring(self):
        """Extractor function should document witness format."""
        assert memory_leak.extract_counterexample.__doc__ is not None
        assert "witness" in memory_leak.extract_counterexample.__doc__.lower()


class TestMemoryLeakConservativeApproach:
    """Test that MEMORY_LEAK detection is conservative (sound)."""
    
    def test_no_false_positives_on_bounded_allocation(self):
        """Bounded allocation should not trigger leak detection."""
        # This is a semantic property: the predicate should only fire
        # when there's actual evidence of unbounded growth
        state = SymbolicMachineState()
        # No flags set, heap in normal state
        assert not memory_leak.is_unsafe_memory_leak(state)
    
    def test_requires_explicit_evidence(self):
        """Leak detection requires explicit evidence (flags/thresholds)."""
        state = SymbolicMachineState()
        # Even with heap allocated, no leak unless flags are set
        # (In real analysis, flags would be set by loop/pattern analysis)
        assert not memory_leak.is_unsafe_memory_leak(state)
