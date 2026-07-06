"""
Tests for DOUBLE_FREE unsafe region.

DOUBLE_FREE occurs when the same resource is freed/closed multiple times:
- Closing the same file handle twice
- Releasing the same lock twice
- Freeing the same native object twice
- Double-closing sockets, connections, etc.

These tests validate the semantic model's ability to detect double-free
by tracking resource lifecycle state (allocated -> freed -> freed again).
"""

import pytest
from a3_python.unsafe import double_free
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


class MockState:
    """Mock state for unit testing predicates."""
    def __init__(self):
        self.exception = None
        self.exception_message = ""
        self.halted = False
        self.frame_stack = []
        self.double_free_reached = False
        self.resource_states = {}


class MockResourceLifecycle:
    """Mock resource lifecycle tracking."""
    def __init__(self, free_count=0, resource_type="unknown"):
        self.free_count = free_count
        self.resource_type = resource_type


class TestDoubleFreePredicateUnit:
    """Unit tests for is_unsafe_double_free predicate."""
    
    def test_double_free_flag_set(self):
        """Predicate returns True when double_free_reached flag is set."""
        state = MockState()
        state.double_free_reached = True
        assert double_free.is_unsafe_double_free(state)
    
    def test_resource_freed_twice(self):
        """Predicate returns True when resource free_count >= 2."""
        state = MockState()
        state.resource_states = {
            "file_handle_123": MockResourceLifecycle(free_count=2, resource_type="file")
        }
        assert double_free.is_unsafe_double_free(state)
    
    def test_resource_freed_three_times(self):
        """Predicate returns True when resource freed multiple times."""
        state = MockState()
        state.resource_states = {
            "socket_456": MockResourceLifecycle(free_count=3, resource_type="socket")
        }
        assert double_free.is_unsafe_double_free(state)
    
    def test_value_error_closed_file(self):
        """Predicate returns True for ValueError on closed file operation."""
        state = MockState()
        state.exception = "ValueError"
        state.exception_message = "I/O operation on closed file"
        assert double_free.is_unsafe_double_free(state)
    
    def test_value_error_closed_socket(self):
        """Predicate returns True for ValueError on closed socket."""
        state = MockState()
        state.exception = "ValueError"
        state.exception_message = "operation on closed socket"
        assert double_free.is_unsafe_double_free(state)
    
    def test_runtime_error_release_unlocked_lock(self):
        """Predicate returns True for RuntimeError on double-release of lock."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "release unlocked lock"
        assert double_free.is_unsafe_double_free(state)
    
    def test_runtime_error_already_released(self):
        """Predicate returns True for RuntimeError indicating already released."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "cannot release already released semaphore"
        assert double_free.is_unsafe_double_free(state)
    
    def test_system_error_double_free(self):
        """Predicate returns True for SystemError from native double-free."""
        state = MockState()
        state.exception = "SystemError"
        state.exception_message = "double free detected in native extension"
        assert double_free.is_unsafe_double_free(state)
    
    def test_safe_state_no_double_free(self):
        """Predicate returns False for safe state."""
        state = MockState()
        assert not double_free.is_unsafe_double_free(state)
    
    def test_resource_freed_once_not_bug(self):
        """Predicate returns False when resource freed only once."""
        state = MockState()
        state.resource_states = {
            "file_handle_789": MockResourceLifecycle(free_count=1, resource_type="file")
        }
        assert not double_free.is_unsafe_double_free(state)
    
    def test_unrelated_value_error(self):
        """Predicate returns False for unrelated ValueError."""
        state = MockState()
        state.exception = "ValueError"
        state.exception_message = "invalid literal for int()"
        assert not double_free.is_unsafe_double_free(state)
    
    def test_unrelated_runtime_error(self):
        """Predicate returns False for unrelated RuntimeError."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "maximum recursion depth exceeded"
        assert not double_free.is_unsafe_double_free(state)


class TestDoubleFreeCounterexampleExtraction:
    """Test counterexample extraction for DOUBLE_FREE."""
    
    def test_extract_with_flag(self):
        """Extract counterexample when double_free_reached flag is set."""
        state = MockState()
        state.double_free_reached = True
        state.double_freed_resource_id = "file_handle_42"
        state.resource_free_count = 2
        state.double_freed_resource_type = "file"
        
        trace = ["LOAD_CONST", "CALL", "CALL"]  # Open, close, close
        result = double_free.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DOUBLE_FREE"
        assert result["trace"] == trace
        assert result["final_state"]["double_free_reached"] == True
        assert result["final_state"]["resource_id"] == "file_handle_42"
        assert result["final_state"]["free_count"] == 2
        assert result["final_state"]["resource_type"] == "file"
    
    def test_extract_from_resource_states(self):
        """Extract counterexample from resource_states tracking."""
        state = MockState()
        state.resource_states = {
            "lock_999": MockResourceLifecycle(free_count=2, resource_type="lock")
        }
        
        trace = ["LOAD_GLOBAL", "CALL", "CALL"]
        result = double_free.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DOUBLE_FREE"
        assert result["final_state"]["resource_id"] == "lock_999"
        assert result["final_state"]["free_count"] == 2
        assert result["final_state"]["resource_type"] == "lock"
    
    def test_extract_from_exception(self):
        """Extract counterexample from exception information."""
        state = MockState()
        state.exception = "ValueError"
        state.exception_message = "I/O operation on closed file"
        state.frame_stack = [1, 2, 3]
        
        trace = ["LOAD_NAME", "LOAD_ATTR", "CALL"]
        result = double_free.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DOUBLE_FREE"
        assert result["final_state"]["exception"] == "ValueError"
        assert "closed file" in result["final_state"]["exception_message"]
        assert result["final_state"]["resource_type"] == "file_or_socket"
        assert result["final_state"]["frame_count"] == 3
    
    def test_extract_lock_double_release(self):
        """Extract counterexample for lock double-release."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "release unlocked lock"
        
        trace = ["LOAD_GLOBAL", "LOAD_ATTR", "CALL", "LOAD_ATTR", "CALL"]
        result = double_free.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DOUBLE_FREE"
        assert result["final_state"]["resource_type"] == "lock_or_semaphore"


class TestDoubleFreeIntegration:
    """Integration tests using symbolic VM (if double-free tracking is implemented)."""
    
    @pytest.mark.xfail(reason="Requires explicit resource lifecycle tracking in symbolic VM - not yet implemented")
    def test_double_close_file_bug(self):
        """BUG: Closing the same file twice."""
        code = compile("""
f = open('test.txt', 'w')
f.close()
f.close()  # DOUBLE_FREE
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DOUBLE_FREE']
        
        assert len(bugs) > 0, "Should detect DOUBLE_FREE"
        assert bugs[0]["final_state"]["resource_type"] in ["file", "file_or_socket"]
    
    @pytest.mark.xfail(reason="Requires lock tracking - not yet implemented")
    def test_double_release_lock_bug(self):
        """BUG: Releasing the same lock twice."""
        code = compile("""
import threading
lock = threading.Lock()
lock.acquire()
lock.release()
lock.release()  # DOUBLE_FREE / RuntimeError
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DOUBLE_FREE']
        
        assert len(bugs) > 0, "Should detect DOUBLE_FREE"
    
    @pytest.mark.xfail(reason="Requires resource lifecycle tracking - not yet implemented")
    def test_conditional_double_close_bug(self):
        """BUG: Conditional path leading to double close."""
        code = compile("""
def cleanup(twice):
    f = open('data.txt', 'r')
    f.close()
    if twice:
        f.close()  # DOUBLE_FREE on this path

cleanup(True)
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=400)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DOUBLE_FREE']
        
        # Should detect at least on the twice=True path
        assert len(bugs) > 0, "Should detect DOUBLE_FREE on double-close path"


class TestDoubleFreeNonBugs:
    """Test cases where DOUBLE_FREE is NOT reachable (NON-BUG)."""
    
    def test_single_close_not_bug(self):
        """NON-BUG: Closing file once is safe."""
        state = MockState()
        state.resource_states = {
            "file_handle_100": MockResourceLifecycle(free_count=1, resource_type="file")
        }
        assert not double_free.is_unsafe_double_free(state)
    
    def test_no_close_not_bug(self):
        """NON-BUG: Not closing file at all is not double-free (may be leak)."""
        state = MockState()
        state.resource_states = {
            "file_handle_200": MockResourceLifecycle(free_count=0, resource_type="file")
        }
        assert not double_free.is_unsafe_double_free(state)
    
    @pytest.mark.xfail(reason="Requires resource tracking - not yet implemented")
    def test_context_manager_single_close_not_bug(self):
        """NON-BUG: Context manager closes file once automatically."""
        code = compile("""
with open('test.txt', 'w') as f:
    f.write('data')
# File closed automatically, no double-free
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        double_free_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DOUBLE_FREE']
        
        assert len(double_free_bugs) == 0, "Should not detect DOUBLE_FREE"
    
    @pytest.mark.xfail(reason="Requires lock tracking - not yet implemented")
    def test_lock_acquire_release_once_not_bug(self):
        """NON-BUG: Acquire and release lock once is safe."""
        code = compile("""
import threading
lock = threading.Lock()
lock.acquire()
lock.release()
# No second release
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=200)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        double_free_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DOUBLE_FREE']
        
        assert len(double_free_bugs) == 0, "Should not detect DOUBLE_FREE"
    
    @pytest.mark.xfail(reason="Requires resource tracking - not yet implemented")
    def test_different_files_closed_not_bug(self):
        """NON-BUG: Closing two different files is safe."""
        code = compile("""
f1 = open('file1.txt', 'w')
f2 = open('file2.txt', 'w')
f1.close()
f2.close()
# Each file closed once
""", "<test>", "exec")
        vm = SymbolicVM()
        paths = vm.explore_bounded(code, max_steps=300)
        
        bugs = [check_unsafe_regions(p.state, p.trace) for p in paths]
        double_free_bugs = [b for b in bugs if b is not None and b['bug_type'] == 'DOUBLE_FREE']
        
        assert len(double_free_bugs) == 0, "Should not detect DOUBLE_FREE"
    
    def test_unrelated_exception_not_double_free(self):
        """NON-BUG: Other exceptions are not double-free."""
        state = MockState()
        state.exception = "TypeError"
        state.exception_message = "unsupported operand type(s)"
        assert not double_free.is_unsafe_double_free(state)
    
    def test_normal_execution_not_double_free(self):
        """NON-BUG: Normal execution without resource operations."""
        state = MockState()
        state.frame_stack = [1]
        state.halted = False
        assert not double_free.is_unsafe_double_free(state)


class TestDoubleFreeSemantics:
    """Tests validating the semantic model of DOUBLE_FREE."""
    
    def test_double_free_is_distinct_from_use_after_free(self):
        """DOUBLE_FREE (freeing twice) is semantically distinct from USE_AFTER_FREE (using after free)."""
        # DOUBLE_FREE: second close call
        double_free_state = MockState()
        double_free_state.double_free_reached = True
        
        # USE_AFTER_FREE: using closed resource
        use_after_free_state = MockState()
        use_after_free_state.use_after_free_reached = True
        
        assert double_free.is_unsafe_double_free(double_free_state)
        # Use after free is a different bug class
        assert not double_free.is_unsafe_double_free(use_after_free_state)
    
    def test_double_free_tracks_free_count(self):
        """DOUBLE_FREE detection should track exact number of frees."""
        state = MockState()
        
        # 0 frees: not a bug
        state.resource_states = {"res1": MockResourceLifecycle(free_count=0)}
        assert not double_free.is_unsafe_double_free(state)
        
        # 1 free: not a bug
        state.resource_states = {"res2": MockResourceLifecycle(free_count=1)}
        assert not double_free.is_unsafe_double_free(state)
        
        # 2 frees: bug
        state.resource_states = {"res3": MockResourceLifecycle(free_count=2)}
        assert double_free.is_unsafe_double_free(state)
        
        # 3+ frees: also a bug
        state.resource_states = {"res4": MockResourceLifecycle(free_count=5)}
        assert double_free.is_unsafe_double_free(state)
    
    def test_multiple_resources_independent(self):
        """Each resource is tracked independently for double-free."""
        state = MockState()
        state.resource_states = {
            "res_a": MockResourceLifecycle(free_count=1),  # OK
            "res_b": MockResourceLifecycle(free_count=2),  # DOUBLE_FREE
            "res_c": MockResourceLifecycle(free_count=1),  # OK
        }
        
        # Should detect double-free because res_b has free_count=2
        assert double_free.is_unsafe_double_free(state)
