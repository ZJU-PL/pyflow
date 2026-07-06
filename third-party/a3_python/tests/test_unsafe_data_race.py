"""
Tests for DATA_RACE unsafe region.

DATA_RACE occurs when multiple threads access shared state concurrently,
with at least one write, without proper synchronization:
- Multiple threads writing to shared dict/list without locks
- Check-then-act (TOCTOU) patterns on shared state
- Concurrent access during GIL-release operations
- Dictionary/set size change during iteration from another thread

These tests validate the semantic model's ability to detect data races
using lockset algorithm (Eraser) and happens-before analysis.
"""

import pytest
from a3_python.unsafe import data_race
from a3_python.unsafe.registry import check_unsafe_regions


class MockState:
    """Mock state for unit testing predicates."""
    def __init__(self):
        self.exception = None
        self.exception_message = ""
        self.halted = False
        self.frame_stack = []
        self.data_race_reached = False
        self.heap_access_log = []
        self.toctou_race_detected = False
        self.thread_safety_violation = False


class TestDataRacePredicateUnit:
    """Unit tests for is_unsafe_data_race predicate."""
    
    def test_data_race_flag_set(self):
        """Predicate returns True when data_race_reached flag is set."""
        state = MockState()
        state.data_race_reached = True
        assert data_race.is_unsafe_data_race(state)
    
    def test_lockset_violation_two_threads_write(self):
        """Predicate returns True when two threads write with no common lock."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'global_var_x',
                'thread_id': 1,
                'is_write': True,
                'lockset': [],  # No locks held
                'timestamp': 100,
                'instruction': 'STORE_GLOBAL'
            },
            {
                'location': 'global_var_x',
                'thread_id': 2,
                'is_write': True,
                'lockset': [],  # No locks held
                'timestamp': 101,
                'instruction': 'STORE_GLOBAL'
            }
        ]
        assert data_race.is_unsafe_data_race(state)
    
    def test_lockset_violation_read_write_no_lock(self):
        """Predicate returns True for concurrent read-write without lock."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'shared_list',
                'thread_id': 1,
                'is_write': False,
                'lockset': [],
                'timestamp': 100,
                'instruction': 'LOAD_GLOBAL'
            },
            {
                'location': 'shared_list',
                'thread_id': 2,
                'is_write': True,
                'lockset': [],
                'timestamp': 102,
                'instruction': 'LIST_APPEND'
            }
        ]
        assert data_race.is_unsafe_data_race(state)
    
    def test_no_race_with_common_lock(self):
        """Predicate returns False when all accesses hold same lock."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'counter',
                'thread_id': 1,
                'is_write': True,
                'lockset': ['lock_A'],
                'timestamp': 100,
                'instruction': 'BINARY_OP'
            },
            {
                'location': 'counter',
                'thread_id': 2,
                'is_write': True,
                'lockset': ['lock_A'],
                'timestamp': 105,
                'instruction': 'BINARY_OP'
            }
        ]
        assert not data_race.is_unsafe_data_race(state)
    
    def test_no_race_single_thread(self):
        """Predicate returns False for single-threaded access."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'local_var',
                'thread_id': 1,
                'is_write': True,
                'lockset': [],
                'timestamp': 100,
                'instruction': 'STORE_FAST'
            }
        ]
        assert not data_race.is_unsafe_data_race(state)
    
    def test_no_race_only_reads(self):
        """Predicate returns False when all accesses are reads."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'constant',
                'thread_id': 1,
                'is_write': False,
                'lockset': [],
                'timestamp': 100,
                'instruction': 'LOAD_CONST'
            },
            {
                'location': 'constant',
                'thread_id': 2,
                'is_write': False,
                'lockset': [],
                'timestamp': 101,
                'instruction': 'LOAD_CONST'
            }
        ]
        assert not data_race.is_unsafe_data_race(state)
    
    def test_lockset_intersection_empty(self):
        """Predicate returns True when lockset intersection becomes empty."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'shared_resource',
                'thread_id': 1,
                'is_write': True,
                'lockset': ['lock_A'],
                'timestamp': 100,
                'instruction': 'STORE_ATTR'
            },
            {
                'location': 'shared_resource',
                'thread_id': 2,
                'is_write': True,
                'lockset': ['lock_B'],  # Different lock
                'timestamp': 101,
                'instruction': 'STORE_ATTR'
            }
        ]
        assert data_race.is_unsafe_data_race(state)
    
    def test_runtime_error_dict_changed_size(self):
        """Predicate returns True for RuntimeError: dict changed size."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "dictionary changed size during iteration"
        assert data_race.is_unsafe_data_race(state)
    
    def test_runtime_error_set_changed_size(self):
        """Predicate returns True for RuntimeError: set changed size."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "set changed size during iteration"
        assert data_race.is_unsafe_data_race(state)
    
    def test_toctou_race_detected(self):
        """Predicate returns True when TOCTOU race flag is set."""
        state = MockState()
        state.toctou_race_detected = True
        assert data_race.is_unsafe_data_race(state)
    
    def test_thread_safety_violation(self):
        """Predicate returns True when thread safety violation detected."""
        state = MockState()
        state.thread_safety_violation = True
        assert data_race.is_unsafe_data_race(state)


class TestDataRaceCounterexampleExtraction:
    """Tests for extract_counterexample function."""
    
    def test_extract_basic_race(self):
        """Extract counterexample for basic data race."""
        state = MockState()
        state.data_race_reached = True
        state.racing_threads = [1, 2]
        state.racing_location = "global_counter"
        state.race_type = "lockset_violation"
        
        trace = ["LOAD_GLOBAL", "BINARY_OP", "STORE_GLOBAL"]
        result = data_race.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DATA_RACE"
        assert result["trace"] == trace
        assert result["final_state"]["racing_threads"] == [1, 2]
        assert result["final_state"]["racing_location"] == "global_counter"
        assert result["final_state"]["race_type"] == "lockset_violation"
    
    def test_extract_from_heap_log(self):
        """Extract race details from heap access log."""
        state = MockState()
        state.heap_access_log = [
            {
                'location': 'shared_dict',
                'thread_id': 1,
                'is_write': False,
                'lockset': [],
                'timestamp': 100,
                'instruction': 'LOAD_GLOBAL'
            },
            {
                'location': 'shared_dict',
                'thread_id': 2,
                'is_write': True,
                'lockset': [],
                'timestamp': 102,
                'instruction': 'DICT_UPDATE'
            }
        ]
        
        trace = ["LOAD_GLOBAL", "DICT_UPDATE"]
        result = data_race.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DATA_RACE"
        assert result["final_state"]["racing_location"] == "shared_dict"
        assert sorted(result["final_state"]["racing_threads"]) == [1, 2]
        assert len(result["final_state"]["access_pattern"]) == 2
        
        # Check access pattern details
        pattern = result["final_state"]["access_pattern"]
        assert any(p['operation'] == 'read' and p['thread'] == 1 for p in pattern)
        assert any(p['operation'] == 'write' and p['thread'] == 2 for p in pattern)
    
    def test_extract_concurrent_mutation_exception(self):
        """Extract details from concurrent mutation exception."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "dictionary changed size during iteration"
        
        trace = ["GET_ITER", "FOR_ITER", "DICT_UPDATE"]
        result = data_race.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DATA_RACE"
        assert result["final_state"]["exception"] == "RuntimeError"
        assert "dictionary changed size" in result["final_state"]["exception_message"]
        assert result["final_state"]["race_type"] == "concurrent_mutation_during_iteration"
    
    def test_extract_toctou_race(self):
        """Extract TOCTOU race details."""
        state = MockState()
        state.toctou_race_detected = True
        state.toctou_location = "file_existence_check"
        
        trace = ["CHECK_FILE", "OPEN_FILE"]
        result = data_race.extract_counterexample(state, trace)
        
        assert result["bug_type"] == "DATA_RACE"
        assert result["final_state"]["race_type"] == "TOCTOU"
        assert result["final_state"]["racing_location"] == "file_existence_check"


class TestDataRaceSemanticScenarios:
    """Semantic tests for various DATA_RACE scenarios."""
    
    def test_compound_operation_race(self):
        """Test race in compound operation (x += 1)."""
        state = MockState()
        # x += 1 decomposes to: LOAD x, ADD 1, STORE x
        # Two threads doing this can interleave
        state.heap_access_log = [
            {'location': 'x', 'thread_id': 1, 'is_write': False, 
             'lockset': [], 'timestamp': 100, 'instruction': 'LOAD_GLOBAL'},
            {'location': 'x', 'thread_id': 2, 'is_write': False, 
             'lockset': [], 'timestamp': 101, 'instruction': 'LOAD_GLOBAL'},
            {'location': 'x', 'thread_id': 1, 'is_write': True, 
             'lockset': [], 'timestamp': 102, 'instruction': 'STORE_GLOBAL'},
            {'location': 'x', 'thread_id': 2, 'is_write': True, 
             'lockset': [], 'timestamp': 103, 'instruction': 'STORE_GLOBAL'},
        ]
        assert data_race.is_unsafe_data_race(state)
    
    def test_list_append_race(self):
        """Test race on list.append from multiple threads."""
        state = MockState()
        state.heap_access_log = [
            {'location': 'shared_list', 'thread_id': 1, 'is_write': True,
             'lockset': [], 'timestamp': 100, 'instruction': 'LIST_APPEND'},
            {'location': 'shared_list', 'thread_id': 2, 'is_write': True,
             'lockset': [], 'timestamp': 101, 'instruction': 'LIST_APPEND'},
        ]
        assert data_race.is_unsafe_data_race(state)
    
    def test_dict_update_race(self):
        """Test race on dict update from multiple threads."""
        state = MockState()
        state.heap_access_log = [
            {'location': 'config_dict', 'thread_id': 1, 'is_write': True,
             'lockset': [], 'timestamp': 100, 'instruction': 'STORE_SUBSCR'},
            {'location': 'config_dict', 'thread_id': 2, 'is_write': True,
             'lockset': [], 'timestamp': 101, 'instruction': 'STORE_SUBSCR'},
        ]
        assert data_race.is_unsafe_data_race(state)
    
    def test_protected_with_lock(self):
        """Test that lock protection prevents race detection."""
        state = MockState()
        state.heap_access_log = [
            {'location': 'balance', 'thread_id': 1, 'is_write': True,
             'lockset': ['account_lock'], 'timestamp': 100, 'instruction': 'STORE_ATTR'},
            {'location': 'balance', 'thread_id': 2, 'is_write': True,
             'lockset': ['account_lock'], 'timestamp': 105, 'instruction': 'STORE_ATTR'},
        ]
        assert not data_race.is_unsafe_data_race(state)
    
    def test_multiple_locks_sufficient(self):
        """Test that any common lock is sufficient."""
        state = MockState()
        state.heap_access_log = [
            {'location': 'data', 'thread_id': 1, 'is_write': True,
             'lockset': ['lock_A', 'lock_B'], 'timestamp': 100, 'instruction': 'STORE'},
            {'location': 'data', 'thread_id': 2, 'is_write': True,
             'lockset': ['lock_B', 'lock_C'], 'timestamp': 101, 'instruction': 'STORE'},
        ]
        # Common lockset = {'lock_B'}, non-empty, so no race
        assert not data_race.is_unsafe_data_race(state)
    
    def test_three_threads_race(self):
        """Test race detection with three threads."""
        state = MockState()
        state.heap_access_log = [
            {'location': 'global', 'thread_id': 1, 'is_write': True,
             'lockset': [], 'timestamp': 100, 'instruction': 'STORE'},
            {'location': 'global', 'thread_id': 2, 'is_write': False,
             'lockset': [], 'timestamp': 101, 'instruction': 'LOAD'},
            {'location': 'global', 'thread_id': 3, 'is_write': True,
             'lockset': [], 'timestamp': 102, 'instruction': 'STORE'},
        ]
        assert data_race.is_unsafe_data_race(state)


# Integration tests marked for when full symbolic VM threading support exists
@pytest.mark.xfail(reason="Awaiting symbolic VM thread scheduling implementation")
class TestDataRaceIntegration:
    """Integration tests requiring full threading semantics."""
    
    def test_concurrent_dict_iteration_modification(self):
        """Test race when iterating dict while another thread modifies it."""
        code = """
import threading

shared_dict = {'a': 1, 'b': 2}

def modifier():
    shared_dict['c'] = 3

def iterator():
    for k in shared_dict:
        pass

t1 = threading.Thread(target=iterator)
t2 = threading.Thread(target=modifier)
t1.start()
t2.start()
t1.join()
t2.join()
"""
        # This should be detected as DATA_RACE when VM supports threading
        # Expected: RuntimeError: dictionary changed size during iteration
        pass
    
    def test_gil_release_race(self):
        """Test race during GIL-release operations."""
        code = """
import threading
import time

counter = 0

def increment():
    global counter
    for _ in range(1000):
        counter += 1
        time.sleep(0)  # GIL release point

t1 = threading.Thread(target=increment)
t2 = threading.Thread(target=increment)
t1.start()
t2.start()
t1.join()
t2.join()
# Expected: counter != 2000 (lost updates due to race)
"""
        # This should be detected as DATA_RACE
        pass
    
    def test_check_then_act_toctou(self):
        """Test time-of-check-time-of-use race."""
        code = """
import threading

class BankAccount:
    def __init__(self):
        self.balance = 100
    
    def withdraw(self, amount):
        if self.balance >= amount:  # CHECK
            # Race window here
            self.balance -= amount  # ACT

account = BankAccount()

def withdraw_50():
    account.withdraw(50)

t1 = threading.Thread(target=withdraw_50)
t2 = threading.Thread(target=withdraw_50)
t1.start()
t2.start()
t1.join()
t2.join()
# Expected: balance may be negative (race in check-then-act)
"""
        # This should be detected as TOCTOU DATA_RACE
        pass


class TestHappensBeforeAnalysis:
    """Tests for happens-before ordering analysis."""
    
    def test_happens_before_same_thread(self):
        """Test happens-before in same thread by timestamp."""
        state = MockState()
        access1 = {'thread_id': 1, 'timestamp': 100}
        access2 = {'thread_id': 1, 'timestamp': 200}
        
        assert data_race._happens_before(access1, access2, state)
        assert not data_race._happens_before(access2, access1, state)
    
    def test_happens_before_different_threads_no_sync(self):
        """Test no happens-before between threads without synchronization."""
        state = MockState()
        access1 = {'thread_id': 1, 'timestamp': 100}
        access2 = {'thread_id': 2, 'timestamp': 200}
        
        assert not data_race._happens_before(access1, access2, state)
        assert not data_race._happens_before(access2, access1, state)
    
    def test_happens_before_with_sync_edge(self):
        """Test happens-before via synchronization edge."""
        state = MockState()
        state.happens_before_edges = {
            ((1, 100), (2, 200))  # Thread 1 at time 100 happens-before thread 2 at time 200
        }
        access1 = {'thread_id': 1, 'timestamp': 100}
        access2 = {'thread_id': 2, 'timestamp': 200}
        
        assert data_race._happens_before(access1, access2, state)
        assert not data_race._happens_before(access2, access1, state)
