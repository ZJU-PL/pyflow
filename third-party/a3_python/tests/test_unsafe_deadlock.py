"""
Tests for DEADLOCK unsafe region.

DEADLOCK occurs when threads are in circular wait on synchronization primitives:
- Lock ordering violations (A->B vs B->A)
- Resource allocation graph cycles
- Thread.join() circular dependencies
- All threads blocked with circular wait

These tests validate the semantic model's ability to detect deadlocks
using RAG cycle detection, lock ordering analysis, and happens-before violations.
"""

import pytest
from a3_python.unsafe import deadlock
from a3_python.unsafe.registry import check_unsafe_regions


class MockState:
    """Mock state for unit testing predicates."""
    def __init__(self):
        self.exception = None
        self.exception_message = ""
        self.halted = False
        self.frame_stack = []
        self.deadlock_reached = False
        self.lock_wait_graph = None
        self.lock_acquisition_orders = []
        self.threads = {}
        self.lock_holders = {}
        self.thread_join_graph = {}
        self.lock_acquire_timeout = False
        self.lock_holder = None
        self.current_thread = None
        self.lock_wait_chain = []
        self.path_condition = None


class TestDeadlockPredicateUnit:
    """Unit tests for is_unsafe_deadlock predicate."""
    
    def test_deadlock_flag_set(self):
        """Predicate returns True when deadlock_reached flag is set."""
        state = MockState()
        state.deadlock_reached = True
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_rag_cycle_simple_two_threads(self):
        """Predicate returns True for simple RAG cycle: T1->L1->T2->L2->T1."""
        state = MockState()
        state.lock_wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L1', 'holding': ['L2']},
                'T2': {'waiting_on': 'L2', 'holding': ['L1']}
            },
            'locks': {
                'L1': {'held_by': 'T2', 'waiters': ['T1']},
                'L2': {'held_by': 'T1', 'waiters': ['T2']}
            }
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_rag_cycle_three_threads(self):
        """Predicate returns True for RAG cycle with three threads."""
        state = MockState()
        state.lock_wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L1', 'holding': ['L3']},
                'T2': {'waiting_on': 'L2', 'holding': ['L1']},
                'T3': {'waiting_on': 'L3', 'holding': ['L2']}
            },
            'locks': {
                'L1': {'held_by': 'T2', 'waiters': ['T1']},
                'L2': {'held_by': 'T3', 'waiters': ['T2']},
                'L3': {'held_by': 'T1', 'waiters': ['T3']}
            }
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_no_deadlock_no_cycle(self):
        """Predicate returns False when threads wait in chain (no cycle)."""
        state = MockState()
        state.lock_wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L1', 'holding': []},
                'T2': {'waiting_on': None, 'holding': ['L1']}
            },
            'locks': {
                'L1': {'held_by': 'T2', 'waiters': ['T1']}
            }
        }
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_lock_ordering_violation_ab_ba(self):
        """Predicate returns True for classic lock ordering violation (A->B vs B->A)."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['lockA', 'lockB']),  # T1 acquires A then B
            ('T2', ['lockB', 'lockA'])   # T2 acquires B then A => violation!
        ]
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_lock_ordering_violation_complex(self):
        """Predicate returns True for complex lock ordering violation."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['L1', 'L2', 'L3']),
            ('T2', ['L3', 'L1']),  # L3 before L1 (conflicts with T1's L1 before L3)
            ('T3', ['L2', 'L3'])
        ]
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_no_lock_ordering_violation_consistent(self):
        """Predicate returns False when all threads use consistent lock order."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['lockA', 'lockB', 'lockC']),
            ('T2', ['lockA', 'lockB']),
            ('T3', ['lockB', 'lockC'])
        ]
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_all_threads_blocked_circular(self):
        """Predicate returns True when all threads blocked in circular wait."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'waiting', 'waiting_on': 'L2'},
            'T3': {'state': 'waiting', 'waiting_on': 'L3'}
        }
        state.lock_holders = {
            'L1': 'T2',  # T1 waits for L1 held by T2
            'L2': 'T3',  # T2 waits for L2 held by T3
            'L3': 'T1'   # T3 waits for L3 held by T1 => cycle!
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_not_all_threads_blocked(self):
        """Predicate returns False when at least one thread is runnable."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'running', 'waiting_on': None}
        }
        state.lock_holders = {'L1': 'T2'}
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_thread_join_circular_dependency(self):
        """Predicate returns True for circular thread join (T1.join(T2), T2.join(T1))."""
        state = MockState()
        state.thread_join_graph = {
            'T1': ['T2'],  # T1 waiting to join T2
            'T2': ['T1']   # T2 waiting to join T1 => deadlock!
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_thread_join_three_way_cycle(self):
        """Predicate returns True for three-way join cycle."""
        state = MockState()
        state.thread_join_graph = {
            'T1': ['T2'],
            'T2': ['T3'],
            'T3': ['T1']
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_thread_join_no_cycle(self):
        """Predicate returns False for linear thread join (no cycle)."""
        state = MockState()
        state.thread_join_graph = {
            'T1': ['T2'],
            'T2': ['T3'],
            'T3': []
        }
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_lock_acquire_timeout_with_circular_wait(self):
        """Predicate returns True when lock timeout indicates deadlock."""
        state = MockState()
        state.lock_acquire_timeout = True
        state.current_thread = 'T1'
        state.lock_holder = 'T2'
        state.lock_wait_chain = ['T2', 'lock_X', 'T1', 'lock_Y']  # T2 waits on T1
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_deadlock_exception(self):
        """Predicate returns True for explicit deadlock exception."""
        state = MockState()
        state.exception = "DeadlockError"
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_runtime_error_deadlock_message(self):
        """Predicate returns True for RuntimeError with deadlock message."""
        state = MockState()
        state.exception = "RuntimeError"
        state.exception_message = "Deadlock detected: circular dependency"
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_no_deadlock_clean_state(self):
        """Predicate returns False for clean state with no deadlock indicators."""
        state = MockState()
        assert not deadlock.is_unsafe_deadlock(state)


class TestDeadlockHelpers:
    """Test helper functions for deadlock detection."""
    
    def test_has_cycle_in_rag_simple(self):
        """Test RAG cycle detection for simple case."""
        wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L1', 'holding': ['L2']},
                'T2': {'waiting_on': 'L2', 'holding': ['L1']}
            },
            'locks': {
                'L1': {'held_by': 'T2', 'waiters': ['T1']},
                'L2': {'held_by': 'T1', 'waiters': ['T2']}
            }
        }
        assert deadlock._has_cycle_in_rag(wait_graph)
    
    def test_has_cycle_in_rag_no_cycle(self):
        """Test RAG cycle detection returns False for no cycle."""
        wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L1', 'holding': []},
                'T2': {'waiting_on': None, 'holding': ['L1']}
            },
            'locks': {
                'L1': {'held_by': 'T2', 'waiters': ['T1']}
            }
        }
        assert not deadlock._has_cycle_in_rag(wait_graph)
    
    def test_detect_lock_ordering_violation(self):
        """Test lock ordering violation detection."""
        orders = [
            ('T1', ['A', 'B']),
            ('T2', ['B', 'A'])
        ]
        assert deadlock._detect_lock_ordering_violation(orders)
    
    def test_no_lock_ordering_violation(self):
        """Test no violation when orders are consistent."""
        orders = [
            ('T1', ['A', 'B', 'C']),
            ('T2', ['A', 'C']),
            ('T3', ['B', 'C'])
        ]
        assert not deadlock._detect_lock_ordering_violation(orders)
    
    def test_all_threads_blocked_with_cycle(self):
        """Test all-threads-blocked detection with circular wait."""
        threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'waiting', 'waiting_on': 'L2'}
        }
        lock_holders = {
            'L1': 'T2',
            'L2': 'T1'
        }
        assert deadlock._all_threads_blocked(threads, lock_holders)
    
    def test_not_all_threads_blocked(self):
        """Test returns False when a thread is runnable."""
        threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'running', 'waiting_on': None}
        }
        lock_holders = {'L1': 'T2'}
        assert not deadlock._all_threads_blocked(threads, lock_holders)
    
    def test_has_cycle_in_thread_graph(self):
        """Test thread join graph cycle detection."""
        join_graph = {
            'T1': ['T2'],
            'T2': ['T3'],
            'T3': ['T1']
        }
        assert deadlock._has_cycle_in_thread_graph(join_graph)
    
    def test_no_cycle_in_thread_graph(self):
        """Test no cycle in thread join graph."""
        join_graph = {
            'T1': ['T2'],
            'T2': ['T3']
        }
        assert not deadlock._has_cycle_in_thread_graph(join_graph)


class TestDeadlockCounterexample:
    """Test counterexample extraction for deadlock."""
    
    def test_extract_counterexample_rag_cycle(self):
        """Test counterexample extraction for RAG cycle."""
        state = MockState()
        state.lock_wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L1', 'holding': ['L2']},
                'T2': {'waiting_on': 'L2', 'holding': ['L1']}
            },
            'locks': {
                'L1': {'held_by': 'T2', 'waiters': ['T1']},
                'L2': {'held_by': 'T1', 'waiters': ['T2']}
            }
        }
        
        trace = ['LOAD_FAST', 'CALL (acquire)', 'LOAD_FAST', 'CALL (acquire)']
        result = deadlock.extract_counterexample(state, trace)
        
        assert result['bug_type'] == 'DEADLOCK'
        assert result['trace'] == trace
        assert len(result['threads_involved']) >= 1
        assert len(result['lock_cycle']) >= 2
        assert result['deadlock_type'] == 'resource_allocation_graph_cycle'
    
    def test_extract_counterexample_lock_ordering(self):
        """Test counterexample extraction for lock ordering violation."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['lockA', 'lockB']),
            ('T2', ['lockB', 'lockA'])
        ]
        
        trace = ['thread1_acquire_A', 'thread1_acquire_B', 'thread2_acquire_B', 'thread2_acquire_A']
        result = deadlock.extract_counterexample(state, trace)
        
        assert result['bug_type'] == 'DEADLOCK'
        assert len(result['lock_ordering_violations']) > 0
        violation = result['lock_ordering_violations'][0]
        assert set(violation['locks']) == {'lockA', 'lockB'}
    
    def test_extract_counterexample_thread_join(self):
        """Test counterexample extraction for thread join deadlock."""
        state = MockState()
        state.thread_join_graph = {
            'T1': ['T2'],
            'T2': ['T1']
        }
        
        trace = ['T1.join(T2)', 'T2.join(T1)']
        result = deadlock.extract_counterexample(state, trace)
        
        assert result['bug_type'] == 'DEADLOCK'
        assert result['deadlock_type'] == 'thread_join_circular_dependency'
        assert set(result['threads_involved']) == {'T1', 'T2'}


class TestDeadlockIntegration:
    """Integration tests: realistic deadlock scenarios."""
    
    @pytest.mark.xfail(reason="Requires full symbolic VM with threading support")
    def test_classic_lock_ordering_deadlock(self):
        """
        Classic deadlock scenario:
        Thread 1: lock.acquire(A); lock.acquire(B)
        Thread 2: lock.acquire(B); lock.acquire(A)
        """
        # This would require full VM with threading
        # For now, we test the predicate directly
        pass
    
    @pytest.mark.xfail(reason="Requires full symbolic VM with threading support")
    def test_dining_philosophers_deadlock(self):
        """
        Dining philosophers: circular wait on fork (lock) resources.
        Each philosopher acquires left fork, then right fork.
        If all acquire left simultaneously, deadlock.
        """
        pass
    
    @pytest.mark.xfail(reason="Requires full symbolic VM with threading support")
    def test_nested_lock_different_orders(self):
        """
        Multiple functions with nested locks, acquired in different orders.
        """
        pass
    
    def test_no_deadlock_single_threaded(self):
        """No deadlock possible in single-threaded program."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'running', 'waiting_on': None}
        }
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_no_deadlock_locks_released_properly(self):
        """No deadlock when locks are acquired and released in LIFO order."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['A', 'B']),  # Acquire A, B; release B, A
            ('T2', ['A', 'B'])   # Same order => no violation
        ]
        assert not deadlock.is_unsafe_deadlock(state)


class TestDeadlockSynthetic:
    """Synthetic test cases (10 BUG + 10 NON-BUG)."""
    
    # === BUG cases (should detect deadlock) ===
    
    def test_bug_1_two_threads_two_locks_opposite_order(self):
        """BUG: Two threads, two locks, opposite acquisition order."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['lock1', 'lock2']),
            ('T2', ['lock2', 'lock1'])
        ]
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_2_rag_cycle_holds_and_waits(self):
        """BUG: RAG cycle - each thread holds a lock other needs."""
        state = MockState()
        state.lock_wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L2', 'holding': ['L1']},
                'T2': {'waiting_on': 'L1', 'holding': ['L2']}
            },
            'locks': {
                'L1': {'held_by': 'T1', 'waiters': ['T2']},
                'L2': {'held_by': 'T2', 'waiters': ['T1']}
            }
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_3_three_threads_circular_wait(self):
        """BUG: Three threads in circular wait chain."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'waiting', 'waiting_on': 'L2'},
            'T3': {'state': 'waiting', 'waiting_on': 'L3'}
        }
        state.lock_holders = {'L1': 'T2', 'L2': 'T3', 'L3': 'T1'}
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_4_thread_join_self_reference(self):
        """BUG: Thread tries to join itself (indirect via cycle)."""
        state = MockState()
        state.thread_join_graph = {'T1': ['T1']}  # T1.join(T1) - self deadlock
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_5_multiple_lock_ordering_violations(self):
        """BUG: Multiple conflicting lock orderings."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['A', 'B', 'C']),
            ('T2', ['C', 'B', 'A']),  # Completely reversed
            ('T3', ['B', 'A'])
        ]
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_6_complex_rag_four_nodes(self):
        """BUG: Complex RAG with 4 threads and 4 locks."""
        state = MockState()
        state.lock_wait_graph = {
            'threads': {
                'T1': {'waiting_on': 'L2', 'holding': ['L1']},
                'T2': {'waiting_on': 'L3', 'holding': ['L2']},
                'T3': {'waiting_on': 'L4', 'holding': ['L3']},
                'T4': {'waiting_on': 'L1', 'holding': ['L4']}
            },
            'locks': {
                'L1': {'held_by': 'T1', 'waiters': ['T4']},
                'L2': {'held_by': 'T2', 'waiters': ['T1']},
                'L3': {'held_by': 'T3', 'waiters': ['T2']},
                'L4': {'held_by': 'T4', 'waiters': ['T3']}
            }
        }
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_7_timeout_with_circular_dependency(self):
        """BUG: Lock acquire timeout exposing circular wait."""
        state = MockState()
        state.lock_acquire_timeout = True
        state.current_thread = 'T1'
        state.lock_holder = 'T2'
        state.lock_wait_chain = ['T2', 'L_X', 'T1', 'L_Y']
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_8_deadlock_exception_raised(self):
        """BUG: Explicit DeadlockError exception."""
        state = MockState()
        state.exception = "threading.DeadlockError"
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_9_all_threads_waiting_no_progress(self):
        """BUG: All threads in wait state, none can progress."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'waiting', 'waiting_on': 'L2'}
        }
        state.lock_holders = {'L1': 'T2', 'L2': 'T1'}
        assert deadlock.is_unsafe_deadlock(state)
    
    def test_bug_10_nested_locks_inconsistent_order(self):
        """BUG: Deeply nested locks acquired in inconsistent order."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['outer', 'middle', 'inner']),
            ('T2', ['inner', 'outer'])  # Acquires inner before outer => conflict
        ]
        assert deadlock.is_unsafe_deadlock(state)
    
    # === NON-BUG cases (should NOT detect deadlock) ===
    
    def test_non_bug_1_single_thread(self):
        """NON-BUG: Single thread cannot deadlock with itself (normal locks)."""
        state = MockState()
        state.threads = {'T1': {'state': 'running', 'waiting_on': None}}
        state.lock_acquisition_orders = [('T1', ['lock1', 'lock2', 'lock3'])]
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_2_consistent_lock_order(self):
        """NON-BUG: All threads acquire locks in same consistent order."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['A', 'B', 'C']),
            ('T2', ['A', 'B']),
            ('T3', ['B', 'C']),
            ('T4', ['A', 'C'])
        ]
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_3_no_circular_wait_chain(self):
        """NON-BUG: Threads wait in linear chain, not circular."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'waiting', 'waiting_on': 'L2'},
            'T3': {'state': 'running', 'waiting_on': None}
        }
        state.lock_holders = {'L1': 'T2', 'L2': 'T3'}
        # T1 waits for T2, T2 waits for T3, T3 runs => no cycle
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_4_locks_released_before_next_acquire(self):
        """NON-BUG: Locks released before acquiring next (no holding multiple)."""
        state = MockState()
        # Even though orders differ, if locks are released between acquires, no deadlock
        state.lock_acquisition_orders = [
            ('T1', ['A']),  # Acquire A, release A
            ('T1', ['B']),  # Then acquire B
            ('T2', ['B']),  # Acquire B, release B
            ('T2', ['A'])   # Then acquire A
        ]
        # No RAG cycle since not holding both simultaneously
        state.lock_wait_graph = {'threads': {}, 'locks': {}}
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_5_thread_joins_complete_successfully(self):
        """NON-BUG: Thread joins complete without circular dependency."""
        state = MockState()
        state.thread_join_graph = {
            'main': ['T1', 'T2', 'T3'],  # Main waits for workers
            'T1': [],
            'T2': [],
            'T3': []
        }
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_6_at_least_one_thread_runnable(self):
        """NON-BUG: At least one thread is runnable (can make progress)."""
        state = MockState()
        state.threads = {
            'T1': {'state': 'waiting', 'waiting_on': 'L1'},
            'T2': {'state': 'running', 'waiting_on': None}
        }
        state.lock_holders = {'L1': 'T2'}
        # T2 can release L1, allowing T1 to proceed
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_7_reentrant_lock_same_thread(self):
        """NON-BUG: Reentrant lock (RLock) acquired multiple times by same thread."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['reentrant', 'reentrant', 'reentrant'])  # Same lock, same thread
        ]
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_8_timeout_but_no_holder(self):
        """NON-BUG: Lock timeout but no other thread holds it (spurious timeout)."""
        state = MockState()
        state.lock_acquire_timeout = True
        state.lock_holder = None  # No one holds the lock
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_9_empty_wait_graph(self):
        """NON-BUG: No threads, no locks, no deadlock."""
        state = MockState()
        state.lock_wait_graph = {'threads': {}, 'locks': {}}
        assert not deadlock.is_unsafe_deadlock(state)
    
    def test_non_bug_10_locks_acquired_atomically_within_with_block(self):
        """NON-BUG: Locks acquired in with-statement, properly scoped."""
        state = MockState()
        state.lock_acquisition_orders = [
            ('T1', ['lock_A']),
            ('T2', ['lock_B'])  # Different locks, no contention
        ]
        assert not deadlock.is_unsafe_deadlock(state)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
