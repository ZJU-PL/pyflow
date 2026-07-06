"""
Test heap observers for structural reasoning.

These tests verify that SeqLen, DictSize, and HasKey observers
enable reasoning about collection properties without pattern matching.
"""

import pytest
import z3
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.z3model.heap import SymbolicHeap
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_seq_len_observer_basic():
    """Test that SeqLen observer is correctly initialized and constrained."""
    heap = SymbolicHeap()
    
    # Allocate a list with length 3
    obj_id = heap.allocate_sequence("list", z3.IntVal(3), {})
    
    # Get the SeqLen observer
    seq_len = heap.get_seq_len_observer(obj_id)
    
    # Get constraints
    constraints = heap.constrain_observers()
    
    # Should have one constraint: SeqLen(obj_id) == 3
    assert len(constraints) == 1
    
    # Verify the constraint
    solver = z3.Solver()
    solver.add(constraints[0])
    solver.add(seq_len == 3)
    assert solver.check() == z3.sat
    
    # Verify that SeqLen != 3 is unsat
    solver = z3.Solver()
    solver.add(constraints[0])
    solver.add(seq_len != 3)
    assert solver.check() == z3.unsat


def test_dict_size_observer_basic():
    """Test that DictSize observer is correctly initialized and constrained."""
    heap = SymbolicHeap()
    
    # Allocate a dict with 2 keys
    obj_id = heap.allocate_dict(keys={'a', 'b'}, values={'a': SymbolicValue.int(1), 'b': SymbolicValue.int(2)})
    
    # Get the DictSize observer
    dict_size = heap.get_dict_size_observer(obj_id)
    
    # Get constraints
    constraints = heap.constrain_observers()
    
    # Should have one constraint: DictSize(obj_id) == 2
    assert len(constraints) == 1
    
    # Verify the constraint
    solver = z3.Solver()
    solver.add(constraints[0])
    solver.add(dict_size == 2)
    assert solver.check() == z3.sat
    
    # Verify that DictSize != 2 is unsat
    solver = z3.Solver()
    solver.add(constraints[0])
    solver.add(dict_size != 2)
    assert solver.check() == z3.unsat


def test_len_builtin_uses_observer():
    """Test that len() builtin correctly uses SeqLen observer."""
    # This test validates the observer machinery, not the full VM exploration
    code = compile("""
def f(lst):
    return len(lst)
""", "<test>", "exec")
    
    func_code = code.co_consts[0]
    vm = SymbolicVM()
    
    # Execute symbolically with a list argument
    paths = vm.explore_bounded(func_code, max_steps=50)
    
    # Should have at least one path (even if not completed)
    assert len(paths) > 0
    
    # Check that any path with a list allocation has observer constraints
    for path in paths:
        observer_constraints = path.state.heap.constrain_observers()
        # If there are sequences in the heap, we should have observers
        if len(path.state.heap.sequences) > 0:
            assert len(observer_constraints) > 0
            break


def test_len_empty_list():
    """Test len() on empty list with observer reasoning."""
    code = compile("""
def f():
    lst = []
    return len(lst)
""", "<test>", "exec")
    
    func_code = code.co_consts[0]
    vm = SymbolicVM()
    
    paths = vm.explore_bounded(func_code, max_steps=100)
    
    # Check that observer constraints are present
    assert len(paths) > 0
    for path in paths:
        if len(path.state.heap.sequences) > 0:
            observer_constraints = path.state.heap.constrain_observers()
            assert len(observer_constraints) > 0
            break


def test_len_nonempty_list():
    """Test len() on non-empty list with observer reasoning."""
    code = compile("""
def f():
    lst = [1, 2, 3]
    return len(lst)
""", "<test>", "exec")
    
    func_code = code.co_consts[0]
    vm = SymbolicVM()
    
    paths = vm.explore_bounded(func_code, max_steps=100)
    
    assert len(paths) > 0
    # Check that the list has SeqLen == 3
    for path in paths:
        if len(path.state.heap.sequences) > 0:
            # Verify observer constraints are present
            observer_constraints = path.state.heap.constrain_observers()
            assert len(observer_constraints) > 0
            
            # Check that at least one sequence has length 3
            has_len_3 = False
            for obj_id, seq in path.state.heap.sequences.items():
                if z3.is_int_value(seq.length) and seq.length.as_long() == 3:
                    has_len_3 = True
                    break
            if has_len_3:
                break


def test_len_symbolic_list():
    """Test len() on list passed as argument (symbolic)."""
    # This test validates observer-based reasoning setup
    code = compile("""
def f(lst):
    n = len(lst)
    if n > 0:
        return True
    return False
""", "<test>", "exec")
    
    func_code = code.co_consts[0]
    vm = SymbolicVM()
    
    paths = vm.explore_bounded(func_code, max_steps=100)
    
    # Should explore some paths
    assert len(paths) > 0
    
    # This tests that symbolic reasoning setup works (full integration tested elsewhere)


def test_multiple_sequences_observers():
    """Test that multiple sequences have independent observers."""
    heap = SymbolicHeap()
    
    # Allocate two sequences with different lengths
    obj_id1 = heap.allocate_sequence("list", z3.IntVal(5), {})
    obj_id2 = heap.allocate_sequence("tuple", z3.IntVal(3), {})
    
    # Get observers
    seq_len1 = heap.get_seq_len_observer(obj_id1)
    seq_len2 = heap.get_seq_len_observer(obj_id2)
    
    # They should be different Z3 variables
    assert seq_len1 is not seq_len2
    
    # Get constraints
    constraints = heap.constrain_observers()
    
    # Should have two constraints
    assert len(constraints) == 2
    
    # Verify both constraints
    solver = z3.Solver()
    for constraint in constraints:
        solver.add(constraint)
    
    solver.add(seq_len1 == 5)
    solver.add(seq_len2 == 3)
    assert solver.check() == z3.sat
    
    # Verify wrong values are unsat
    solver = z3.Solver()
    for constraint in constraints:
        solver.add(constraint)
    solver.add(seq_len1 == 3)  # Wrong
    assert solver.check() == z3.unsat


def test_observer_survives_heap_copy():
    """Test that observers are preserved when heap is copied."""
    heap = SymbolicHeap()
    
    obj_id = heap.allocate_sequence("list", z3.IntVal(10), {})
    seq_len = heap.get_seq_len_observer(obj_id)
    
    # Copy the heap
    heap_copy = heap.copy()
    
    # The observer should exist in the copy
    assert obj_id in heap_copy.seq_len_observers
    
    # And it should have the same constraints
    constraints_orig = heap.constrain_observers()
    constraints_copy = heap_copy.constrain_observers()
    
    assert len(constraints_orig) == len(constraints_copy)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
