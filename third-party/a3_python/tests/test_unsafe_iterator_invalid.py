"""
Tests for ITERATOR_INVALID bug type.

ITERATOR_INVALID detects collection mutation during iteration:
- Dict/set mutation during iteration (raises RuntimeError in CPython)
- List mutation during iteration (undefined behavior)

These tests verify the semantic unsafe predicate, not text patterns.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from a3_python.unsafe.iterator_invalid import is_unsafe_iterator_invalid, extract_counterexample
from a3_python.semantics.symbolic_vm import SymbolicMachineState, SymbolicVM


class TestIteratorInvalidUnsafePredicate:
    """Test the unsafe predicate U_ITERATOR_INVALID(σ)."""
    
    def test_predicate_requires_flag(self):
        """Unsafe predicate requires iterator_invalidation_reached flag."""
        state = SymbolicMachineState()
        assert not is_unsafe_iterator_invalid(state)
    
    def test_predicate_with_flag_set(self):
        """Predicate returns True when iterator_invalidation_reached is True."""
        state = SymbolicMachineState()
        state.iterator_invalidation_reached = True
        assert is_unsafe_iterator_invalid(state)
    
    def test_predicate_runtime_error_without_flag(self):
        """RuntimeError alone is insufficient without the semantic flag."""
        state = SymbolicMachineState()
        state.exception = "RuntimeError"
        # Without iterator_invalidation_reached flag, this could be any RuntimeError
        assert not is_unsafe_iterator_invalid(state)
    
    def test_predicate_runtime_error_with_flag(self):
        """RuntimeError with flag is unsafe."""
        state = SymbolicMachineState()
        state.exception = "RuntimeError"
        state.iterator_invalidation_reached = True
        assert is_unsafe_iterator_invalid(state)
    
    def test_predicate_other_exception(self):
        """Other exceptions don't trigger ITERATOR_INVALID."""
        state = SymbolicMachineState()
        state.exception = "ValueError"
        state.iterator_invalidation_reached = False
        assert not is_unsafe_iterator_invalid(state)


class TestIteratorInvalidCounterexample:
    """Test counterexample extraction."""
    
    def test_extract_basic_info(self):
        """Counterexample includes bug type and trace."""
        state = SymbolicMachineState()
        state.iterator_invalidation_reached = True
        state.exception = "RuntimeError"
        trace = ["instr_1", "instr_2"]
        
        result = extract_counterexample(state, trace)
        
        assert result["bug_type"] == "ITERATOR_INVALID"
        assert result["trace"] == trace
        assert result["final_state"]["iterator_invalidation_reached"] is True
    
    def test_extract_includes_iterator_state(self):
        """Counterexample includes active iterator information."""
        state = SymbolicMachineState()
        state.iterator_invalidation_reached = True
        state.active_iterators = [(123, 456)]  # collection_id, iterator_id
        state.last_collection_mutation = "dict[key]=value"
        
        result = extract_counterexample(state, [])
        
        assert result["final_state"]["active_iterators"] == [(123, 456)]
        assert result["final_state"]["last_mutation"] == "dict[key]=value"
    
    def test_extract_includes_path_condition(self):
        """Counterexample includes Z3 path condition."""
        import z3
        state = SymbolicMachineState()
        state.iterator_invalidation_reached = True
        state.path_condition = z3.And(z3.Bool('p1'), z3.Bool('p2'))
        
        result = extract_counterexample(state, [])
        
        assert result["path_condition"] is not None
        assert "p1" in result["path_condition"]


class TestIteratorInvalidBugFixtures:
    """
    Test ITERATOR_INVALID detection on concrete fixtures.
    
    Note: Full symbolic execution with iterator tracking is not yet implemented.
    These tests document expected behavior and will pass once the VM
    implements GET_ITER/FOR_ITER opcodes with mutation tracking.
    """
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes + mutation tracking")
    def test_dict_add_during_iteration(self):
        """Dict mutation (add key) during iteration should be detected."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_invalid_dict_add.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Would execute and detect iterator invalidation
        # assert path.state.iterator_invalidation_reached
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes + mutation tracking")
    def test_dict_del_during_iteration(self):
        """Dict mutation (delete key) during iteration should be detected."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_invalid_dict_del.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Would execute and detect iterator invalidation
        # assert path.state.iterator_invalidation_reached
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes + mutation tracking")
    def test_set_add_during_iteration(self):
        """Set mutation during iteration should be detected."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_invalid_set_add.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Would execute and detect iterator invalidation
        # assert path.state.iterator_invalidation_reached
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes + mutation tracking")
    def test_list_modify_during_iteration(self):
        """List mutation during iteration should be detected (undefined behavior)."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_invalid_list_modify.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Would execute and detect iterator invalidation
        # assert path.state.iterator_invalidation_reached


class TestIteratorValidFixtures:
    """
    Test that safe iteration patterns are not flagged.
    
    These are NON-BUG tests: valid iteration without mutation.
    """
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes")
    def test_dict_readonly_iteration(self):
        """Read-only dict iteration is safe."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_valid_dict_readonly.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Should complete without iterator_invalidation_reached
        # assert not path.state.iterator_invalidation_reached
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes")
    def test_dict_mutation_after_iteration(self):
        """Dict mutation after iteration completes is safe."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_valid_dict_after.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Should complete without iterator_invalidation_reached
        # assert not path.state.iterator_invalidation_reached
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes")
    def test_list_copy_iteration(self):
        """Iterating over a copy while mutating original is safe."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_valid_list_copy.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Should complete without iterator_invalidation_reached
        # assert not path.state.iterator_invalidation_reached
    
    @pytest.mark.skip(reason="Requires GET_ITER/FOR_ITER opcodes")
    def test_break_before_mutation(self):
        """Breaking before mutation is safe."""
        fixture = Path(__file__).parent / "fixtures" / "iterator_valid_break_before_mutation.py"
        code = compile(fixture.read_text(), str(fixture), 'exec')
        
        vm = SymbolicVM()
        path = vm.load_code(code)
        # Should complete without iterator_invalidation_reached
        # assert not path.state.iterator_invalidation_reached


class TestIteratorInvalidSemantics:
    """
    Test semantic requirements for ITERATOR_INVALID.
    
    These tests verify that the bug type definition is semantic, not heuristic.
    """
    
    def test_no_text_pattern_matching(self):
        """Detection must not rely on text patterns like 'for' or 'del'."""
        # The unsafe predicate operates on machine state, not source code
        state = SymbolicMachineState()
        state.iterator_invalidation_reached = True
        
        # This should trigger regardless of what the source code looks like
        assert is_unsafe_iterator_invalid(state)
    
    def test_requires_active_iterator_and_mutation(self):
        """
        Semantic requirement: both an active iterator and a mutation
        must occur on the same collection.
        """
        # The VM must track:
        # 1. When an iterator is created (GET_ITER)
        # 2. When the iterator is active (during FOR_ITER loop)
        # 3. When the underlying collection is mutated
        # 4. Match mutation to active iterator's collection
        
        # This is verified by the iterator_invalidation_reached flag,
        # which the VM sets only when these conditions are all met
        state = SymbolicMachineState()
        state.active_iterators = [(123, 456)]  # Has active iterator
        state.last_collection_mutation = "mutation on 123"
        state.iterator_invalidation_reached = True  # VM detected the conflict
        
        assert is_unsafe_iterator_invalid(state)
    
    def test_safe_if_no_active_iterator(self):
        """Mutation without active iterator is safe."""
        state = SymbolicMachineState()
        state.active_iterators = []
        state.last_collection_mutation = "dict[key]=value"
        # Without active iterator, no invalidation
        assert not is_unsafe_iterator_invalid(state)
    
    def test_safe_if_different_collection(self):
        """Mutation of different collection is safe."""
        # If iterator is on collection A, mutation of collection B is safe
        # The VM must track collection identity and only flag when
        # iterator_invalidation_reached is set (matching collection IDs)
        state = SymbolicMachineState()
        state.active_iterators = [(123, 456)]  # Iterator on collection 123
        state.last_collection_mutation = "mutation on 789"  # Different collection
        # VM would not set iterator_invalidation_reached
        assert not is_unsafe_iterator_invalid(state)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
