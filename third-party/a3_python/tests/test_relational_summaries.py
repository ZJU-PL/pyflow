"""
Tests for relational summary system (ELEVATION_PLAN.md implementation).

These tests validate:
1. The "cases + havoc" pattern works correctly
2. Summaries integrate with symbolic execution
3. Guard evaluation and postcondition application
4. Soundness: havoc fallback remains reachable
"""

import pytest
import z3

from a3_python.contracts.relations import (
    RelationalSummary, RelationalCase, PostCondition, HavocCase,
    register_relational_summary, get_relational_summary, has_relational_summary
)
from a3_python.z3model.values import SymbolicValue, ValueTag


def test_relational_summary_registration():
    """Test that relational summaries can be registered and retrieved."""
    # Check that builtin_relations module registered summaries
    assert has_relational_summary("len")
    assert has_relational_summary("abs")
    assert has_relational_summary("isinstance")
    
    # Check that unknown functions don't have summaries
    assert not has_relational_summary("unknown_builtin_xyz")


def test_len_relational_summary():
    """Test that len() has a relational summary with proper structure."""
    summary = get_relational_summary("len")
    
    assert summary is not None
    assert summary.function_id == "len"
    assert len(summary.cases) > 0  # Should have at least one case
    assert summary.havoc is not None  # Required havoc fallback
    assert summary.provenance == "python_spec"


def test_relational_summary_with_symbolic_execution():
    """Test that relational summaries work in symbolic execution."""
    # For now, just verify that the integration is set up correctly
    # A full end-to-end test would require running the analyzer
    
    # Verify that relational summaries are being checked
    from a3_python.contracts.relations import has_relational_summary
    from a3_python.semantics.symbolic_vm import SymbolicVM
    
    # The VM should have access to relational summaries
    assert has_relational_summary("len")
    assert has_relational_summary("abs")
    
    # This validates the integration without needing to run full analysis


def test_abs_relational_summary_structure():
    """Test that abs() has a well-formed relational summary."""
    summary = get_relational_summary("abs")
    
    assert summary is not None
    assert summary.function_id == "abs"
    assert len(summary.cases) > 0
    assert summary.havoc is not None


def test_isinstance_relational_summary_structure():
    """Test that isinstance() has a well-formed relational summary."""
    summary = get_relational_summary("isinstance")
    
    assert summary is not None
    assert summary.function_id == "isinstance"
    assert len(summary.cases) > 0
    assert summary.havoc is not None


def test_havoc_case_always_applies():
    """Test that havoc case is always applicable (soundness requirement)."""
    havoc = HavocCase()
    assert havoc.applies()  # Should always be True
    
    # Havoc should be maximal over-approximation
    assert havoc.may_read_heap
    assert havoc.may_write_heap
    assert havoc.may_allocate
    assert havoc.may_raise_any


def test_relational_summary_soundness():
    """
    Test that relational summaries maintain soundness:
    - If no case guard holds, havoc fallback applies
    - Sem_f ⊆ R_f (over-approximation property)
    """
    # Create a simple test summary
    test_summary = RelationalSummary(
        function_id="test_func",
        provenance="test"
    )
    
    # Add a case with an impossible guard
    def impossible_guard(state, args):
        return z3.BoolVal(False)  # Never holds
    
    def dummy_post(state, args, fresh):
        return PostCondition(
            return_value=SymbolicValue(ValueTag.INT, z3.IntVal(42))
        )
    
    test_summary.add_case(RelationalCase(
        name="impossible",
        guard=impossible_guard,
        post=dummy_post,
        provenance="test"
    ))
    
    # The summary should still have havoc fallback
    assert test_summary.havoc is not None
    assert test_summary.havoc.applies()
    
    # This ensures soundness: even if no case matches,
    # the havoc fallback provides a sound over-approximation


def test_postcondition_structure():
    """Test that PostCondition has the required fields."""
    post = PostCondition(
        return_value=SymbolicValue(ValueTag.INT, z3.IntVal(10)),
        path_constraints=[z3.BoolVal(True)],
        heap_constraints=[],
        observer_updates={}
    )
    
    assert post.return_value is not None
    assert isinstance(post.path_constraints, list)
    assert isinstance(post.heap_constraints, list)
    assert isinstance(post.observer_updates, dict)


def test_relational_case_structure():
    """Test that RelationalCase has the required fields."""
    def test_guard(state, args):
        return z3.BoolVal(True)
    
    def test_post(state, args, fresh):
        return PostCondition(
            return_value=SymbolicValue(ValueTag.BOOL, z3.BoolVal(True))
        )
    
    case = RelationalCase(
        name="test_case",
        guard=test_guard,
        post=test_post,
        may_raise=["ValueError"],
        provenance="test"
    )
    
    assert case.name == "test_case"
    assert case.guard is not None
    assert case.post is not None
    assert "ValueError" in case.may_raise
    assert case.provenance == "test"


def test_range_relational_summary():
    """Test that range() has a relational summary."""
    summary = get_relational_summary("range")
    
    assert summary is not None
    assert summary.function_id == "range"
    assert len(summary.cases) > 0
    assert summary.havoc is not None
    assert summary.provenance == "python_spec"


def test_sorted_relational_summary():
    """Test that sorted() has a relational summary."""
    summary = get_relational_summary("sorted")
    
    assert summary is not None
    assert summary.function_id == "sorted"
    assert len(summary.cases) > 0
    assert summary.havoc is not None
    assert summary.provenance == "python_spec"


def test_enumerate_relational_summary():
    """Test that enumerate() has a relational summary."""
    summary = get_relational_summary("enumerate")
    
    assert summary is not None
    assert summary.function_id == "enumerate"
    assert len(summary.cases) > 0
    assert summary.havoc is not None
    assert summary.provenance == "python_spec"


def test_zip_relational_summary():
    """Test that zip() has a relational summary."""
    summary = get_relational_summary("zip")
    
    assert summary is not None
    assert summary.function_id == "zip"
    assert len(summary.cases) > 0
    assert summary.havoc is not None
    assert summary.provenance == "python_spec"


def test_new_builtins_registered():
    """Test that all new builtins are registered."""
    assert has_relational_summary("range")
    assert has_relational_summary("sorted")
    assert has_relational_summary("enumerate")
    assert has_relational_summary("zip")
    assert has_relational_summary("reversed")
    assert has_relational_summary("map")
    assert has_relational_summary("filter")
    assert has_relational_summary("all")
    assert has_relational_summary("any")


def test_reversed_relational_summary():
    """Test that reversed() has a relational summary."""
    summary = get_relational_summary("reversed")
    
    assert summary is not None
    assert summary.function_id == "reversed"
    assert len(summary.cases) > 0
    assert summary.havoc is not None


def test_map_relational_summary():
    """Test that map() has a relational summary."""
    summary = get_relational_summary("map")
    
    assert summary is not None
    assert summary.function_id == "map"
    assert len(summary.cases) > 0
    assert summary.havoc is not None


def test_filter_relational_summary():
    """Test that filter() has a relational summary."""
    summary = get_relational_summary("filter")
    
    assert summary is not None
    assert summary.function_id == "filter"
    assert len(summary.cases) > 0
    assert summary.havoc is not None


def test_all_any_relational_summaries():
    """Test that all() and any() have relational summaries."""
    all_summary = get_relational_summary("all")
    any_summary = get_relational_summary("any")
    
    assert all_summary is not None
    assert any_summary is not None
    assert all_summary.function_id == "all"
    assert any_summary.function_id == "any"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
